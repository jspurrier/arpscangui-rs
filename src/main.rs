use slint::{ModelRc, VecModel, invoke_from_event_loop, Image};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use std::io::{self, BufRead};
use std::fs::File;
use std::collections::HashMap;
use std::str::FromStr;
use std::path::Path;
use std::process::Command;
use std::env;
use std::sync::{Arc, Mutex};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use lazy_static::lazy_static;

slint::include_modules!();

lazy_static! {
    static ref OUI_MAP: HashMap<String, String> = {
        let mut map = HashMap::new();
        if let Ok(file) = File::open("oui.txt") {
            let reader = io::BufReader::new(file);
            let mut current_oui = String::new();
            
            for line in reader.lines().filter_map(Result::ok) {
                let line = line.trim();
                if line.contains("(hex)") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        current_oui = parts[0].replace("-", "").to_uppercase();
                    }
                } else if !current_oui.is_empty() && line.contains("base 16") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let manufacturer = parts[3..].join(" ");
                        map.insert(current_oui.clone(), manufacturer);
                    }
                }
            }
        }
        map
    };
}

fn get_manufacturer(mac: &MacAddr) -> String {
    let mac_prefix = format!("{:02X}{:02X}{:02X}", mac.0, mac.1, mac.2);
    OUI_MAP.get(&mac_prefix)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn get_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| {
            iface.is_up() 
            && !iface.is_loopback() 
            && !iface.ips.is_empty()
            && iface.mac.is_some()
        })
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u32), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format. Use: x.x.x.x/n".to_string());
    }

    let ip = Ipv4Addr::from_str(parts[0])
        .map_err(|e| format!("Invalid IP address: {}", e))?;
    let mask = parts[1]
        .parse::<u32>()
        .map_err(|e| format!("Invalid subnet mask: {}", e))?;

    if mask > 32 {
        return Err("Subnet mask must be between 0 and 32".to_string());
    }

    Ok((ip, mask))
}

fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n.to_be_bytes())
}

async fn scan_network(cidr: String) -> Result<Vec<ScanResult>, String> {
    if !Path::new("oui.txt").exists() {
        return Err("oui.txt file not found. Ensure it’s in the same directory as the executable.".to_string());
    }

    let (network, mask) = parse_cidr(&cidr)?;
    let interface = get_default_interface()
        .ok_or_else(|| {
            let os_msg = if cfg!(target_os = "windows") {
                "No suitable network interface found. Ensure you’re running with administrative privileges."
            } else {
                "No suitable network interface found. Ensure you’re running with root privileges (e.g., sudo)."
            };
            os_msg.to_string()
        })?;

    let source_ip = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => Ipv4Addr::new(0, 0, 0, 0),
        })
        .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

    let source_mac = interface.mac.unwrap_or(MacAddr::zero());
    let mut results = HashMap::new();

    let network_u32 = ip_to_u32(network) & !(0xFFFFFFFF >> mask);
    let host_count = 1 << (32 - mask);
    
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled channel type".to_string()),
        Err(e) => {
            let os_msg = if cfg!(target_os = "windows") {
                format!("Failed to create channel: {}. Ensure you’re running as Administrator.", e)
            } else {
                format!("Failed to create channel: {}. Ensure you’re running with sudo.", e)
            };
            return Err(os_msg);
        }
    };

    let start_time = Instant::now();
    
    for i in 1..host_count - 1 {
        let target_ip = u32_to_ip(network_u32 + i);
        
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
            .ok_or("Failed to create ethernet packet")?;

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
            .ok_or("Failed to create ARP packet")?;

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet_mut());

        if tx.send_to(ethernet_packet.packet(), None).is_none() {
            println!("Warning: Failed to send packet to {}", target_ip);
        }
    }

    while start_time.elapsed() < Duration::from_secs(5) {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let ip = arp.get_sender_proto_addr();
                                let mac = arp.get_sender_hw_addr();
                                results.insert(ip, mac);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    break;
                }
                println!("Warning: Failed to receive packet: {}", e);
                continue;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut scan_results: Vec<ScanResult> = results.into_iter().map(|(ip, mac)| {
        let manufacturer = get_manufacturer(&mac);
        ScanResult {
            ip: ip.to_string().into(),
            mac: mac.to_string().into(),
            manufacturer: manufacturer.into(),
        }
    }).collect();

    scan_results.sort_by(|a, b| {
        let ip_a = Ipv4Addr::from_str(&a.ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
        let ip_b = Ipv4Addr::from_str(&b.ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
        ip_a.cmp(&ip_b)
    });

    println!("Scan completed with {} results", scan_results.len());
    Ok(scan_results)
}

fn open_url(url: &str, as_root: bool) -> Result<(), String> {
    if cfg!(target_os = "linux") && as_root {
        let user = env::var("SUDO_USER")
            .map_err(|_| "SUDO_USER not set; are you running with sudo?")?;
        let display = env::var("DISPLAY")
            .unwrap_or_else(|_| ":0".to_string());
        let home = env::var("HOME")
            .unwrap_or_else(|_| format!("/home/{}", user));
        let xauthority = env::var("XAUTHORITY")
            .unwrap_or_else(|_| format!("/home/{}/.Xauthority", user));

        let status = Command::new("sudo")
            .arg("-u")
            .arg(&user)
            .env("DISPLAY", &display)
            .env("HOME", &home)
            .env("XAUTHORITY", &xauthority)
            .arg("xdg-open")
            .arg(url)
            .status()
            .map_err(|e| format!("Failed to execute xdg-open: {}", e))?;

        if status.success() {
            Ok(())
        } else {
            Err(format!("xdg-open failed with exit code: {:?}", status.code()))
        }
    } else {
        open::that(url).map_err(|e| format!("Failed to open URL: {}", e))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;
    let pending_url = Arc::new(Mutex::new(None::<String>));

    // Set background image if it exists
    let background_path = "background.png"; // Adjust filename as needed
    if Path::new(background_path).exists() {
        if let Ok(image) = Image::load_from_path(Path::new(background_path)) {
            ui.set_background_image(image);
            println!("Background image set to: {}", background_path);
        } else {
            println!("Failed to load background image '{}', using default solid background", background_path);
        }
    } else {
        println!("No background image found at '{}', using default solid background", background_path);
    }

    ui.window().set_size(slint::PhysicalSize::new(1000, 800));
    println!("Window size set to: {:?}", ui.window().size());

    ui.on_close_window({
        let ui_handle = ui.as_weak();
        move || {
            if let Some(ui) = ui_handle.upgrade() {
                ui.window().hide();
            }
        }
    });

    ui.on_scan_network({
        let ui_handle = ui.as_weak();
        move |network| {
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_status("Running".into());
                println!("Status set to Running");
                let ui_handle_clone = ui_handle.clone();
                let network = network.to_string();
                tokio::spawn(async move {
                    let result = scan_network(network).await;
                    invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle_clone.upgrade() {
                            match result {
                                Ok(results) => {
                                    let model = VecModel::from(results);
                                    ui.set_scan_results(ModelRc::new(model));
                                    ui.set_status("Scan Complete".into());
                                    println!("Status set to Scan Complete");
                                }
                                Err(e) => {
                                    ui.set_status(format!("Error: {}", e).into());
                                    ui.set_scan_results(ModelRc::new(VecModel::default()));
                                    println!("Status set to Error: {}", e);
                                }
                            }
                        }
                    }).expect("Failed to invoke UI update from event loop");
                });
            }
        }
    });

    ui.on_show_warning({
        let ui_handle = ui.as_weak();
        move || {
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_popup_visible(true);
            }
        }
    });

    ui.on_proceed_with_url({
        let ui_handle = ui.as_weak();
        let pending_url = pending_url.clone();
        move || {
            if let Some(ui) = ui_handle.upgrade() {
                let url = {
                    let mut lock = pending_url.lock().unwrap();
                    lock.take()
                };
                if let Some(url) = url {
                    let is_root = cfg!(target_os = "linux") && env::var("SUDO_UID").is_ok();
                    if let Err(e) = open_url(&url, is_root) {
                        println!("Failed to open URL {}: {}", url, e);
                        ui.set_status(format!("Error opening URL: {}", e).into());
                    } else {
                        println!("Opened URL: {}", url);
                    }
                }
            }
        }
    });

    ui.on_open_http({
        let ui_handle = ui.as_weak();
        let pending_url = pending_url.clone();
        move |ip| {
            if let Some(ui) = ui_handle.upgrade() {
                let url = format!("http://{}", ip);
                let is_root = cfg!(target_os = "linux") && env::var("SUDO_UID").is_ok();
                if is_root {
                    *pending_url.lock().unwrap() = Some(url);
                    ui.invoke_show_warning();
                } else {
                    if let Err(e) = open_url(&url, false) {
                        println!("Failed to open HTTP URL {}: {}", url, e);
                    } else {
                        println!("Opened HTTP URL: {}", url);
                    }
                }
            }
        }
    });

    ui.on_open_https({
        let ui_handle = ui.as_weak();
        let pending_url = pending_url.clone();
        move |ip| {
            if let Some(ui) = ui_handle.upgrade() {
                let url = format!("https://{}", ip);
                let is_root = cfg!(target_os = "linux") && env::var("SUDO_UID").is_ok();
                if is_root {
                    *pending_url.lock().unwrap() = Some(url);
                    ui.invoke_show_warning();
                } else {
                    if let Err(e) = open_url(&url, false) {
                        println!("Failed to open HTTPS URL {}: {}", url, e);
                    } else {
                        println!("Opened HTTPS URL: {}", url);
                    }
                }
            }
        }
    });

    ui.run()?;
    Ok(())
}
