#![cfg_attr(feature = "windows-no-popup", windows_subsystem = "windows")]

use slint::{ModelRc, VecModel, invoke_from_event_loop, Image, Model};
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
use log::{info, error, debug};
use env_logger::Builder;

// Store original scan results to restore when filter is cleared
lazy_static! {
    static ref ORIGINAL_RESULTS: Arc<Mutex<Vec<ScanResult>>> = Arc::new(Mutex::new(Vec::new()));
}

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
    let interfaces = datalink::interfaces();
    info!("Found {} network interfaces", interfaces.len());
    
    if interfaces.is_empty() {
        error!("No network interfaces detected by pnet");
    }

    for iface in &interfaces {
        let up = iface.is_up();
        let loopback = iface.is_loopback();
        let has_ips = !iface.ips.is_empty();
        let has_mac = iface.mac.is_some();
        
        debug!(
            "Interface: {}\n  Up: {}\n  Loopback: {}\n  IPs: {:?}\n  MAC: {:?}\n  Suitable: {}",
            iface.name, up, loopback, iface.ips, iface.mac, 
            up && !loopback && has_ips && has_mac
        );
    }

    let selected = interfaces.into_iter().find(|iface| {
        !iface.is_loopback() 
        && iface.ips.iter().any(|ip| ip.is_ipv4() && ip.ip() != Ipv4Addr::new(0, 0, 0, 0))
    });

    match &selected {
        Some(iface) => info!("Selected interface: {}", iface.name),
        None => error!("No suitable interface found after filtering"),
    }
    selected
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
    info!("Starting network scan for CIDR: {}", cidr);

    if !Path::new("oui.txt").exists() {
        error!("oui.txt file not found");
        return Err("oui.txt file not found. Ensure it’s in the same directory as the executable.".to_string());
    }

    let (network, mask) = parse_cidr(&cidr)?;
    let interface = get_default_interface()
        .ok_or_else(|| {
            let os_msg = if cfg!(target_os = "windows") {
                "No suitable network interface found. Ensure Npcap is installed, run as Administrator, and check if your network adapter is active (e.g., via 'ipconfig')."
            } else {
                "No suitable network interface found. Ensure you’re running with root privileges (e.g., sudo)."
            };
            error!("{}", os_msg);
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

    // First scan pass
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => {
            info!("Ethernet channel created successfully for interface {}", interface.name);
            (tx, rx)
        },
        Ok(_) => {
            error!("Unhandled channel type");
            return Err("Unhandled channel type".to_string())
        },
        Err(e) => {
            let os_msg = if cfg!(target_os = "windows") {
                format!("Failed to create channel: {}. Ensure Npcap is installed and run as Administrator.", e)
            } else {
                format!("Failed to create channel: {}. Ensure you’re running with sudo.", e)
            };
            error!("{}", os_msg);
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
            debug!("Failed to send packet to {}", target_ip);
        } else {
            debug!("Sent ARP request to {}", target_ip);
        }
    }

    // Increased timeout for more consistent results
    let timeout = if cfg!(target_os = "windows") { Duration::from_secs(20) } else { Duration::from_secs(15) };
    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let ip = arp.get_sender_proto_addr();
                                let mac = arp.get_sender_hw_addr();
                                results.insert(ip, mac);
                                debug!("Received ARP reply from {} with MAC {}", ip, mac);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    info!("Receive timeout reached in first pass");
                    break;
                }
                debug!("Failed to receive packet: {}", e);
                continue;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Second scan pass for IPs that didn't respond
    let missing_ips: Vec<Ipv4Addr> = (1..host_count - 1)
        .map(|i| u32_to_ip(network_u32 + i))
        .filter(|ip| !results.contains_key(ip))
        .collect();

    if !missing_ips.is_empty() {
        info!("Starting second scan pass for {} IPs that didn't respond", missing_ips.len());
        let start_time = Instant::now();

        for target_ip in missing_ips {
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
                debug!("Failed to send packet to {} in second pass", target_ip);
            } else {
                debug!("Sent ARP request to {} in second pass", target_ip);
            }
        }

        while start_time.elapsed() < timeout {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                        if ethernet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let ip = arp.get_sender_proto_addr();
                                    let mac = arp.get_sender_hw_addr();
                                    results.insert(ip, mac);
                                    debug!("Received ARP reply from {} with MAC {} in second pass", ip, mac);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        info!("Receive timeout reached in second pass");
                        break;
                    }
                    debug!("Failed to receive packet in second pass: {}", e);
                    continue;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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

    // Store the original results for filtering
    let mut original = ORIGINAL_RESULTS.lock().unwrap();
    *original = scan_results.clone();

    info!("Scan completed with {} results", scan_results.len());
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

fn normalize_mac(mac: &str) -> String {
    mac.to_lowercase().replace([':', '-', ' '], "")
}

fn filter_results_by_mac_or_manufacturer(results: Vec<ScanResult>, filter: &str) -> Vec<ScanResult> {
    let normalized_filter = normalize_mac(filter); // Normalize the filter input
    info!("Filtering with normalized filter: {}", normalized_filter); // Debug log
    if normalized_filter.is_empty() {
        // If filter is empty, return the original results
        let original = ORIGINAL_RESULTS.lock().unwrap();
        return original.clone();
    }

    results.into_iter().filter(|result| {
        let normalized_mac = normalize_mac(&result.mac);
        let normalized_manufacturer = result.manufacturer.to_lowercase();
        let matches_mac = normalized_mac.contains(&normalized_filter);
        let matches_manufacturer = normalized_manufacturer.contains(&normalized_filter);
        if matches_mac {
            info!("Match found in MAC: {} for filter {}", normalized_mac, normalized_filter);
        }
        if matches_manufacturer {
            info!("Match found in manufacturer: {} for filter {}", normalized_manufacturer, normalized_filter);
        }
        matches_mac || matches_manufacturer
    }).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(target_os = "windows") {
        let log_file = File::create("arpscangui.log").expect("Failed to create log file");
        Builder::from_default_env()
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .init();
    } else {
        env_logger::init();
    }
    info!("Application starting");

    let ui = MainWindow::new()?;
    let pending_url = Arc::new(Mutex::new(None::<String>));

    let background_path = "background.png";
    if Path::new(background_path).exists() {
        if let Ok(image) = Image::load_from_path(Path::new(background_path)) {
            ui.set_background_image(image);
            info!("Background image set to: {}", background_path);
        } else {
            error!("Failed to load background image '{}'", background_path); // Fixed macro invocation
        }
    } else {
        info!("No background image found at '{}'", background_path);
    }

    ui.window().set_size(slint::PhysicalSize::new(1000, 600));
    info!("Window size set to: {:?}", ui.window().size());

    #[cfg(not(feature = "windows-no-popup"))]
    {
        ui.set_popup_visible(false);
        info!("Popup visibility set to false on non-Windows build");
    }

    ui.on_close_window({
        let ui_handle = ui.as_weak();
        move || {
            if let Some(ui) = ui_handle.upgrade() {
                let _ = ui.window().hide();
            }
        }
    });

    ui.on_scan_network({
        let ui_handle = ui.as_weak();
        move |network| {
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_status("Scanning...".into());
                info!("Scan initiated for network: {}", network);
                let ui_handle_clone = ui_handle.clone();
                let network = network.to_string();
                tokio::spawn(async move {
                    let result = crate::scan_network(network).await;
                    invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle_clone.upgrade() {
                            match result {
                                Ok(results) => {
                                    let model = VecModel::from(results);
                                    ui.set_scan_results(ModelRc::new(model));
                                    ui.set_status("Scan Complete".into());
                                    info!("Scan completed successfully");
                                }
                                Err(e) => {
                                    ui.set_status(format!("Error: {}", e).into());
                                    ui.set_scan_results(ModelRc::new(VecModel::default()));
                                    error!("Scan failed: {}", e);
                                }
                            }
                        } else {
                            error!("UI handle upgrade failed");
                        }
                    }).expect("Failed to invoke UI update from event loop");
                });
            }
        }
    });

    #[cfg(not(feature = "windows-no-popup"))]
    {
        ui.on_show_warning({
            let ui_handle = ui.as_weak();
            move || {
                if let Some(ui) = ui_handle.upgrade() {
                    let is_root = env::var("SUDO_UID").is_ok();
                    info!("Checking warning: is_root={}", is_root);
                    if is_root {
                        info!("Showing popup: Linux with root privileges detected");
                        ui.set_popup_visible(true);
                    } else {
                        info!("Suppressing popup: Not root");
                        ui.set_popup_visible(false);
                    }
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
                        let is_root = env::var("SUDO_UID").is_ok();
                        if let Err(e) = crate::open_url(&url, is_root) {
                            error!("Failed to open URL {}: {}", url, e);
                            ui.set_status(format!("Error opening URL: {}", e).into());
                        } else {
                            info!("Opened URL: {}", url);
                        }
                    }
                }
            }
        });
    }

    ui.on_open_http({
        let ui_handle = ui.as_weak();
        let _pending_url = pending_url.clone(); // Renamed to _pending_url to indicate it's unused
        move |ip| {
            if let Some(_ui) = ui_handle.upgrade() { // Renamed to _ui to indicate it's unused
                let url = format!("http://{}", ip);
                #[cfg(feature = "windows-no-popup")]
                {
                    info!("Opening HTTP URL directly: Running on Windows");
                    if let Err(e) = crate::open_url(&url, false) {
                        error!("Failed to open HTTP URL {}: {}", url, e);
                    } else {
                        info!("Opened HTTP URL: {}", url);
                    }
                }
                #[cfg(not(feature = "windows-no-popup"))]
                {
                    let is_root = env::var("SUDO_UID").is_ok();
                    if is_root {
                        info!("Pending HTTP URL: Linux with root privileges detected");
                        *_pending_url.lock().unwrap() = Some(url);
                        _ui.invoke_show_warning();
                    } else {
                        info!("Opening HTTP URL directly: Not root");
                        if let Err(e) = crate::open_url(&url, false) {
                            error!("Failed to open HTTP URL {}: {}", url, e);
                        } else {
                            info!("Opened HTTP URL: {}", url);
                        }
                    }
                }
            }
        }
    });

    ui.on_open_https({
        let ui_handle = ui.as_weak();
        let _pending_url = pending_url.clone(); // Renamed to _pending_url to indicate it's unused
        move |ip| {
            if let Some(_ui) = ui_handle.upgrade() { // Renamed to _ui to indicate it's unused
                let url = format!("https://{}", ip);
                #[cfg(feature = "windows-no-popup")]
                {
                    info!("Opening HTTPS URL directly: Running on Windows");
                    if let Err(e) = crate::open_url(&url, false) {
                        error!("Failed to open HTTPS URL {}: {}", url, e);
                    } else {
                        info!("Opened HTTPS URL: {}", url);
                    }
                }
                #[cfg(not(feature = "windows-no-popup"))]
                {
                    let is_root = env::var("SUDO_UID").is_ok();
                    if is_root {
                        info!("Pending HTTPS URL: Linux with root privileges detected");
                        *_pending_url.lock().unwrap() = Some(url);
                        _ui.invoke_show_warning();
                    } else {
                        info!("Opening HTTPS URL directly: Not root");
                        if let Err(e) = crate::open_url(&url, false) {
                            error!("Failed to open HTTPS URL {}: {}", url, e);
                        } else {
                            info!("Opened HTTPS URL: {}", url);
                        }
                    }
                }
            }
        }
    });

    ui.on_filter_by_mac({
        let ui_handle = ui.as_weak();
        move |filter| {
            if let Some(ui) = ui_handle.upgrade() {
                let current_results = ui.get_scan_results().iter().collect::<Vec<ScanResult>>();
                let filtered_results = crate::filter_results_by_mac_or_manufacturer(current_results, &filter);
                let model = VecModel::from(filtered_results);
                ui.set_scan_results(ModelRc::new(model));
                info!("Filtered results by: {}", filter);
            }
        }
    });

    ui.run()?;
    Ok(())
}