extern crate pnet;
extern crate regex;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::{Packet, ipv4::Ipv4Packet, tcp::TcpPacket};
use pnet::util::checksum;
use regex::Regex;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::thread;

// Pattern to match potential SQL injection keywords (simple example)
lazy_static::lazy_static! {
    static ref SQL_INJECTION_PATTERN: Regex = Regex::new(r"(\b(select|insert|update|delete|drop|union|into|load_file|outfile)\b.*[';]+)").unwrap();
}

struct IPS {
    blocked_ips: HashSet<Ipv4Addr>,
}

impl IPS {
    fn new() -> Self {
        IPS {
            blocked_ips: HashSet::new(),
        }
    }

    fn is_sql_injection(&self, payload: &str) -> bool {
        SQL_INJECTION_PATTERN.is_match(payload)
    }

    fn block_ip(&mut self, ip: Ipv4Addr) {
        if !self.blocked_ips.contains(&ip) {
            self.blocked_ips.insert(ip);
            println!("Blocking IP: {}", ip);
        }
    }

    fn start_sniffing(&mut self) {
        let interfaces = datalink::interfaces();
        let iface = interfaces.into_iter().find(|iface: &NetworkInterface| iface.is_up()).expect("No network interface found");

        println!("Starting packet sniffing on interface: {}", iface.name);

        let (mut tx, mut rx) = datalink::channel(&iface, Default::default()).expect("Error opening datalink channel");

        loop {
            let packet = rx.next().expect("Error receiving packet");
            self.process_packet(packet);
        }
    }

    fn process_packet(&mut self, packet: pnet::datalink::DataLinkReceiver) {
        if let Some(ip_packet) = Ipv4Packet::new(packet.packet()) {
            if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                let src_ip = ip_packet.get_source();
                let dst_ip = ip_packet.get_destination();
                let payload = String::from_utf8_lossy(tcp_packet.payload());

                if self.is_sql_injection(&payload) {
                    println!("Potential SQL Injection detected from {} to {}: {}", src_ip, dst_ip, payload);
                    self.block_ip(src_ip);
                }
            }
        }
    }
}

fn main() {
    let mut ips = IPS::new();
    ips.start_sniffing();
}

/* enter cargo.toml
[dependencies]
pnet = "0.30.0"  # For packet sniffing
regex = "1.5"     # For pattern matching
*/
