mod ipv4_util;

use crate::ipv4_util::get_ipv4_addresses;

use log::{debug, error, info, warn};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer4};
use pnet::util::checksum;
use rand::Rng;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn build_icmp_packet(identify_number: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let mut packet = MutableEchoRequestPacket::new(&mut buf).unwrap();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(echo_request::IcmpCodes::NoCode);
    packet.set_identifier(identify_number);
    packet.set_sequence_number(0);
    packet.set_payload(&[]);

    let csum = checksum(&packet.packet(), 1);
    packet.set_checksum(csum);

    buf
}

fn process_packet(expected_ip: &Ipv4Addr, received_ip: IpAddr) -> bool {
    if &received_ip == expected_ip {
        info!("Recv packet from: {}", received_ip);
        return true;
    } else {
        warn!("Unexpected packet from: {} - {}", expected_ip, received_ip);
        return false;
    }
}

fn is_bcast_address(ip: &Ipv4Addr) -> bool {
    ip.octets()[3] == 255
}

fn ping(ip: Ipv4Addr) -> bool {
    if is_bcast_address(&ip) {
        return false;
    }

    let protocol = Layer4(pnet::transport::TransportProtocol::Ipv4(
        pnet::packet::ip::IpNextHeaderProtocols::Icmp,
    ));
    let (mut tx, mut rx) = transport_channel(1024, protocol).expect("Err creating channel");

    let mut rng = rand::thread_rng();
    let identifier: u16 = rng.gen();
    let packet_data = build_icmp_packet(identifier);

    let packet = IcmpPacket::new(&packet_data).unwrap();

    if let Err(e) = tx.send_to(&packet, ip.into()) {
        warn!("Err sending packet to {}: {}", ip, e);
        return false;
    }

    let mut iter = icmp_packet_iter(&mut rx);
    match iter.next_with_timeout(Duration::from_millis(200)) {
        Ok(Some((_received_packet, addr))) => {
            if process_packet(&ip, addr) {
                return true;
            }
        }
        Ok(None) => {
            //println!("No packet recv in timeout {}", ip);
        }
        Err(e) => {
            error!("Err recv packet: {}", e);
        }
    }

    false
}

struct PingResult {
    ip_addr: Ipv4Addr,
    is_up: bool,
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() != 1 {
        info!("Usage: sudo nmapr <IP or IP/CIDR>");
        return;
    }

    match get_ipv4_addresses(&args[0]) {
        Ok(ips) => {
            let ping_results: Vec<PingResult> = ips
                .into_iter()
                .map(|ip| PingResult {
                    ip_addr: ip,
                    is_up: ping(ip),
                })
                .collect();

            for result in ping_results {
                if result.is_up {
                    info!("{} is up", result.ip_addr);
                } else {
                    debug!("{} is down", result.ip_addr);
                }
            }
        }
        Err(e) => {
            error!("Err: {}", e);
        }
    }
}
