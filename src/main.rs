use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer4};
use pnet::util::checksum;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::{env, process};

fn build_icmp_packet(seq_number: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let mut packet = MutableEchoRequestPacket::new(&mut buf).unwrap();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(echo_request::IcmpCodes::NoCode);
    packet.set_identifier(0);
    packet.set_sequence_number(seq_number);
    packet.set_payload(&[]);

    let csum = checksum(&packet.packet(), 1);
    packet.set_checksum(csum);

    buf
}

fn ping(ip: Ipv4Addr) -> bool {
    let protocol = Layer4(pnet::transport::TransportProtocol::Ipv4(
        pnet::packet::ip::IpNextHeaderProtocols::Icmp,
    ));
    let (mut tx, mut rx) = transport_channel(1024, protocol).expect("Err creating channel");

    let packet_data = build_icmp_packet(1);

    let packet = IcmpPacket::new(&packet_data).unwrap();

    tx.send_to(&packet, ip.into())
        .expect("Err sending ICMP packet");

    let mut iter = icmp_packet_iter(&mut rx);
    match iter.next_with_timeout(Duration::from_secs(1)) {
        Ok(Some((_packet, addr))) => {
            println!("Recv packet from: {}", addr);
            return true;
        }
        Ok(None) => {
            println!("No packet recv in timeout");
        }
        Err(e) => {
            eprintln!("Err recv packet: {}", e);
        }
    }

    false
}

const USAGE: &str = "USAGE: sudo nmapr <TARGET IP>";

fn main() {
    let mut args = env::args().skip(1);
    let Some(ip) = args.next() else {
        eprintln!("{USAGE}");
        process::exit(1);
    };

    if ping(ip.parse().expect("Failed to parse IP addr")) {
        println!("{} is up", ip);
    } else {
        println!("{} seems not up", ip);
    }
}
