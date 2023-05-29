use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::transport::icmp_packet_iter;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use std::net::Ipv4Addr;
use std::process;

const IPV4_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PAYLOAD_LEN: usize = 48;
const HEADER_LEN: usize = IPV4_HEADER_LEN + ICMP_HEADER_LEN;

/*
 * Google の　DNS サーバーにリクエストを投げてみる
 */
fn main() {
    let icmp_type = IcmpTypes::EchoRequest;
    let destination = Ipv4Addr::new(8, 8, 8, 8);
    let protocol = Layer3(IpNextHeaderProtocols::Icmp);

    let (mut tx, mut rx) = transport_channel(4096, protocol).unwrap();

    let mut ipv4_buffer = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN];
    let mut icmp_buffer = [0u8; ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN];

    /*
     * Construct IPv4 Packet.
     */
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length((IPV4_HEADER_LEN as u8) / 4);
    ipv4_packet.set_total_length((HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(destination);

    /*
     * Construct ICMP Packet.
     */
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
    icmp_packet.set_icmp_type(icmp_type);
    icmp_packet.set_sequence_number(1);
    icmp_packet.set_identifier(1);

    /*
     * Calculate checksum.
     */
    let checksum = pnet::util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet());

    tx.send_to(ipv4_packet, destination.into()).unwrap();

    let mut iter = icmp_packet_iter(&mut rx);
    
    println!("Before loop.");

    /*
     * Listen for replies.
     */
    loop {
        println!("First statement in loop.");
        match iter.next() {
            Ok((packet, addr)) => {
                if addr == destination {
                    if packet.get_icmp_type() == IcmpTypes::EchoReply {
                        println!("Received reply from {}", addr);
                        break;
                    } else {
                        println!("[packet.get_icmp_type() != IcmpTypes::EchoReply] icmp_type={:?}", packet.get_icmp_type());
                    }
                } else {
                    println!("[addr != destination] addr={}. packet={:?}", addr, packet);
                }
            },
            Err(error) => {
                eprintln!("Error receiving packet: {}", error);
                process::exit(1);
            }
        }    
    }
}
