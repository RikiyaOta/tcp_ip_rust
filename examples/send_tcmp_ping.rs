use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::icmp::{time_exceeded, IcmpPacket, IcmpType, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{icmp_packet_iter, ipv4_packet_iter};
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use std::net::IpAddr;
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
    let destination = Ipv4Addr::new(8, 8, 8, 8);

    /*
     * Construct IPv4 Packet.
     */
    let mut ipv4_buffer = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length((IPV4_HEADER_LEN as u8) / 4);
    //ipv4_packet.set_total_length((HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_total_length(HEADER_LEN as u16);
    ipv4_packet.set_identification(1);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(destination);

    /*
     * Construct ICMP Packet.
     */
    let mut icmp_buffer = [0u8; ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCodes::NoCode);
    icmp_packet.set_checksum(0);
    icmp_packet.set_sequence_number(1);
    icmp_packet.set_identifier(1);

    /*
     * Calculate checksum.
     */
    let checksum = pnet::util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(&icmp_packet.packet());

    /*
     * Send request.
     */

    let (mut tx, mut rx) = transport_channel(512, Layer3(IpNextHeaderProtocols::Icmp)).unwrap();
    let mut rx = ipv4_packet_iter(&mut rx);

    let mut reach = 0;

    println!("[*] Scaning route => {}", ipv4_packet.get_destination());

    for i in 1..255 {
        ipv4_packet.set_ttl(i);
        let ipv4 = Ipv4Packet::new(&ipv4_packet.packet()).unwrap();
        tx.send_to(ipv4, IpAddr::V4(ipv4_packet.get_destination())).unwrap();

        for _ in 0..3 {
            match rx.next() {
                Ok((packet, _addr)) => {
                    let i_pac = Ipv4Packet::new(packet.packet()).unwrap();
                    match i_pac.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            let icmp_pac = IcmpPacket::new(i_pac.payload()).unwrap();
                            match icmp_pac.get_icmp_type() {
                                IcmpTypes::EchoReply => {
                                    reach = 1;
                                    println!("[*] Reach ttl: {} from {}", i, i_pac.get_source());
                                    break;
                                }
                                IcmpTypes::TimeExceeded => match icmp_packet.get_icmp_code() {
                                    time_exceeded::IcmpCodes::TimeToLiveExceededInTransit => {
                                        reach = 0;
                                        println!("- ttl: {} from {}", i, i_pac.get_source());
                                        break;
                                    }
                                    _ => {
                                        println!("[*] IcmpType:TimeExceeded unknown response");
                                    }
                                },
                                _ => {
                                    println!(".");
                                }
                            }
                        }
                        _ => {
                            reach = 2;
                            println!(".");
                        }
                    }
                }
                Err(_) => {
                    println!(".")
                }
            }
        }

        if reach == 1 {
            break;
        }
    }

    //tx.send_to(ipv4_packet, destination.into()).unwrap();

    //let mut iter = icmp_packet_iter(&mut rx);

    //println!("Before loop.");

    // /*
    // * Listen for replies.
    // */
    //loop {
    //    println!("First statement in loop.");
    //    match iter.next() {
    //        Ok((packet, addr)) => {
    //            if addr == destination {
    //                if packet.get_icmp_type() == IcmpTypes::EchoReply {
    //                    println!("Received reply from {}", addr);
    //                    break;
    //                } else {
    //                    println!(
    //                        "[packet.get_icmp_type() != IcmpTypes::EchoReply] icmp_type={:?}",
    //                        packet.get_icmp_type()
    //                    );
    //                }
    //            } else {
    //                println!("[addr != destination] addr={}. packet={:?}", addr, packet);
    //            }
    //        }
    //        Err(error) => {
    //            eprintln!("Error receiving packet: {}", error);
    //            process::exit(1);
    //        }
    //    }
    //}
}
