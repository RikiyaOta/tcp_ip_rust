use crate::internet_protocol::Ipv4Address;
use crate::transmission_control_protocol::{tcp_packet::TcpPacket, TCP_PROTOCOL_NUMBER};

/*
 * NOTE: IPv4 を念頭に実装する。IPv6 の場合は違う。
 */
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcpPseudoHeader {
    /*
     * Source IPv4 Address.
     */
    source_address: Ipv4Address,

    /*
     * Destination IPv4 Address.
     */
    destination_address: Ipv4Address,

    /*
     * Zero. This filed should be `0`.
     */
    zero: u8,

    /*
     * Protocol Number. TCP の場合は`6`.
     */
    ptcl: u8,

    /*
     * TCP Header Length and the Data Length in octets.
     */
    tcp_length: u16,
}

impl TcpPseudoHeader {
    pub fn new(tcp_packet: &TcpPacket) -> Self {
        let source_address = tcp_packet.get_source_address();
        let destination_address = tcp_packet.get_destination_address();
        let zero = 0u8;
        let ptcl = TCP_PROTOCOL_NUMBER;

        // TODO: これでいいんだっけ。勢いで書いてて眠い。
        let tcp_length = (tcp_packet.calculate_tcp_header_length()
            + tcp_packet.calculate_payload_length()) as u16;

        Self {
            source_address,
            destination_address,
            zero,
            ptcl,
            tcp_length,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 12];

        buffer[0..4].copy_from_slice(&self.source_address);
        buffer[4..8].copy_from_slice(&self.destination_address);
        buffer[9] = self.zero;
        buffer[10] = self.ptcl;
        buffer[10..12].copy_from_slice(&self.tcp_length.to_be_bytes());

        buffer
    }
}
