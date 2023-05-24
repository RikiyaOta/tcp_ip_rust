use crate::internet_protocol::{Ipv4Address, Ipv4Header};
use crate::transmission_control_protocol::{tcp_pseudo_header::TcpPseudoHeader, TcpHeader};

#[derive(Debug, Clone)]
pub struct TcpPacket {
    ip_v4_header: Ipv4Header,
    tcp_header: TcpHeader,
    payload: Vec<u8>,
}

impl TcpPacket {
    pub fn get_source_address(&self) -> Ipv4Address {
        self.ip_v4_header.get_source_address()
    }

    pub fn get_destination_address(&self) -> Ipv4Address {
        self.ip_v4_header.get_destination_address()
    }

    pub fn calculate_tcp_header_length(&self) -> usize {
        self.tcp_header.encode().len()
    }

    pub fn calculate_payload_length(&self) -> usize {
        self.payload.len()
    }

    pub fn calculate_checksum(&self) -> u16 {
        let tcp_pseudo_header = TcpPseudoHeader::new(&self);
        let tcp_pseudo_header_bytes = tcp_pseudo_header.encode();
        let tcp_header_bytes = self.tcp_header.encode();

        todo!()
    }
}
