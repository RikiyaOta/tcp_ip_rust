use crate::internet_protocol::Ipv4Address;

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
