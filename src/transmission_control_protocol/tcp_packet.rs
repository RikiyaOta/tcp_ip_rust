use byteorder::{BigEndian, ByteOrder};

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

        /*
         * TCP擬似ヘッダー、TCPヘッダー、Payload の順番で結合して計算する.
         */
        let mut buffer = tcp_pseudo_header_bytes;
        buffer.extend_from_slice(&tcp_header_bytes);
        buffer.extend_from_slice(&self.payload);

        /*
         * チェックサムの計算は 16bits 単位で計算をする。
         * もし buffer.len() が奇数（＝8bitだけ余ってる）の場合は、0u8 を追加して長さを合わせる。
         *
         * payload のところでずれる可能性があるのかな。ヘッダーは（有効なものなら）32bits単位のヘッダーとして
         * 仕様が決められているから。payload はその限りじゃないと思うし。
         */
        if buffer.len() % 2 == 0 {
            buffer.push(0);
        }

        /*
         * 16bits word に変換する。
         *
         * Big endian で変換。
         */
        let mut words = Vec::new();
        for i in (0..buffer.len()).step_by(2) {
            let word = BigEndian::read_u16(&buffer[i..(i + 2)]);
            words.push(word);
        }

        /*
         * 全てのワードを足し算する。
         * オーバーフローを考慮して、32bits で計算結果を保持する。
         */
        let mut sum = 0u32;
        for &word in &words {
            sum = sum.wrapping_add(u32::from(word));
        }

        /*
         * オーバーフローした分を end-around carry して加え戻す
         */
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }
}
