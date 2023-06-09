use crate::transmission_control_protocol::TCP_PROTOCOL_NUMBER;
use byteorder::{BigEndian, ByteOrder};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum Ipv4HeaderDecodeError {
    InputTooShort,
    InvalidFieldValue(String),
    // More...
}

impl fmt::Display for Ipv4HeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipv4HeaderDecodeError::InputTooShort => write!(f, "Input too short."),
            Ipv4HeaderDecodeError::InvalidFieldValue(_todo) => write!(f, "Invalid field value."),
        }
    }
}

impl Error for Ipv4HeaderDecodeError {}

/*
 * 注意：IHL (Internet Header Length) 自体は 4bits.
 * しかし、それは 32bit words つまり 4bytes 単位でデータを表現している。なぜなら、IPヘッダーは各フィールドが32bitsだから。
 *
 *  よって、IHL の最小値は 5 なのであるが、それはヘッダーの最小値が 5 * 4 = 20bytes であることを意味している。
 */
const IHL_MIN_VALUE: usize = 5;
const IPV4_HEADER_UNIT_BITS: usize = 32;
const IPV4_HEADER_UNIT_BYTES: usize = IPV4_HEADER_UNIT_BITS / 8;
pub const IPV4_HEADER_MIN_LEN: usize = IHL_MIN_VALUE * IPV4_HEADER_UNIT_BYTES;
const IPV4_VERSION: u8 = 4;
const UDP_PROTOCOL_NUMBER: u8 = 17;

pub type Ipv4Address = [u8; 4];

/*
 * 注意：RFC791 によれば、例えば version などは 4bits であるが、Rust は 4bits のデータを直接表現できない。
 * よって、getter/setter でデータの整合性を保証する。
 */
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    version: u8,
    ihl: u8,

    /*
     * 注意：Type of Service の上位 6bits と下位 2bits に該当する。
     *
     * dscp: Differentiated Services Code Point. Quality of Service のために使われる。
     * ecn: Explicit Congestion Notification. 輻輳制御のために使われる。
     */
    dscp: u8,
    ecn: u8,

    total_length: u16,
    identification: u16,

    /*
     * 注意：Flags は 3bits
     */
    flags: u8,

    /*
     * 注意：Fragment Offset は　13bits
     */
    fragment_offset: u16,

    ttl: u8,
    protocol: u8,

    header_checksum: u16,

    /*
     * ここがいわゆる IP Address ですね。
     * source, destination
     */
    source_address: Ipv4Address,
    destination_address: Ipv4Address,
}

impl Ipv4Header {
    pub fn set_version(&mut self, version: u8) {
        assert!(
            version <= 0xF,
            "Invalid IP version value!!! It should be 4bits value."
        );
        self.version = version;
        self.set_header_checksum();
    }

    pub fn get_version(&self) -> u8 {
        /*
         * 補足：`&`はビット単位の論理積(AND)
         *
         * 0xF = 0b0000_1111 なので、これとの AND を取ることにより、4bits での値であることと見なして処理する。
         */
        self.version & 0xF
    }

    pub fn set_ihl(&mut self, ihl: u8) {
        assert!(
            ihl <= 0xF,
            "Invalid IP header length value!!! It hould be 4bits value."
        );
        self.ihl = ihl;
        self.set_header_checksum();
    }

    pub fn get_ihl(&self) -> u8 {
        self.ihl & 0xF
    }

    pub fn get_dscp_ecn(&self) -> u8 {
        let dscp = self.dscp & 0b0011_1111; // 上位 6bits を表す。
        let ecn = self.ecn & 0b0000_0011; // 下位 2bits を表す。

        (dscp << 2) | ecn
    }

    pub fn get_total_length(&self) -> u16 {
        self.total_length
    }

    pub fn get_identification(&self) -> u16 {
        self.identification
    }

    pub fn get_flags(&self) -> u8 {
        self.flags & 0b0000_0111
    }

    pub fn set_flags(&mut self, flags: u8) {
        assert!(
            flags <= 0b0000_0111,
            "Invalid Flags value!!! It should be 3bits value"
        );
        self.flags = flags;
        self.set_header_checksum();
    }

    pub fn get_fragment_offset(&self) -> u16 {
        // これと同じ：self.fragment_offset & 0b0001_1111_1111_1111
        self.fragment_offset & ((1 << 13) - 1)
    }

    pub fn get_ttl(&self) -> u8 {
        self.ttl
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
        self.set_header_checksum();
    }

    pub fn get_protocol(&self) -> u8 {
        self.protocol
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.protocol = protocol;
        self.set_header_checksum();
    }

    pub fn get_header_checksum(&self) -> u16 {
        self.header_checksum
    }

    pub fn get_source_address(&self) -> Ipv4Address {
        self.source_address
    }

    pub fn get_destination_address(&self) -> Ipv4Address {
        self.destination_address
    }

    /*
     * 注意：Header checksum は、他のヘッダーフィールドが変わった時（例：TTL）に、再計算をする必要がある。
     *
     * なので、他の setter を読んだときにこの`set_header_checksum`を呼ぶようにしたい。
     * 内部的に呼ぶだけにしたいので、`set_header_checksum`は public にしない。
     *
     * TODO: 各 setter の中で`set_header_checksum`を呼ぶのは性能的に良くないかもしれない？
     *       もし複数のフィールドを更新する必要があって、なおかつそれらのフィールド更新の間に、チェックサムが不整合な状態が存在しても構わないなら、まとめて一括で実施したい。
     */
    fn set_header_checksum(&mut self) {
        let checksum = self.calculate_header_checksum();
        self.header_checksum = checksum;
    }

    fn calculate_header_checksum(&self) -> u16 {
        /*
         * 注意：再計算する前に、Header Checksum はゼロにしておく必要がある。
         */
        let ipv4_header = Self {
            header_checksum: 0,
            ..self.clone()
        };

        /*
         * 1. ヘッダーをバイト列に変換する。
         */
        let bytes = ipv4_header.encode();

        /*
         * 2. ヘッダーを 16bits word に変換する。
         *
         *    Big Endian が通常は用いられるらしい？
         */
        let mut words = Vec::new();
        for i in (0..bytes.len()).step_by(2) {
            let word = BigEndian::read_u16(&bytes[i..i + 2]);
            words.push(word);
        }

        /*
         * 3. 全てのワードを足し算する。この時、オーバーフローの可能性があるので注意。
         *    なお、オーバーフローは無視します。
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

        /*
         * 4. 和の 1 の補数を取ります。
         *
         * 注意：オーバーフローを無視するので、まずは u16 に type cast する。
         * 注意：1の補数は、単にビットを反転させるだけで求められるので、反転演算子`!`を実行している。
         */
        let checksum = !(sum as u16);

        checksum
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 20];

        buffer[0] = (self.get_version() << 4) | self.get_ihl();

        buffer[1] = self.get_dscp_ecn();

        buffer[2..4].copy_from_slice(&self.get_total_length().to_be_bytes());

        buffer[4..6].copy_from_slice(&self.get_identification().to_be_bytes());

        let flags_fragment_offset = ((self.get_flags() as u16) << 13) | self.get_fragment_offset();
        buffer[6..8].copy_from_slice(&flags_fragment_offset.to_be_bytes());

        buffer[8] = self.get_ttl();

        buffer[9] = self.get_protocol();

        buffer[10..12].copy_from_slice(&self.get_header_checksum().to_be_bytes());

        buffer[12..16].copy_from_slice(&self.source_address);

        buffer[16..20].copy_from_slice(&self.destination_address);

        buffer
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, Ipv4HeaderDecodeError> {
        Self::validate_buffer_length(buffer)?;

        let version = buffer[0] & 0b1111_0000;
        let ihl = buffer[0] & 0b0000_1111;
        let dscp = buffer[1] & 0b1111_1100;
        let ecn = buffer[1] & 0b0000_0011;

        let total_length = ((buffer[2] as u16) << 8) | (buffer[3] as u16);
        let identification = ((buffer[4] as u16) << 8) | (buffer[5] as u16);

        let flags = buffer[6] & 0b1110_0000;
        let fragment_offset = (((buffer[6] & 0b0001_1111) as u16) << 8) | buffer[7] as u16;

        let ttl = buffer[8];
        let protocol = buffer[9];

        /*
         *
         * NOTE: ここで誤りがないかチェックする必要があるとか？？？
         *
         */
        let header_checksum = ((buffer[10] as u16) << 8) | buffer[11] as u16;
        let source_address: Ipv4Address = [buffer[12], buffer[13], buffer[14], buffer[15]];
        let destination_address: Ipv4Address = [buffer[16], buffer[17], buffer[18], buffer[19]];

        Self::validate_version(version)?;
        Self::validate_header_length(ihl, buffer.len())?;
        Self::validate_protocol(protocol)?;

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_address,
            destination_address,
        })
    }

    fn validate_buffer_length(buffer: &[u8]) -> Result<(), Ipv4HeaderDecodeError> {
        if buffer.len() < 20 {
            Err(Ipv4HeaderDecodeError::InputTooShort)
        } else {
            Ok(())
        }
    }

    fn validate_version(version: u8) -> Result<(), Ipv4HeaderDecodeError> {
        if version != IPV4_VERSION {
            Err(Ipv4HeaderDecodeError::InvalidFieldValue(
                "The `version` field should be 4.".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn validate_header_length(ihl: u8, buffer_length: usize) -> Result<(), Ipv4HeaderDecodeError> {
        if usize::from(ihl) < IHL_MIN_VALUE {
            Err(Ipv4HeaderDecodeError::InvalidFieldValue(format!(
                "The `ihl` field should not be less than {}.",
                IHL_MIN_VALUE
            )))
        } else if usize::from(ihl * 4) >= buffer_length {
            Err(Ipv4HeaderDecodeError::InvalidFieldValue(format!(
                "The `ihl` field value is larget than the byte length. ihl={}. byte_length={}",
                ihl, buffer_length
            )))
        } else {
            Ok(())
        }
    }

    fn validate_protocol(protocol: u8) -> Result<(), Ipv4HeaderDecodeError> {
        if protocol != TCP_PROTOCOL_NUMBER && protocol != UDP_PROTOCOL_NUMBER {
            Err(Ipv4HeaderDecodeError::InvalidFieldValue(format!(
                "Unknown `protocol` field value. protocol={}",
                protocol
            )))
        } else {
            Ok(())
        }
    }

    /*
     * NOTE: ついでだったので実装した。また実際にパケット受け取ったりするときに使います。
     */
    fn validate_checksum(&self) -> Result<(), Ipv4HeaderDecodeError> {
        let original_checksum = self.header_checksum;
        let checksum = self.calculate_header_checksum();

        if checksum != original_checksum {
            Err(Ipv4HeaderDecodeError::InvalidFieldValue(format!(
                "The header checksum doesn't match."
            )))
        } else {
            Ok(())
        }
    }
}
