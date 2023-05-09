use byteorder::{ByteOrder, NetworkEndian};

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

/*
 * 注意：RFC791 によれば、例えば version などは 4bits であるが、Rust は 4bits のデータを直接表現できない。
 * よって、getter/setter でデータの整合性を保証する。
 */
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: [u8; 4],
    destination: [u8; 4],
}

impl Ipv4Header {
    pub fn set_version(&mut self, version: u8) {
        assert!(
            version <= 0xF,
            "Invalid IP version value!!! It should be 4bits value."
        );
        self.version = version;
    }

    pub fn get_version(&mut self) -> u8 {
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
    }

    pub fn get_ihl(&self) -> u8 {
        self.ihl & 0xF
    }
}
