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

type Ipv4Address = [u8; 4];

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
    checksum: u16,

    /*
     * ここがいわゆる IP Address ですね。
     * source, destination
     */
    source: Ipv4Address,
    destination: Ipv4Address,
}

impl Ipv4Header {
    pub fn set_version(&mut self, version: u8) {
        assert!(
            version <= 0xF,
            "Invalid IP version value!!! It should be 4bits value."
        );
        self.version = version;
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
    }

    pub fn get_fragment_offset(&self) -> u16 {
        // これと同じ：self.fragment_offset & 0b0001_1111_1111_1111
        self.fragment_offset & ((1 << 13) - 1)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 20];

        /*
         * Version and IHL
         */
        buffer[0] = (self.get_version() << 4) | self.get_ihl();

        /*
         * Type of Service
         */
        buffer[1] = self.get_dscp_ecn();

        /*
         * Total Length
         */
        buffer[2..4].copy_from_slice(&self.get_total_length().to_be_bytes());

        /*
         * Identification
         */
        buffer[4..6].copy_from_slice(&self.get_identification().to_be_bytes());

        /*
         * Flags and Fragment Offset
         */
        let flags_fragment_offset = ((self.get_flags() as u16) << 13) | self.get_fragment_offset();
        buffer[6..8].copy_from_slice(&flags_fragment_offset.to_be_bytes());

        todo!();
    }
}
