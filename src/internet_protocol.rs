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

    pub fn get_ttl(&self) -> u8 {
        self.ttl
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    pub fn get_protocol(&self) -> u8 {
        self.protocol
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.protocol = protocol;
    }

    pub fn get_header_checksum(&self) -> u16 {
        self.header_checksum
    }

    /*
     * 注意：Header checksum は、他のヘッダーフィールドが変わった時（例：TTL）に、再計算をする必要がある。
     *
     * なので、他の setter を読んだときにこの`set_header_checksum`を呼ぶようにしたい。
     * 内部的に呼ぶだけにしたいので、`set_header_checksum`は public にしない。
     */
    fn set_header_checksum(&mut self) {
        unimplemented!();
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
}
