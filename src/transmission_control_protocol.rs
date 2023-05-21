/*
 * See: https://www.rfc-editor.org/rfc/rfc9293.html
 */
#[derive(Debug)]
pub struct TcpHeader {
    /*
     * Source Port (16bits)
     */
    source_port: u16,

    /*
     * Destination Port (16bits)
     */
    destination_port: u16,

    /*
     * Sequence Number (32bits)
     */
    sequence_number: u32,

    /*
     * Acknowledgement Number (32bits)
     */
    acknowledgment_number: u32,

    /*
     * Data Offset (4bits)
     */
    data_offset: u8,

    /*
     * Reserved (4bits)
     */
    reserved: u8,

    /*
     * Control Bits (8bits)
     */
    control_bits: ControlBits,

    /*
     * Window (16bits)
     */
    window: u16,

    /*
     * Checksum (16bits)
     */
    checksum: u16,

    /*
     * Urgent Pointer (16bits)
     */
    urgent_pointer: u16,

    /*
     * Options
     */
    options: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ControlBits {
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

impl TcpHeader {
    fn get_data_offset(&self) -> u8 {
        self.data_offset & 0b0000_1111
    }

    /*
     * NOTE: `0`であるべきって仕様.
     */
    fn get_reserved(&self) -> u8 {
        0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 20];

        buffer[0..2].copy_from_slice(&self.source_port.to_be_bytes());

        buffer[2..4].copy_from_slice(&self.destination_port.to_be_bytes());

        buffer[4..8].copy_from_slice(&self.sequence_number.to_be_bytes());

        buffer[8..12].copy_from_slice(&self.acknowledgment_number.to_be_bytes());

        buffer[12] = (self.get_data_offset() << 4) | self.get_reserved();

        buffer[13] = self.control_bits.encode();

        buffer[14..16].copy_from_slice(&self.window.to_be_bytes());

        buffer[16..18].copy_from_slice(&self.checksum.to_be_bytes());

        buffer[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());

        buffer.extend(&self.options);

        buffer
    }
}

impl ControlBits {
    fn encode(&self) -> u8 {
        (u8::from(self.cwr) << 7)
            | (u8::from(self.ece) << 6)
            | (u8::from(self.urg) << 5)
            | (u8::from(self.ack) << 4)
            | (u8::from(self.psh) << 3)
            | (u8::from(self.rst) << 2)
            | (u8::from(self.syn) << 1)
            | u8::from(self.fin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_encode() {
        let control_bits = ControlBits {
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
        };

        let tcp_header = TcpHeader {
            source_port: 5432,
            destination_port: 3306,
            sequence_number: 100,
            acknowledgment_number: 200,
            data_offset: 5,
            reserved: 0,
            control_bits,
            window: 10,
            checksum: 123,
            urgent_pointer: 50,
            options: vec![],
        };

        let expected_output: Vec<u8> = vec![
            /*
             * Expected Source Port Bytes
             */
            21, // ((5432u16 & 0b1111_1111_0000_0000) >> 8) as u8,
            56, // (5432u16 & 0b0000_0000_1111_1111) as u8,

                /*
                 * Expected Destination Port Bytes
                 */

                /*
                 * ToDo...
                 */
        ];

        assert_eq!(tcp_header.encode(), expected_output);
    }
}
