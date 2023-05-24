use std::error::Error;
use std::fmt;
/*
 * See: https://www.rfc-editor.org/rfc/rfc9293.html
 */

#[derive(Debug)]
enum TcpHeaderDecodeError {
    InputTooShort,
    InvalidFieldValue(String),
}

impl fmt::Display for TcpHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpHeaderDecodeError::InputTooShort => write!(f, "Input too short."),
            TcpHeaderDecodeError::InvalidFieldValue(_todo) => write!(f, "Invalid field value."),
        }
    }
}

impl Error for TcpHeaderDecodeError {}

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
    // reserved: u8,

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
            sequence_number: 375912035,
            acknowledgment_number: 768347,
            data_offset: 5,
            // reserved: 0,
            control_bits,
            window: 1000,
            checksum: 2222,
            urgent_pointer: 3333,
            options: vec![],
        };

        let expected_output: Vec<u8> = vec![
            /*
             * Expected Source Port Bytes
             */
            21, 56, /*
                 * Expected Destination Port Bytes
                 */
            12, 234,
            /*
             * Sequence Number Bytes
             */
            22,  // ((375912035u32 & 0xFF00_0000) >> 24) as u8,
            103, // ((375912035u32 & 0x00FF_0000) >> 16) as u8,
            246, // ((375912035u32 & 0x0000_FF00) >> 8) as u8,
            99,  // (375912035u32 & 0x0000_00FF) as u8,
            /*
             * Acknowledgment Number Bytes
             */
            0,   // ((768347u32 & 0xFF00_0000) >> 24) as u8,
            11,  // ((768347u32 & 0x00FF_0000) >> 16) as u8,
            185, // ((768347u32 & 0x0000_FF00) >> 8) as u8,
            91,  // (768347u32 & 0x0000_00FF) as u8,
            /*
             * Data Offset Bytes and Reserved Bytes
             */
            80, /*
                 * Control Bits Bytes
                 */
            0,
            /*
             * Window Bytes
             */
            3,   // ((1000u16 & 0xFF00) >> 8) as u8,
            232, // (1000u16 & 0x00FF) as u8,
            /*
             * Checksum Bytes
             */
            8,   // ((2222u16 & 0xFF00) >> 8) as u8,
            174, // (2222u16 & 0x00FF) as u8,
            /*
             * Urgent Pointer
             */
            13, // ((3333u16 & 0xFF00) >> 8) as u8,
            5,  // (3333u16 & 0x00FF) as u8,

                /*
                 * Options Bytes
                 */
        ];

        assert_eq!(tcp_header.encode(), expected_output);
    }
}
