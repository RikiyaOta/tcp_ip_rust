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
