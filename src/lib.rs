#![no_std]
//! # serial_packet
//!
//! ## Features
//!
//! This crate defines a SerialPacketParser that will receive a byte at a time and
//! parse serial packets from the stream

// Incoming Packet Bytes
//  Header
// |0|1|1|1|0|0|1|1| = 's'
// |0|1|1|0|1|1|1|0| = 'n'
// |0|1|1|1|0|0|0|0| = 'p'
// |HD|B|DL3|DL2|DL1|DL0|x|x| = packet type
//   HD = set if packet has data to write
//   B = set if packet is a batch read/write
//   DL = batch size / 4
//   datalength is 0 if HD clear
//   datalength is 4 if HD set and B clear (DL field ignored)
//   datalength = 4*DL if HD and B set, a write request with bytes to write
//   datalength = 4*DL if HD clear and B set, a read request
// |0|0|0|0|0|0|0|0| = packet address
//  Data
// |0|0|0|0|0|0|0|0| = first byte of data (up to 60 bytes)
// ....
//  Checksum
// |0|0|0|0|0|0|0|0| = first byte of checksum
// |0|0|0|0|0|0|0|0| = second byte of checksum

#[macro_use]
extern crate machine;

// constants for address range sizes
const CONFIG_ARRAY_SIZE: u8 = 64;
const DATA_ARRAY_SIZE: u8 = 60;
const COMMAND_COUNT: u8 = 12;

// MCU memory rep of a serial packet
// real packets don't have a datalen member
#[derive(Copy,Clone)]
pub struct USARTPacket {
    pub pt: u8,
    pub address: u8,
    pub checksum: u16,
    pub datalen: u8,
    pub data: [u8; 64],
}

pub enum USARTPacketType {
    Config,
    Data,
    Command,
    Unknown,
}

impl USARTPacket {
    pub fn new() -> USARTPacket {
        USARTPacket {
            pt: 0,
            address: 0,
            checksum: 0,
            datalen: 0,
            data: [0; 64],
        }
    }
        
    pub fn packet_type(self) -> USARTPacketType {
        if self.address < CONFIG_ARRAY_SIZE {
            USARTPacketType::Config
        } else if self.address >= CONFIG_ARRAY_SIZE
            && self.address < CONFIG_ARRAY_SIZE + DATA_ARRAY_SIZE
        {
            USARTPacketType::Data
        } else if self.address < CONFIG_ARRAY_SIZE + DATA_ARRAY_SIZE + COMMAND_COUNT {
            USARTPacketType::Command
        } else {
            USARTPacketType::Unknown
        }
    }

    pub fn specified_data_size(&self) -> u8 {
        let flags = self.pt & 0xC0;
        match flags {
            0b1000_0000 => 4,
            0b1100_0000 => 4 * ((self.pt >> 2) & 0x0F),
            0b0100_0000 => 4 * ((self.pt >> 2) & 0x0F),
            _ => 0,
        }
    }

    // given a packet, calculate the checksum for it
    pub fn compute_checksum(&self) -> u16 {
        let pt: u16 = self.pt.into();
        let addr: u16 = self.address.into();
        let mut sum: u16 = 0x0073 + 0x006E + 0x0070 + pt + addr;
        for byte in self.data.iter() {
            let b16: u16 = (*byte).into();
            sum += b16;
        }
        sum
    }

    // given a packet compare stored checksum with calculated checksum
    fn compare_checksum(&self) -> bool {
        self.checksum == self.compute_checksum()
    }

}

#[derive(Clone, Debug, PartialEq)]
pub enum PacketHeaderBytes {
    W,
    S,
    N,
    P,
}

//https://github.com/rust-bakery/machine

// Define the machine states
machine!(
    #[derive(Clone, Debug, PartialEq)]
    enum PacketParser {
        Wait { got: PacketHeaderBytes },
        PacketType,
        Address { ty: u8 },
        HaveHeader { ty: u8, addr: u8 },
        Data { len: u8, offset: u8 },
        Checksum { first: bool, sum: u16 },
        ChecksumComplete { sum: u16 },
    }
);

// The transition types
#[derive(Clone, Debug, PartialEq)]
pub struct Advance {
    ch: u8,
}

// the allowed state, transition pairs
transitions!(PacketParser,
             [
                 (Wait, Advance) => [PacketType, Wait],
                 (PacketType, Advance) => Address,
                 (Address, Advance) => HaveHeader,
                 (HaveHeader, Advance) => [Data, Checksum],
                 (Data, Advance) => [Data, Checksum],
                 (Checksum, Advance) => [ChecksumComplete, Checksum],
                 (ChecksumComplete, Advance) => Wait
             ]
);

// additional methods to add to the parser for retrieving data
methods!(PacketParser,
         [
             HaveHeader => get ty: u8,
             HaveHeader => get addr: u8,
             HaveHeader => fn can_collect_header(&self) -> bool,
             Data => get len: u8,
             Data => get offset: u8,
             Data => fn can_collect_data(&self) -> bool,
             ChecksumComplete => get sum: u16,
             ChecksumComplete => fn can_collect_checksum(&self) -> bool
         ]
);

// wait state looking for packet header of 'snp'
impl Wait {
    pub fn on_advance(self, input: Advance) -> PacketParser {
        let got = match (self.got, input.ch) {
            (PacketHeaderBytes::W, b's') => PacketHeaderBytes::S,
            (PacketHeaderBytes::S, b'n') => PacketHeaderBytes::N,
            (PacketHeaderBytes::N, b'p') => PacketHeaderBytes::P,
            (_, _) => PacketHeaderBytes::W,
        };
        if got != PacketHeaderBytes::P {
            PacketParser::wait(got)
        } else {
            PacketParser::packettype()
        }
    }
}

// After the header, we receive the packet type byte
impl PacketType {
    pub fn on_advance(self, input: Advance) -> Address {
        Address { ty: input.ch }
    }
}

// After the packet type byte, we receive the address
impl Address {
    pub fn on_advance(self, input: Advance) -> HaveHeader {
        HaveHeader {
            ty: self.ty,
            addr: input.ch,
        }
    }
}

// once we have the header, type, and address, go to a state where
// outside code can retrieve the type and address, calculate the packet
// data length
impl HaveHeader {
    pub fn on_advance(self, _: Advance) -> PacketParser {
        let flags = self.ty & 0xC0;
        match flags {
            0b1000_0000 => PacketParser::data(4, 0),
            0b1100_0000 => PacketParser::data(4 * ((self.ty >> 2) & 0x0F), 0),
            0b0100_0000 => PacketParser::checksum(true, 0),
            _ => PacketParser::checksum(true, 0),
        }
    }

    pub fn can_collect_header(&self) -> bool {
        true
    }
}

// get the packet data (if any)
impl Data {
    pub fn on_advance(self, _input: Advance) -> PacketParser {
        if self.offset < self.len - 1 {
            PacketParser::data(self.len, self.offset + 1)
        } else {
            PacketParser::checksum(true, 0)
        }
    }

    pub fn can_collect_data(&self) -> bool {
        true
    }
}

// receive the transmitted checksum bytes
impl Checksum {
    pub fn on_advance(self, input: Advance) -> PacketParser {
        if self.first {
            let s: (u16) = input.ch.into();
            PacketParser::checksum(false, s << 8)
        } else {
            let s: (u16) = input.ch.into();
            PacketParser::checksumcomplete(s | self.sum)
        }
    }
}

// allow outside code to collect checksum
// back to wait state
impl ChecksumComplete {
    pub fn on_advance(self, _: Advance) -> Wait {
        Wait {
            got: PacketHeaderBytes::W,
        }
    }

    pub fn can_collect_checksum(&self) -> bool {
        true
    }
}

pub struct SerialPacketParser<'a> {
    parser: PacketParser,
    pkt_buffer: &'a mut USARTPacket,
    have_recvd_pkt: bool,
}

impl <'a> SerialPacketParser<'a> {

    pub fn init(pkt: &'a mut USARTPacket) -> SerialPacketParser<'a> {
        SerialPacketParser {
            parser: PacketParser::Wait(Wait {
                got: PacketHeaderBytes::W,
            }),
            pkt_buffer: pkt,
            have_recvd_pkt: false,
        }
    }

    pub fn parse_received_byte(self, byte: u8) -> SerialPacketParser<'a> {
        // println!("Parser before advance {:?} byte:{}", self.parser, byte);
        match self.parser.can_collect_data() {
            Some(_) => {
                // println!("Data: {}", byte);
                let i: usize = (*unwrap_u8(self.parser.offset())).into();
                self.pkt_buffer.data[i] = byte;
            }
            None => {}
        }
        let mut p = self.parser.on_advance(Advance { ch: byte });
        // println!("Parser after advance {:?} byte:{}", p, byte);
        // collect checksum
        let pkt_recvd = match p.can_collect_checksum() {
            Some(_) => {
                self.pkt_buffer.checksum = *unwrap_u16(p.sum());
                // println!("chksum: {}", self.pkt_buffer.checksum);
                // go to wait state
                p = p.on_advance(Advance { ch: byte });
                true
            }
            None => {
                // or collect header
                match p.can_collect_header() {
                    Some(_) => {
                        self.pkt_buffer.pt = *unwrap_u8(p.ty());
                        self.pkt_buffer.address = *unwrap_u8(p.addr());
                        self.pkt_buffer.datalen = self.pkt_buffer.specified_data_size();
                        // println!("pt: {}", self.pkt_buffer.pt);
                        // println!("address: {}", self.pkt_buffer.address);
                        // advance to either checksum or data
                        p = p.on_advance(Advance { ch: byte });
                    }
                    None => {}
                }
                false
            }
        };
        SerialPacketParser {parser: p, pkt_buffer: self.pkt_buffer, have_recvd_pkt: pkt_recvd}
    }
}

pub fn dispatch_after_parsing(parser: & mut SerialPacketParser) {
    if parser.have_recvd_pkt {
        match parser.pkt_buffer.compare_checksum() {
            true => {
                parser.have_recvd_pkt = false;
                0
            }
            false => 1,
        };
    }
}

fn unwrap_u8(optional: Option<&u8>) -> &u8 {
    match optional {
        Some(p) => p,
        None => panic!(""),
    }
}

fn unwrap_u16(optional: Option<&u16>) -> &u16 {
    match optional {
        Some(p) => p,
        None => panic!(""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_pkt() {
        // a command test packet
        let pktdata: [u8; 7] = [b's', b'n', b'p', 0b0000_0000, 0xCD, 0x02, 0x1e];
        let mut pkt = USARTPacket {pt: 0, address: 0, checksum: 0, datalen: 0, data: [0; 64] };
        let mut parser = SerialPacketParser::init(& mut pkt);
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.have_recvd_pkt, true);
        assert_eq!(parser.pkt_buffer.pt, 0b0000_0000);
        assert_eq!(parser.pkt_buffer.address, 0xCD);
        assert_eq!(parser.pkt_buffer.datalen, 0);
        assert_eq!(parser.pkt_buffer.checksum, 0x021E);
        assert_eq!(parser.pkt_buffer.compare_checksum(), true);
    }

    #[test]
    fn multi_reg_read_pkt() {
        // a multiple register read test packet
        let pktdata: [u8; 7] = [b's', b'n', b'p', 0b0101_1000, 0x45, 0x01, 0xEE];
        let mut pkt = USARTPacket {pt: 0, address: 0, checksum: 0, datalen: 0, data: [0; 64] };
        let mut parser = SerialPacketParser::init(& mut pkt);
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.have_recvd_pkt, true);
        assert_eq!(parser.pkt_buffer.pt, 0b0101_1000);
        assert_eq!(parser.pkt_buffer.address, 0x45);
        assert_eq!(parser.pkt_buffer.datalen, 24);
        assert_eq!(parser.pkt_buffer.checksum, 0x01EE);
        assert_eq!(parser.pkt_buffer.compare_checksum(), true);
    }

    #[test]
    fn single_reg_write_data_pkt() {
        // a single register data test packet
        let pktdata: [u8; 11] = [
            b's', b'n', b'p', 0b1000_0000, 0x01, 0xAB, 0xCD, 0xEF, 0x12, 0x04, 0x4B,
        ];
        let mut pkt = USARTPacket {pt: 0, address: 0, checksum: 0, datalen: 0, data: [0; 64] };
        let mut parser = SerialPacketParser::init(& mut pkt);
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.have_recvd_pkt, true);
        assert_eq!(parser.pkt_buffer.pt, 0b1000_0000);
        assert_eq!(parser.pkt_buffer.address, 0x01);
        assert_eq!(parser.pkt_buffer.datalen, 4);
        assert_eq!(parser.pkt_buffer.data[0], 0xAB);
        assert_eq!(parser.pkt_buffer.data[1], 0xCD);
        assert_eq!(parser.pkt_buffer.data[2], 0xEF);
        assert_eq!(parser.pkt_buffer.data[3], 0x12);
        assert_eq!(parser.pkt_buffer.checksum, 0x044B);
        assert_eq!(parser.pkt_buffer.compare_checksum(), true);
    }

    #[test]
    fn mult_reg_write_data_pkt() {
        // a multiple register data test packet
        let pktdata: [u8; 15] = [
            b's', b'n', b'p', 0b1100_1000, 0x03, 0xAB, 0xCD, 0xEF, 0x12, 0xAB, 0xCD, 0xEF, 0x12, 0x07,
            0x0E,
        ];
        let mut pkt = USARTPacket {pt: 0, address: 0, checksum: 0, datalen: 0, data: [0; 64] };
        let mut parser = SerialPacketParser::init(& mut pkt);
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.have_recvd_pkt, true);
        assert_eq!(parser.pkt_buffer.pt, 0b1100_1000);
        assert_eq!(parser.pkt_buffer.address, 0x03);
        assert_eq!(parser.pkt_buffer.datalen, 8);
        assert_eq!(parser.pkt_buffer.data[0], 0xAB);
        assert_eq!(parser.pkt_buffer.data[1], 0xCD);
        assert_eq!(parser.pkt_buffer.data[2], 0xEF);
        assert_eq!(parser.pkt_buffer.data[3], 0x12);
        assert_eq!(parser.pkt_buffer.data[4], 0xAB);
        assert_eq!(parser.pkt_buffer.data[5], 0xCD);
        assert_eq!(parser.pkt_buffer.data[6], 0xEF);
        assert_eq!(parser.pkt_buffer.data[7], 0x12);
        assert_eq!(parser.pkt_buffer.checksum, 0x070E);
        assert_eq!(parser.pkt_buffer.compare_checksum(), true);
    }

    #[test]
    fn corrupted() {
        // a corrupted data test packet
        let pktdata: [u8; 15] = [
            b's', b'n', b'b', 0xc8, 0x03, 0xAB, 0xCD, 0xEF, 0x12, 0xAB, 0xCD, 0xEF, 0x12, 0x07,
            0x0E,
        ];
        let mut pkt = USARTPacket {pt: 0, address: 0, checksum: 0, datalen: 0, data: [0; 64] };
        let mut parser = SerialPacketParser::init(& mut pkt);
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_ne!(parser.have_recvd_pkt, true);
        assert_eq!(parser.pkt_buffer.pt, 0);
        assert_eq!(parser.pkt_buffer.address, 0);
        assert_eq!(parser.pkt_buffer.datalen, 0);
        assert_eq!(parser.pkt_buffer.checksum, 0);
    }
}
