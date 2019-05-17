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
//   HD = set if packet has data
//   B = set if packet is a batch read/write
//   DL = batch size / 4
//   datalength is 0 if HD clear
//   datalength is 4 if HD set and B clear (DL field ignored)
//   datalength = 4*DL if HD and B set
// |0|0|0|0|0|0|0|0| = packet address
//  Data
// |0|0|0|0|0|0|0|0| = first byte of data (up to 60 bytes)
// ....
//  Checksum
// |0|0|0|0|0|0|0|0| = first byte of checksum
// |0|0|0|0|0|0|0|0| = second byte of checksum

extern crate heapless;
use heapless::consts::*;
use heapless::Vec;

#[macro_use]
extern crate machine;

// constants for address range sizes
const CONFIG_ARRAY_SIZE: u8 = 64;
const DATA_ARRAY_SIZE: u8 = 60;
const COMMAND_COUNT: u8 = 12;

// MCU memory rep of a serial packet
// real packets don't have a datalen member
#[derive(Debug)]
pub struct USARTPacket {
    pt: u8,
    address: u8,
    checksum: u16,
    datalen: u8,
    packet_data: Vec<u8, U64>,
}

pub enum USARTPacketType {
    Config,
    Data,
    Command,
    Unknown,
}

impl USARTPacket {
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
             Data => fn can_collect_data(&self) -> bool,
             ChecksumComplete => get sum: u16,
             ChecksumComplete => fn can_collect_checksum(&self) -> bool
         ]
);

// wait state looking for packet header of 'snp'
impl Wait {
    pub fn on_advance(self, input: Advance) -> PacketParser {
        let got = match self.got {
            PacketHeaderBytes::W => {
                if input.ch == b's' {
                    PacketHeaderBytes::S
                } else {
                    PacketHeaderBytes::W
                }
            }
            PacketHeaderBytes::S => {
                if input.ch == b'n' {
                    PacketHeaderBytes::N
                } else {
                    PacketHeaderBytes::W
                }
            }
            PacketHeaderBytes::N => {
                if input.ch == b'p' {
                    PacketHeaderBytes::P
                } else {
                    PacketHeaderBytes::W
                }
            }
            PacketHeaderBytes::P => PacketHeaderBytes::W,
        };
        if got != PacketHeaderBytes::P {
            println!("to wait");
            PacketParser::wait(got)
        } else {
            println!("To packettype");
            PacketParser::packettype()
        }
    }
}

// After the header, we receive the packet type byte
impl PacketType {
    pub fn on_advance(self, input: Advance) -> Address {
        println!("to address");
        Address { ty: input.ch }
    }
}

// After the packet type byte, we receive the address
impl Address {
    pub fn on_advance(self, input: Advance) -> HaveHeader {
        println!("to haveheader");
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
        let flags = self.ty & (0xC0);
        match flags {
            0x80 => PacketParser::data(4, 0),
            0xC0 => PacketParser::data(4 * ((self.ty >> 2) & 0x0F), 0),
            _ => PacketParser::checksum(true, 0),
        }
    }

    pub fn can_collect_header(&self) -> bool {
        println!("can collect header");
        true
    }
}

// get the packet data (if any)
impl Data {
    pub fn on_advance(self, input: Advance) -> PacketParser {
        println!("ch: {}", input.ch);
        println!("len: {}", self.len);
        println!("offset: {}", self.offset);
        if self.offset < self.len - 1 {
            println!("to data");
            PacketParser::data(self.len, self.offset + 1)
        } else {
            println!("to checksum");
            PacketParser::checksum(true, 0)
        }
    }

    pub fn can_collect_data(&self) -> bool {
        println!("Can Collect data");
        true
    }
}

// receive the transmitted checksum bytes
impl Checksum {
    pub fn on_advance(self, input: Advance) -> PacketParser {
        println!("First: {} Sum: {}", self.first, self.sum);
        if self.first {
            let s: (u16) = input.ch.into();
            println!("to checksum");
            PacketParser::checksum(false, s << 8)
        } else {
            let s: (u16) = input.ch.into();
            println!("to checksumcomplete with {}", s | self.sum);
            PacketParser::checksumcomplete(s | self.sum)
        }
    }
}

// allow outside code to check checksum and do something with the packet
// recycle
impl ChecksumComplete {
    pub fn on_advance(self, _: Advance) -> Wait {
        println!("to wait");
        Wait {
            got: PacketHeaderBytes::W,
        }
    }

    pub fn can_collect_checksum(&self) -> bool {
        println!("can collect checksum");
        true
    }
}

#[derive(Debug)]
pub struct SerialPacketParser {
    parser: PacketParser,
    pkt: USARTPacket,
}

impl SerialPacketParser {
    pub fn init() -> SerialPacketParser {
        SerialPacketParser {
            parser: PacketParser::Wait(Wait {
                got: PacketHeaderBytes::W,
            }),
            pkt: USARTPacket {
                pt: 0,
                address: 0,
                checksum: 0,
                datalen: 0,
                packet_data: Vec::new(),
            },
        }
    }

    pub fn parse_received_byte(mut self, byte: u8) -> SerialPacketParser {
        println!("Parser before advance {:?} byte:{}", self.parser, byte);
        let last_data = self.parser.can_collect_data();
        match last_data {
            Some(_) => {
                println!("Data: {}", byte);
                self.pkt.datalen = *unwrap_u8(self.parser.len());
                // it is not possible for the data array to be full
                // but if the impossible happens, go to initial state
                self = match self.pkt.packet_data.push(byte) {
                    Ok(_t) => self,
                    Err(_e) => SerialPacketParser::init(),
                };
            }
            None => {}
        }
        self.parser = self.parser.on_advance(Advance { ch: byte });
        println!("Parser after advance {:?} byte:{}", self.parser, byte);
        // collect checksum
        let mut result = self.parser.can_collect_checksum();
        match result {
            Some(_) => {
                self.pkt.checksum = *unwrap_u16(self.parser.sum());
                println!("chksum: {}", self.pkt.checksum);
                // Check the packet...
                if SerialPacketParser::compare_checksum(&self.pkt, self.pkt.checksum) {
                    SerialPacketParser::dispatch_received_packet(&self);
                } else {
                    SerialPacketParser::send_bad_checksum_packet(&self);
                }
                // go to wait state
                self.parser = self.parser.on_advance(Advance { ch: byte });
            }
            None => {
                // or collect header
                result = self.parser.can_collect_header();
                match result {
                    Some(_) => {
                        self.pkt.pt = *unwrap_u8(self.parser.ty());
                        self.pkt.address = *unwrap_u8(self.parser.addr());
                        println!("pt: {}", self.pkt.pt);
                        println!("address: {}", self.pkt.address);
                        // advance to either checksum or data
                        self.parser = self.parser.on_advance(Advance { ch: byte });
                    }
                    None => {}
                }
            }
        }
        self
    }

    // given a packet, calculate the checksum for it
    pub fn compute_checksum(pkt: &USARTPacket) -> u16 {
        let pt: u16 = pkt.pt.into();
        let addr: u16 = pkt.address.into();
        let mut sum: u16 = 0x0073 + 0x006E + 0x0070 + pt + addr;
        for byte in pkt.packet_data.iter() {
            let b16: u16 = (*byte).into();
            sum += b16;
        }
        sum
    }

    // given a packet compare stored checksum with calculated checksum
    fn compare_checksum(pkt: &USARTPacket, reqsum: u16) -> bool {
        reqsum == SerialPacketParser::compute_checksum(pkt)
    }

    fn dispatch_received_packet(&self) {
        println!("packet received");
    }

    fn send_bad_checksum_packet(&self) {
        println!("send bad checksum packet");
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
        let pktdata: [u8; 7] = [b's', b'n', b'p', 0x00, 0xCD, 0x02, 0x1e];
        let mut parser = SerialPacketParser::init();
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.pkt.pt, 0x00);
        assert_eq!(parser.pkt.address, 0xCD);
        assert_eq!(parser.pkt.datalen, 0);
        assert_eq!(parser.pkt.checksum, 0x021E);
        assert_eq!(SerialPacketParser::compute_checksum(&parser.pkt), 0x021E);
    }

    #[test]
    fn single_reg_data_pkt() {
        // a single register data test packet
        let pktdata: [u8; 11] = [
            b's', b'n', b'p', 0x80, 0x01, 0xAB, 0xCD, 0xEF, 0x12, 0x04, 0x4B,
        ];
        let mut parser = SerialPacketParser::init();
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.pkt.pt, 0x80);
        assert_eq!(parser.pkt.address, 0x01);
        assert_eq!(parser.pkt.datalen, 4);
        assert_eq!(parser.pkt.packet_data[0], 0xAB);
        assert_eq!(parser.pkt.packet_data[1], 0xCD);
        assert_eq!(parser.pkt.packet_data[2], 0xEF);
        assert_eq!(parser.pkt.packet_data[3], 0x12);
        assert_eq!(parser.pkt.checksum, 0x044B);
        assert_eq!(SerialPacketParser::compute_checksum(&parser.pkt), 0x044B);
    }

    #[test]
    fn mult_reg_data_pkt() {
        // a multiple register data test packet
        let pktdata: [u8; 15] = [
            b's', b'n', b'p', 0xc8, 0x03, 0xAB, 0xCD, 0xEF, 0x12, 0xAB, 0xCD, 0xEF, 0x12, 0x07,
            0x0E,
        ];
        let mut parser = SerialPacketParser::init();
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.pkt.pt, 0xC8);
        assert_eq!(parser.pkt.address, 0x03);
        assert_eq!(parser.pkt.datalen, 8);
        assert_eq!(parser.pkt.packet_data[0], 0xAB);
        assert_eq!(parser.pkt.packet_data[1], 0xCD);
        assert_eq!(parser.pkt.packet_data[2], 0xEF);
        assert_eq!(parser.pkt.packet_data[3], 0x12);
        assert_eq!(parser.pkt.packet_data[4], 0xAB);
        assert_eq!(parser.pkt.packet_data[5], 0xCD);
        assert_eq!(parser.pkt.packet_data[6], 0xEF);
        assert_eq!(parser.pkt.packet_data[7], 0x12);
        assert_eq!(parser.pkt.checksum, 0x070E);
        assert_eq!(SerialPacketParser::compute_checksum(&parser.pkt), 0x070E);
    }

    #[test]
    fn corrupted() {
        // a corrupted data test packet
        let pktdata: [u8; 15] = [
            b's', b'n', b'b', 0xc8, 0x03, 0xAB, 0xCD, 0xEF, 0x12, 0xAB, 0xCD, 0xEF, 0x12, 0x07,
            0x0E,
        ];
        let mut parser = SerialPacketParser::init();
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte);
        }
        assert_eq!(parser.pkt.pt, 0);
        assert_eq!(parser.pkt.address, 0);
        assert_eq!(parser.pkt.datalen, 0);
        assert_eq!(parser.pkt.checksum, 0);
    }
}
