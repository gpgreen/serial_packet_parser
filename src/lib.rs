#![no_std]
//! # serial_network_packet
//!
//! ## Features
//!
//! This crate defines a SerialNetworkPacket that is intended to work with devices that have
//! an address and value type of configuration. The targeted addresses are expected to be mostly
//! sequential, so that multiple values can be written with a starting address that is incremented
//! for each value. This behaviour is similar to that implemented in a lot of hardware peripherals.
//! There are 4 types of packets, Read/Write/BatchRead/BatchWrite. The sequence of values can
//! be up to 64 bytes in length. This keeps the packet to a known maximum size so that it is easy
//! to use on systems with no dynamic memory allocation.
//!
//! The packet's are defined as follows:
//! ```ignore
//! |0|1|1|1|0|0|1|1| = 's'
//! |0|1|1|0|1|1|1|0| = 'n'
//! |0|1|1|1|0|0|0|0| = 'p'
//! |WR|B|DL3|DL2|DL1|DL0|x|x| = packet type
//!   WR (Write bit) = set if packet has data to write
//!   B (Batch Bit) = set if packet is a batch read, ignored if write
//!   DL (Datalen field) = (datalen / 4) >> 1
//!     [WR:0 B:0] datalength = 0
//!     [WR:1 B:x] datalength = 4 * (DL + 4), a write request with bytes to write
//!     [WR:0 B:1] datalength = 4 * (DL + 4), a read request
//!   Final 2 bits are ignored
//! |x|x|x|x|x|x|x|x| = packet address
//! |x|x|x|x|x|x|x|x| = first byte of data
//! ....
//! |x|x|x|x|x|x|x|x| = last byte of data
//! |x|x|x|x|x|x|x|x| = first (high) byte of checksum
//! |x|x|x|x|x|x|x|x| = second (low) byte of checksum
//! ```
//! This crate defines a `PacketParser` which is a state machine that parses
//! SerialNetworkPacket's a byte at a time. This is intended for use with Serial Port
//! hardware. The parser is implemented with the `machine` crate.

#[macro_use]
extern crate machine;
mod parser;

use core::convert::TryFrom;
use core::ops::RangeInclusive;
use defmt::Format;
use parser::PacketParser;

/// Errors that can be encountered in this crate
#[derive(Debug, Copy, Clone, PartialEq, Format)]
pub enum SerialPacketError {
    /// Data length not within bounds
    DataLen(usize),
    /// Checksum doesn't match contents of packet
    Checksum,
    /// A write packet must have data
    WritePacketEmptyData,
}

/// Constrain a u8 to values allowed for packet data length [4..64]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Format)]
pub struct PacketDataLen(u8);

impl PacketDataLen {
    /// Create a new PacketDataLen
    pub const fn new(value: u8) -> Result<Self, SerialPacketError> {
        if value >= 4 && value <= 64 {
            Ok(Self(value))
        } else {
            Err(SerialPacketError::DataLen(value as usize))
        }
    }
    /// Get the u8 value of the PacketDataLen
    pub const fn u8(&self) -> u8 {
        self.0
    }
}

impl TryFrom<usize> for PacketDataLen {
    type Error = SerialPacketError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if RangeInclusive::new(4, 64).contains(&value) {
            Ok(Self(value as u8))
        } else {
            Err(SerialPacketError::DataLen(value))
        }
    }
}

/// Serial Packet Type Enumeration
#[derive(Debug, Copy, Clone, PartialEq, Eq, Format)]
pub enum SerialPacketType {
    Read,
    BatchRead(PacketDataLen),
    Write(PacketDataLen),
}

impl From<SerialPacketTypeField> for SerialPacketType {
    fn from(ptf: SerialPacketTypeField) -> Self {
        match (ptf.is_batch(), ptf.is_write()) {
            (false, false) => SerialPacketType::Read,
            (true, false) => {
                SerialPacketType::BatchRead(PacketDataLen::new(ptf.datalen()).unwrap())
            }
            (false, true) | (true, true) => {
                SerialPacketType::Write(PacketDataLen::new(ptf.datalen()).unwrap())
            }
        }
    }
}

impl SerialPacketType {
    /// Get an equivalent u8 for the Enumeration value
    pub fn u8(&self) -> u8 {
        match self {
            SerialPacketType::Read => 0,
            SerialPacketType::BatchRead(datalen) => 0b0100_0000 | (datalen.u8() - 4),
            SerialPacketType::Write(datalen) => 0b1100_0000 | (datalen.u8() - 4),
        }
    }
}

/// Packet Type Field
#[derive(Debug, Copy, Clone, Format, PartialEq)]
pub struct SerialPacketTypeField(u8);

impl SerialPacketTypeField {
    /// is this a write request
    pub fn is_write(&self) -> bool {
        self.0 & 0x80 != 0
    }
    /// is this a batch request?
    pub fn is_batch(&self) -> bool {
        self.0 & 0x40 != 0
    }
    /// datalength in bytes
    pub fn datalen(&self) -> u8 {
        match self.0 & 0b1100_0000 {
            // read request, no data
            0b0000_0000 => 0,
            // others, 4 * (data len + 1 bit)
            0b0100_0000 | 0b1100_0000 | 0b1000_0000 => 4 * (((self.0 & 0x3c) + 4) >> 2),
            _ => panic!(), // will never be reached
        }
    }
}

impl From<u8> for SerialPacketTypeField {
    fn from(byte: u8) -> Self {
        SerialPacketTypeField(byte & 0b1111_1100)
    }
}

impl From<SerialPacketType> for SerialPacketTypeField {
    fn from(ty: SerialPacketType) -> Self {
        SerialPacketTypeField(ty.u8())
    }
}

/// Serial Network Packet
#[derive(Debug, Copy, Clone, Format)]
pub struct SerialNetworkPacket {
    pub pt: SerialPacketTypeField,
    pub address: u8,
    pub checksum: u16,
    pub data: [u8; 64],
}

impl SerialNetworkPacket {
    /// an empty packet
    pub fn empty() -> Self {
        SerialNetworkPacket {
            pt: SerialPacketTypeField::from(SerialPacketType::Read),
            address: 0,
            checksum: 0,
            data: [0; 64],
        }
    }

    /// a Read packet
    pub fn new_read(address: u8, datalen: PacketDataLen) -> Result<Self, SerialPacketError> {
        let ty = if datalen.u8() == 4 {
            SerialPacketType::Read
        } else {
            SerialPacketType::BatchRead(datalen)
        };
        // calculate the checksum
        let mut pkt = SerialNetworkPacket {
            pt: SerialPacketTypeField::from(ty),
            address,
            checksum: 0,
            data: [0; 64],
        };
        pkt.checksum = pkt.compute_checksum();
        Ok(pkt)
    }

    /// a Write packet
    pub fn new_write(address: u8, data: &[u8]) -> Result<Self, SerialPacketError> {
        let ty = if data.is_empty() {
            return Err(SerialPacketError::WritePacketEmptyData);
        } else {
            SerialPacketType::Write(PacketDataLen::try_from(data.len())?)
        };
        let mut buf = [0; 64];
        buf[0..data.len()].clone_from_slice(data);
        let mut pkt = SerialNetworkPacket {
            pt: SerialPacketTypeField::from(ty),
            address,
            checksum: 0,
            data: buf,
        };
        pkt.checksum = pkt.compute_checksum();
        Ok(pkt)
    }

    /// calculate packet checksum from elements
    pub fn compute_checksum(&self) -> u16 {
        let pt: u16 = self.pt.0.into();
        let addr: u16 = self.address.into();
        let mut sum: u16 = b's' as u16 + b'n' as u16 + b'p' as u16 + pt + addr;
        sum += self.data.iter().map(|b| *b as u16).sum::<u16>();
        sum
    }

    /// compare stored checksum with calculated checksum
    pub fn compare_checksum(&self) -> bool {
        self.checksum == self.compute_checksum()
    }
}

/// Implements a parser on a stream of bytes
#[derive(Debug, Format)]
pub struct PacketByteStreamHandler {
    parser: PacketParser,
    packet_buffer: SerialNetworkPacket,
}

impl PacketByteStreamHandler {
    /// Create a new handler
    pub fn new() -> Self {
        PacketByteStreamHandler {
            parser: PacketParser::new(),
            packet_buffer: SerialNetworkPacket::empty(),
        }
    }

    /// Called on each incoming byte
    /// If a complete packet has been received, the checksum is checked.
    /// On a good checksum, the method returns a copy of the packet, on a
    /// bad checksum, returns an error. If no complete packet, returns None
    pub fn feed(&mut self, byte: u8) -> Result<Option<SerialNetworkPacket>, SerialPacketError> {
        self.parser = self
            .parser
            .clone()
            .parse_received_byte(byte, &mut self.packet_buffer);
        if self.parser.have_complete_packet().is_some() {
            // parser found complete packet
            let pkt = self.packet_buffer;
            // reset input packet
            self.packet_buffer = SerialNetworkPacket::empty();
            // switch based on checksum of received packet
            if pkt.compare_checksum() {
                Ok(Some(pkt))
            } else {
                Err(SerialPacketError::Checksum)
            }
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_data_len_range() {
        assert!(PacketDataLen::new(4).is_ok());
        assert!(PacketDataLen::new(64).is_ok());
        assert!(matches!(
            PacketDataLen::new(65),
            Err(crate::SerialPacketError::DataLen(65))
        ));
        assert!(matches!(
            PacketDataLen::new(0),
            Err(crate::SerialPacketError::DataLen(0))
        ));
        assert!(PacketDataLen::try_from(5_usize).is_ok());
        assert!(matches!(
            PacketDataLen::try_from(0_usize),
            Err(crate::SerialPacketError::DataLen(0))
        ));
    }

    #[test]
    fn serial_packet_type() {
        let rd = SerialPacketType::Read;
        assert_eq!(
            SerialPacketType::from(SerialPacketTypeField::from(0)).u8(),
            rd.u8()
        );
        let wr = SerialPacketType::Write(PacketDataLen(4));
        assert_eq!(
            SerialPacketType::from(SerialPacketTypeField::from(0b1000_0000)).u8(),
            wr.u8()
        );
        let rdb = SerialPacketType::BatchRead(PacketDataLen(4));
        assert_eq!(
            SerialPacketType::from(SerialPacketTypeField::from(0b0100_0000)).u8(),
            rdb.u8()
        );
        let wrdb = SerialPacketType::Write(PacketDataLen(64));
        let wrfd = SerialPacketTypeField::from(0b1111_1100);
        assert_eq!(wrfd.datalen(), 64);
        assert_eq!(SerialPacketType::from(wrfd), wrdb);
    }

    #[test]
    fn read_pkt() {
        // a read packet
        let pktdata: [u8; 7] = [b's', b'n', b'p', 0b0000_0000, 0xCD, 0x02, 0x1e];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            if parser.have_complete_packet().is_some() {
                panic!();
            }
            parser = parser.parse_received_byte(*byte, &mut pkt);
        }
        if parser.have_complete_packet().is_none() {
            panic!();
        }
        assert_eq!(pkt.address, 0xCD);
        assert!(!pkt.pt.is_write() && !pkt.pt.is_batch());
        assert_eq!(pkt.pt.datalen(), 0);
        assert_eq!(pkt.checksum, 0x021E);
        assert!(pkt.compare_checksum());
    }

    #[test]
    fn batch_read_pkt() {
        // a batch read test packet
        let pktdata: [u8; 7] = [b's', b'n', b'p', 0b0101_1000, 0x45, 0x01, 0xEE];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            if parser.have_complete_packet().is_some() {
                panic!();
            }
            parser = parser.parse_received_byte(*byte, &mut pkt);
        }
        if parser.have_complete_packet().is_none() {
            panic!();
        }
        assert!(!pkt.pt.is_write() && pkt.pt.is_batch());
        assert_eq!(pkt.pt.datalen(), 28);
        assert_eq!(pkt.address, 0x45);
        assert_eq!(pkt.checksum, 0x01EE);
        assert!(pkt.compare_checksum());
    }

    #[test]
    fn write_data_pkt() {
        // a write data test packet
        let pktdata: [u8; 11] = [
            b's',
            b'n',
            b'p',
            0b1000_0000,
            0x01,
            0xAB,
            0xCD,
            0xEF,
            0x12,
            0x04,
            0x4B,
        ];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            if parser.have_complete_packet().is_some() {
                panic!();
            }
            parser = parser.parse_received_byte(*byte, &mut pkt);
        }
        if parser.have_complete_packet().is_none() {
            panic!();
        }
        assert!(pkt.pt.is_write() && !pkt.pt.is_batch());
        assert_eq!(pkt.pt.datalen(), 4);
        assert_eq!(pkt.address, 0x01);
        assert_eq!(pkt.data[0], 0xAB);
        assert_eq!(pkt.data[1], 0xCD);
        assert_eq!(pkt.data[2], 0xEF);
        assert_eq!(pkt.data[3], 0x12);
        assert_eq!(pkt.checksum, 0x044B);
        assert!(pkt.compare_checksum());
    }

    #[test]
    fn batch_write_data_pkt() {
        // a batch write test packet
        let pktdata: [u8; 15] = [
            b's',
            b'n',
            b'p',
            0b1100_0100,
            0x03,
            0xAB,
            0xCD,
            0xEF,
            0x12,
            0xAB,
            0xCD,
            0xEF,
            0x12,
            0x07,
            0x0A,
        ];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            if parser.have_complete_packet().is_some() {
                panic!();
            }
            parser = parser.parse_received_byte(*byte, &mut pkt);
        }
        if parser.have_complete_packet().is_none() {
            panic!();
        }
        assert_eq!(pkt.pt.0, 0b1100_0100);
        assert_eq!(pkt.address, 0x03);
        assert_eq!(pkt.data[0], 0xAB);
        assert_eq!(pkt.data[1], 0xCD);
        assert_eq!(pkt.data[2], 0xEF);
        assert_eq!(pkt.data[3], 0x12);
        assert_eq!(pkt.data[4], 0xAB);
        assert_eq!(pkt.data[5], 0xCD);
        assert_eq!(pkt.data[6], 0xEF);
        assert_eq!(pkt.data[7], 0x12);
        assert_eq!(pkt.checksum, 0x070A);
        assert_eq!(pkt.checksum, pkt.compute_checksum());
    }

    #[test]
    fn corrupted() {
        // a corrupted data test packet, bad magic
        let pktdata: [u8; 15] = [
            b's', b'n', b'b', 0xc8, 0x03, 0xAB, 0xCD, 0xEF, 0x12, 0xAB, 0xCD, 0xEF, 0x12, 0x07,
            0x0E,
        ];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte, &mut pkt);
            if parser.have_complete_packet().is_some() {
                panic!();
            }
        }
    }

    #[test]
    fn bad_checksum() {
        // a corrupted data test packet, bad checksum
        let pktdata: [u8; 15] = [
            b's', b'n', b'p', 0xc8, 0x03, 0xAB, 0xCD, 0xEF, 0x12, 0xAB, 0xCD, 0xEF, 0x12, 0x08,
            0x0E,
        ];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            if parser.have_complete_packet().is_some() {
                panic!();
            }
            parser = parser.parse_received_byte(*byte, &mut pkt);
        }
        assert!(!pkt.compare_checksum());
    }

    #[test]
    fn midstream() {
        // parse the packet not assuming first bytes are packet magic bytes
        let pktdata: [u8; 11] = [
            0xde,
            0xad,
            0xbe,
            0xef,
            b's',
            b'n',
            b'p',
            0b0000_0000,
            0xCD,
            0x02,
            0x1e,
        ];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            if parser.have_complete_packet().is_some() {
                panic!();
            }
            parser = parser.parse_received_byte(*byte, &mut pkt);
        }
        if parser.have_complete_packet().is_none() {
            panic!();
        }
        assert!(!pkt.pt.is_write() && !pkt.pt.is_batch());
        assert_eq!(pkt.pt.datalen(), 0);
        assert_eq!(pkt.address, 0xcd);
        assert!(pkt.compare_checksum());
    }

    #[test]
    fn two_packets() {
        // parse the packet not assuming first bytes are packet magic bytes
        let pktdata: [u8; 22] = [
            0xde,
            0xad,
            0xbe,
            0xef,
            b's',
            b'n',
            b'p',
            0b0000_0000,
            0xCD,
            0x02,
            0x1e,
            0xde,
            0xad,
            0xbe,
            0xef,
            b's',
            b'n',
            b'p',
            0b0000_0000,
            0xCD,
            0x02,
            0x1e,
        ];
        let mut pkt = SerialNetworkPacket::empty();
        let mut parser = PacketParser::new();
        for byte in pktdata.iter() {
            parser = parser.parse_received_byte(*byte, &mut pkt);
            if parser.have_complete_packet().is_some() {
                assert!(!pkt.pt.is_write() && !pkt.pt.is_batch());
                assert_eq!(pkt.pt.datalen(), 0);
                assert_eq!(pkt.address, 0xcd);
                assert!(pkt.compare_checksum());
            }
        }
    }
}
