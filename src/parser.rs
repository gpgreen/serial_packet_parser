use crate::{SerialNetworkPacket, SerialPacketTypeField};
use defmt::{debug, Format};

/// State values of the packet header
#[derive(Clone, Debug, PartialEq, Format)]
pub enum PacketHeaderBytes {
    Waiting,
    S,
    N,
    P,
}

// Define the machine states
machine!(
    #[derive(Clone, Debug, PartialEq, Format)]
    enum PacketParser {
        Wait { got: PacketHeaderBytes },
        PacketType,
        Address { ty: SerialPacketTypeField },
        HaveHeader { ty: SerialPacketTypeField, addr: u8 },
        Data { len: u8, offset: u8 },
        Checksum { first: bool, sum: u16 },
        ChecksumComplete { sum: u16 },
        HavePacket,
    }
);

/// The state transition types
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
                 (ChecksumComplete, Advance) => HavePacket,
                 (HavePacket, Advance) => Wait
             ]
);

// additional methods to add to the parser for retrieving data
methods!(PacketParser,
         [
             HaveHeader => get ty: SerialPacketTypeField,
             HaveHeader => get addr: u8,
             HaveHeader => fn can_collect_header(&self) -> bool,
             Data => get len: u8,
             Data => get offset: u8,
             Data => fn can_collect_data(&self) -> bool,
             ChecksumComplete => get sum: u16,
             ChecksumComplete => fn can_collect_checksum(&self) -> bool,
             HavePacket => fn have_complete_packet(&self) -> bool
         ]
);

/// wait state looking for packet header of 'snp'
impl Wait {
    pub fn on_advance(self, input: Advance) -> PacketParser {
        let got = match (self.got, input.ch) {
            (PacketHeaderBytes::Waiting, b's') => PacketHeaderBytes::S,
            (PacketHeaderBytes::S, b'n') => PacketHeaderBytes::N,
            (PacketHeaderBytes::N, b'p') => PacketHeaderBytes::P,
            (_, _) => PacketHeaderBytes::Waiting,
        };
        if got != PacketHeaderBytes::P {
            PacketParser::wait(got)
        } else {
            PacketParser::packet_type()
        }
    }
}

/// After the header, we receive the packet type byte
impl PacketType {
    pub fn on_advance(self, input: Advance) -> Address {
        Address {
            ty: SerialPacketTypeField::from(input.ch),
        }
    }
}

/// After the packet type byte, we receive the address
impl Address {
    pub fn on_advance(self, input: Advance) -> HaveHeader {
        HaveHeader {
            ty: self.ty,
            addr: input.ch,
        }
    }
}

// once we have the header, type, and address, go get data or checksum
impl HaveHeader {
    pub fn on_advance(self, _: Advance) -> PacketParser {
        if !self.ty.is_write() {
            PacketParser::checksum(true, 0)
        } else {
            PacketParser::data(self.ty.datalen(), 0)
        }
    }

    pub fn can_collect_header(&self) -> bool {
        true
    }
}

/// get the packet data (if any)
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

/// receive the transmitted checksum bytes
impl Checksum {
    pub fn on_advance(self, input: Advance) -> PacketParser {
        if self.first {
            let s: u16 = input.ch.into();
            PacketParser::checksum(false, s << 8)
        } else {
            let s: u16 = input.ch.into();
            PacketParser::checksum_complete(s | self.sum)
        }
    }
}

/// allow outside code to collect checksum
impl ChecksumComplete {
    pub fn on_advance(self, _: Advance) -> HavePacket {
        HavePacket {}
    }

    pub fn can_collect_checksum(&self) -> bool {
        true
    }
}

/// end of state machine
impl HavePacket {
    pub fn on_advance(self, _: Advance) -> Wait {
        Wait {
            got: PacketHeaderBytes::Waiting,
        }
    }

    pub fn have_complete_packet(&self) -> bool {
        true
    }
}

impl PacketParser {
    pub fn new() -> PacketParser {
        PacketParser::Wait(Wait {
            got: PacketHeaderBytes::Waiting,
        })
    }

    pub fn parse_received_byte(self, byte: u8, pkt: &mut SerialNetworkPacket) -> PacketParser {
        debug!("Parser before advance {:?} byte:0x{:x}", self, byte);
        if self.can_collect_data().is_some() {
            let i: usize = (*self.offset().expect("packet offset is None")).into();
            pkt.data[i] = byte;
        }
        let mut p = self.on_advance(Advance { ch: byte });
        debug!("Parser after advance {:?} byte:0x{:x}", p, byte);
        // collect checksum
        if p.can_collect_checksum().is_some() {
            pkt.checksum = *p.sum().expect("packet checksum is None");
            p = p.on_advance(Advance { ch: byte });
        }
        if p.can_collect_header().is_some() {
            pkt.pt = *p.ty().expect("packet type is None");
            pkt.address = *p.addr().expect("packet address is None");
            // advance to either checksum or data
            p = p.on_advance(Advance { ch: byte });
        }
        p
    }
}
