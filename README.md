# Serial Network Packets

This crate defines a SerialNetworkPacket that is intended to work with devices that have
an address and value type of configuration. The targeted addresses are expected to be mostly
sequential, so that multiple values can be written with a starting address that is incremented
for each value. This behaviour is similar to that implemented in a lot of hardware peripherals.
There are 4 types of packets, Read/Write/BatchRead/BatchWrite. The sequence of values can
be up to 64 bytes in length. This keeps the packet to a known maximum size so that it is easy
to use on systems with no dynamic memory allocation.

<img
src="https://raw.githubusercontent.com/gpgreen/serial_packet_parser/main/packetparser.png"
width="640" alt="State Machine for packet parsing" />

## Description

This driver is intended to work on embedded platforms. It is `no_std`
compatible, builds on stable Rust, and only uses safe Rust.

## License

`serial_packet_parser` is licensed under either of

- Apache License, Version 2.0 [LICENSE-APACHE](LICENSE-APACHE)
- MIT License [LICENSE-MIT](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[crate-docs]: https://docs.rs/serial_packet_parser
[embedded-hal]: https://crates.io/crates/embedded-hal
