# Notices

NetSift is licensed under the [PolyForm Small Business License 1.0.0](LICENSE.md).

## Third-party software

NetSift is built with open-source components, each under the MIT and/or Apache-2.0
license, including
[egui and eframe](https://github.com/emilk/egui),
[rfd](https://github.com/PolyMeilex/rfd),
[pcap](https://github.com/rust-pcap/pcap),
[crossbeam](https://github.com/crossbeam-rs/crossbeam),
[png](https://github.com/image-rs/image-png) and the
[RustCrypto](https://github.com/RustCrypto) AEADs, block ciphers and hashes
(AES-GCM, ChaCha20-Poly1305, HMAC, SHA-2).
The full list is in `Cargo.lock`.

Live capture uses the system's [libpcap](https://www.tcpdump.org/) (BSD license).
The HPACK Huffman table and static tables are data from
[RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) and
[RFC 9204](https://www.rfc-editor.org/rfc/rfc9204).

Wireshark is a registered trademark of the Wireshark Foundation. NetSift is not affiliated
with the Wireshark Foundation, Apple or Microsoft.
