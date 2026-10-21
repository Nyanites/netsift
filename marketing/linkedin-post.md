I love Wireshark. I've used it for years. But some of the features its users have asked for since the 2000s still aren't there, so I built them.

Meet NetSift: a packet analyzer written in Rust, with live capture, pcap/pcapng support and live decryption.

What it does that Wireshark doesn't:

🧩 Shows which app sent every packet, live, without root for your own apps. Firefox, git and curl each get their own traffic and hosts.
⏱ Turns HTTP/1, /2 and /3 into a browser-devtools-style waterfall you can export as HAR.
⚖️ Diffs two captures (client side vs server side): what never arrived, and how long everything took between the two points.
🌐 One click launches Firefox or Chrome with key logging, and HTTPS, HTTP/2 and HTTP/3 decrypt live as you browse (including QUIC key updates and Encrypted Client Hello).

Speed on a 1M-packet / 1 GB capture (Apple M4 Pro, vs tshark 4.6.8):
• 8–73 ms per search once loaded (tshark re-reads the file: 4.1–5.3 s per search)
• 7.2–7.5 s to load and decrypt HTTPS + HTTP/3 (tshark: 11.0–11.7 s)
To be fair: without decryption, tshark's single pass is a bit faster, and NetSift uses about 3× the memory to keep everything instantly searchable.

Every screenshot comes from a real Firefox session I captured and decrypted (60/60 TLS and QUIC sessions). The decryption is tested against real rustls, h2, quinn and h3 stacks plus the RFC test vectors, not mock data.

What's the one thing you've always wanted Wireshark to do? The most-requested answer gets built next. 👇

#networking #wireshark #rust #cybersecurity #devtools #http3
