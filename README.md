# DNS Parser

Zero dependency DNS message wire format codec implemented in Rust.

This crate parses and serializes DNS messages. It is a codec library, not a resolver, cache, or DNSSEC validator.

## Features

- Wire format support for common DNS message structures from the RFCs listed below
- No external crate dependencies
- Typed support for the record types listed in this README
- EDNS(0), including the padding option from RFC 7830

## Implemented RFCs (wire formats)

- RFC 1034 / 1035: domain names, messages, and common record types
- RFC 2782: SRV records
- RFC 3596: AAAA records
- RFC 4034: DS, RRSIG, NSEC, and DNSKEY record layouts (structural parse and serialize only)
- RFC 5155: NSEC3 and NSEC3PARAM record layouts (structural parse and serialize only)
- RFC 6844 / 8659: CAA records
- RFC 6891: EDNS(0) OPT records
- RFC 7830: EDNS(0) padding option

SOA fields used by negative caching (RFC 2308) can be parsed and serialized. This crate does not implement negative caching behavior.

## Supported Record Types

- A
- NS
- CNAME
- SOA
- PTR
- MX
- TXT
- AAAA
- SRV
- OPT
- DS
- RRSIG
- NSEC
- DNSKEY
- NSEC3
- NSEC3PARAM
- CAA
- ANY

Unknown types are preserved as raw RDATA.

## Usage

```rust
use dns_parser::{Message, RecordType, ResponseCode};

fn main() {
    let dns_message_bytes = vec![/* ... */];
    let message = Message::parse(&dns_message_bytes).unwrap();

    println!("Transaction ID: {}", message.header.id);

    let mut response = Message::new_response(message.header.id, ResponseCode::NoError);
    let bytes = response.to_bytes();
    let _ = bytes;
    let _ = RecordType::A;
}
```

Build a query and an A response:

```rust
use std::net::Ipv4Addr;
use dns_parser::{Message, RecordType};

let query = Message::new_query(1234, "example.com", RecordType::A).unwrap();
let query_bytes = query.to_bytes();

let response_bytes = Message::create_a_response(
    1234,
    "example.com",
    Ipv4Addr::new(93, 184, 216, 34),
    3600,
).unwrap();
let _ = (query_bytes, response_bytes);
```

Run the included example:

```bash
cargo run --example edns_padding
```

## EDNS Features

### RFC 7830 EDNS(0) Padding

You can pad a message toward a target size:

```rust
use dns_parser::{Message, RecordType};

let mut query = Message::new_query(1234, "example.com", RecordType::A).unwrap();
query.add_padding(128).unwrap();

let bytes = query.to_bytes();
assert_eq!(bytes.len(), 128);
```

You can also inspect EDNS options in a parsed message:

```rust
use dns_parser::{EdnsOption, Message};

let message = Message::parse(&bytes).unwrap();

if let Some((udp_size, ext_rcode, version, flags, options)) = message.get_edns_options() {
    println!("EDNS: UDP Size: {}, Version: {}", udp_size, version);
    let _ = (ext_rcode, flags);

    for (code, data) in options {
        if code == EdnsOption::Padding.to_u16() {
            println!("Message has {} bytes of padding", data.len());
        }
    }
}
```

## Name notes

Owner names may include underscore labels (for SRV style names such as `_sip._tcp.example.com`).
A lone `*` is allowed only as the leftmost label for wildcard names such as `*.example.com`.

## License

MIT
