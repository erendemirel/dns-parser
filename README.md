# DNS Parser

A zero-dependency RFC-compliant DNS parser implemented in Rust.

## Features

- Compliance with DNS-related RFCs
- Zero external dependencies
- Support for all standard DNS record types

## Implemented RFCs

- RFC 1034/1035 - Domain Names - Concepts and Facilities / Domain Names - Implementation and Specification
- RFC 2308 - Negative Caching of DNS Queries
- RFC 2782 - A DNS RR for specifying the location of services (SRV RR)
- RFC 3596 - IPv6 support
- RFC 4034 - Resource Records for the DNS Security Extensions
- RFC 5155 - DNSSEC Hashed Authenticated Denial of Existence (NSEC3)
- RFC 6844/8659 - DNS Certification Authority Authorization (CAA) Resource Record
- RFC 6891 - Extension Mechanisms for DNS (EDNS(0))
- RFC 7830 - The EDNS(0) Padding Option

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

## EDNS Features

### RFC 7830 - EDNS(0) Padding

The parser includes support for EDNS(0) padding as described in RFC 7830. This feature allows DNS messages to be padded to a specific size to help prevent traffic analysis. 

Example usage:

```rust
use dns_parser::message::Message;
use dns_parser::types::RecordType;

// Create a DNS query
let mut query = Message::new_query(1234, "example.com", RecordType::A).unwrap();

// Add padding to a specific size (e.g., 128 bytes)
query.add_padding(128).unwrap();

// The message will now be padded to approximately 128 bytes when serialized
let bytes = query.to_bytes();
```

You can also check for EDNS options in a parsed message:

```rust
use dns_parser::types::EdnsOption;

// Parse a DNS message
let message = Message::parse(&bytes).unwrap();

// Check for EDNS options
if let Some((udp_size, ext_rcode, version, flags, options)) = message.get_edns_options() {
    println!("EDNS: UDP Size: {}, Version: {}", udp_size, version);
    
    // Look for padding option
    for (code, data) in options {
        if code == EdnsOption::Padding.to_u16() {
            println!("Message has {} bytes of padding", data.len());
        }
    }
}
```

## Usage

```rust
use dns_parser::message::Message;

fn main() {
    // Parse a DNS message from bytes
    let dns_message_bytes = vec![/* ... */];
    let message = Message::parse(&dns_message_bytes).unwrap();
    
    // Access message fields
    println!("Transaction ID: {}", message.header.id);
    
    // Create and serialize a DNS message
    let response = Message::new_response(/* ... */);
    let bytes = response.to_bytes();
}
```

## License

MIT 