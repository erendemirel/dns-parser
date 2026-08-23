pub mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod question;
pub mod resource_record;
pub mod types;

pub use error::Error;
pub use error::Result;
pub use header::Header;
pub use message::Message;
pub use name::DnsName;
pub use question::Question;
pub use resource_record::{RData, ResourceRecord};
pub use types::{Class, EdnsOption, OpCode, RecordType, ResponseCode};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::header::Header;
    use crate::message::Message;
    use crate::name::DnsName;
    use crate::question::Question;
    use crate::resource_record::{RData, ResourceRecord};
    use crate::types::{Class, EdnsOption, RecordType, ResponseCode};

    fn roundtrip_rr(record: ResourceRecord) -> ResourceRecord {
        let mut buffer = Vec::new();
        let mut positions = HashMap::new();
        record.write(&mut buffer, &mut positions);
        let (parsed, size) = ResourceRecord::parse(&buffer, 0).unwrap();
        assert_eq!(size, buffer.len());
        parsed
    }

    #[test]
    fn test_dns_name() {
        let name = DnsName::new("www.example.com").unwrap();
        assert_eq!(name.to_string(), "www.example.com");

        let root = DnsName::new(".").unwrap();
        assert_eq!(root.to_string(), ".");

        let mut buffer = Vec::new();
        let mut positions = HashMap::new();

        name.write(&mut buffer, &mut positions);
        assert!(!buffer.is_empty());

        let (parsed_name, _) = DnsName::parse(&buffer, 0, &buffer).unwrap();
        assert_eq!(parsed_name.to_string(), "www.example.com");
    }

    #[test]
    fn test_dns_name_srv_and_wildcard() {
        let srv = DnsName::new("_sip._tcp.example.com").unwrap();
        assert_eq!(srv.to_string(), "_sip._tcp.example.com");

        let wildcard = DnsName::new("*.example.com").unwrap();
        assert_eq!(wildcard.to_string(), "*.example.com");

        assert!(DnsName::new("www.*.example.com").is_err());
    }

    #[test]
    fn test_dns_header() {
        let header = Header::new_query(1234);
        assert_eq!(header.id, 1234);
        assert!(!header.is_response);

        let mut buffer = Vec::new();
        header.write(&mut buffer);
        assert_eq!(buffer.len(), 12);

        let (parsed_header, _) = Header::parse(&buffer).unwrap();
        assert_eq!(parsed_header.id, 1234);
        assert!(!parsed_header.is_response);
    }

    #[test]
    fn test_dns_question() {
        let name = DnsName::new("example.com").unwrap();
        let question = Question::new(name, RecordType::A, Class::IN);

        let mut buffer = Vec::new();
        let mut positions = HashMap::new();
        question.write(&mut buffer, &mut positions);

        let (parsed_question, _) = Question::parse(&buffer, 0).unwrap();
        assert_eq!(parsed_question.name.to_string(), "example.com");
        assert!(matches!(parsed_question.qtype, RecordType::A));
        assert!(matches!(parsed_question.qclass, Class::IN));
    }

    #[test]
    fn test_dns_resource_record_a() {
        let name = DnsName::new("example.com").unwrap();
        let ip = Ipv4Addr::new(93, 184, 216, 34);

        let record = ResourceRecord::new(name, RecordType::A, Class::IN, 3600, RData::A(ip));
        let parsed = roundtrip_rr(record);

        assert_eq!(parsed.name.to_string(), "example.com");
        assert!(matches!(parsed.record_type, RecordType::A));
        assert!(matches!(parsed.class, Class::IN));
        assert_eq!(parsed.ttl, 3600);

        if let RData::A(parsed_ip) = parsed.data {
            assert_eq!(parsed_ip, ip);
        } else {
            panic!("Expected A record data");
        }
    }

    #[test]
    fn test_record_roundtrips() {
        let name = DnsName::new("example.com").unwrap();
        let other = DnsName::new("ns1.example.com").unwrap();

        let cases = vec![
            ResourceRecord::new(
                name.clone(),
                RecordType::AAAA,
                Class::IN,
                60,
                RData::AAAA(Ipv6Addr::LOCALHOST),
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::NS,
                Class::IN,
                60,
                RData::NS(other.clone()),
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::CNAME,
                Class::IN,
                60,
                RData::CNAME(other.clone()),
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::PTR,
                Class::IN,
                60,
                RData::PTR(other.clone()),
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::MX,
                Class::IN,
                60,
                RData::MX {
                    preference: 10,
                    exchange: other.clone(),
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::TXT,
                Class::IN,
                60,
                RData::TXT(vec!["hello".into(), "world".into()]),
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::SOA,
                Class::IN,
                60,
                RData::SOA {
                    mname: other.clone(),
                    rname: DnsName::new("hostmaster.example.com").unwrap(),
                    serial: 1,
                    refresh: 2,
                    retry: 3,
                    expire: 4,
                    minimum: 5,
                },
            ),
            ResourceRecord::new(
                DnsName::new("_sip._tcp.example.com").unwrap(),
                RecordType::SRV,
                Class::IN,
                60,
                RData::SRV {
                    priority: 1,
                    weight: 2,
                    port: 5060,
                    target: other.clone(),
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::DS,
                Class::IN,
                60,
                RData::DS {
                    key_tag: 12345,
                    algorithm: 8,
                    digest_type: 2,
                    digest: vec![1, 2, 3, 4],
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::DNSKEY,
                Class::IN,
                60,
                RData::DNSKEY {
                    flags: 256,
                    protocol: 3,
                    algorithm: 8,
                    public_key: vec![9, 8, 7],
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::RRSIG,
                Class::IN,
                60,
                RData::RRSIG {
                    type_covered: 1,
                    algorithm: 8,
                    labels: 2,
                    original_ttl: 60,
                    signature_expiration: 100,
                    signature_inception: 50,
                    key_tag: 12345,
                    signer_name: other.clone(),
                    signature: vec![1, 2, 3],
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::NSEC,
                Class::IN,
                60,
                RData::NSEC {
                    next_domain_name: other.clone(),
                    type_bit_maps: vec![0, 1, 0x40],
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::NSEC3,
                Class::IN,
                60,
                RData::NSEC3 {
                    hash_algorithm: 1,
                    flags: 0,
                    iterations: 10,
                    salt: vec![1, 2],
                    next_hashed_owner_name: vec![9, 9, 9],
                    type_bit_maps: vec![0, 1, 0x40],
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::NSEC3PARAM,
                Class::IN,
                60,
                RData::NSEC3PARAM {
                    hash_algorithm: 1,
                    flags: 0,
                    iterations: 10,
                    salt: vec![1, 2],
                },
            ),
            ResourceRecord::new(
                name.clone(),
                RecordType::CAA,
                Class::IN,
                60,
                RData::CAA {
                    flags: 0,
                    tag: "issue".into(),
                    value: b"letsencrypt.org".to_vec(),
                },
            ),
        ];

        for record in cases {
            let parsed = roundtrip_rr(record.clone());
            assert_eq!(
                format!("{:?}", parsed.data),
                format!("{:?}", record.data),
                "round trip failed for {:?}",
                record.record_type
            );
        }
    }

    #[test]
    fn test_dns_message_query() {
        let query = Message::new_query(1234, "example.com", RecordType::A).unwrap();
        assert_eq!(query.header.id, 1234);
        assert!(!query.header.is_response);
        assert_eq!(query.questions.len(), 1);
        assert_eq!(query.questions[0].name.to_string(), "example.com");

        let query_bytes = query.to_bytes();
        let parsed_query = Message::parse(&query_bytes).unwrap();

        assert_eq!(parsed_query.header.id, 1234);
        assert!(!parsed_query.header.is_response);
        assert_eq!(parsed_query.questions.len(), 1);
        assert_eq!(parsed_query.questions[0].name.to_string(), "example.com");
    }

    #[test]
    fn test_dns_message_response() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let response_bytes = Message::create_a_response(1234, "example.com", ip, 3600).unwrap();
        let response = Message::parse(&response_bytes).unwrap();

        assert_eq!(response.header.id, 1234);
        assert!(response.header.is_response);
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.answers.len(), 1);

        assert_eq!(response.questions[0].name.to_string(), "example.com");
        assert!(matches!(response.questions[0].qtype, RecordType::A));

        assert_eq!(response.answers[0].name.to_string(), "example.com");
        assert!(matches!(response.answers[0].record_type, RecordType::A));
        assert_eq!(response.answers[0].ttl, 3600);

        if let RData::A(response_ip) = &response.answers[0].data {
            assert_eq!(*response_ip, ip);
        } else {
            panic!("Expected A record data");
        }
    }

    #[test]
    fn test_edns_options_roundtrip() {
        let mut message = Message::new_query(1234, "example.com", RecordType::A).unwrap();

        let padding_data = vec![0u8; 20];
        let options = vec![(EdnsOption::Padding.to_u16(), padding_data)];

        message.add_edns_options(4096, 0, 0, 0, options);

        assert_eq!(message.additionals.len(), 1);
        assert_eq!(message.header.additional_count, 1);

        let bytes = message.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();

        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.header.additional_count, 1);

        let mut found_padding = false;
        if let Some((udp_size, ext_rcode, version, flags, options)) = parsed.get_edns_options() {
            assert_eq!(udp_size, 4096);
            assert_eq!(ext_rcode, 0);
            assert_eq!(version, 0);
            assert_eq!(flags, 0);

            for (code, data) in options {
                if code == EdnsOption::Padding.to_u16() {
                    found_padding = true;
                    assert_eq!(data.len(), 20);
                }
            }
        }

        assert!(found_padding);
    }

    #[test]
    fn test_add_padding_roundtrip() {
        let mut message = Message::new_query(1234, "example.com", RecordType::A).unwrap();
        message.add_padding(128).unwrap();

        assert_eq!(message.additionals.len(), 1);
        assert_eq!(message.header.additional_count, 1);

        let bytes = message.to_bytes();
        assert_eq!(bytes.len(), 128);
        assert_eq!(&bytes[10..12], &[0, 1]);

        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.header.additional_count, 1);

        let edns = parsed.get_edns_options().expect("EDNS options missing");
        let padding = edns
            .4
            .iter()
            .find(|(code, _)| *code == EdnsOption::Padding.to_u16())
            .expect("padding option missing");
        assert!(!padding.1.is_empty());
    }

    #[test]
    fn test_add_padding_preserves_existing_options() {
        let mut message = Message::new_query(1234, "example.com", RecordType::A).unwrap();
        message.add_edns_options(
            1232,
            0,
            0,
            0,
            vec![(EdnsOption::NSID.to_u16(), b"ns1".to_vec())],
        );
        message.add_padding(160).unwrap();

        let bytes = message.to_bytes();
        assert_eq!(bytes.len(), 160);

        let parsed = Message::parse(&bytes).unwrap();
        let (_, _, _, _, options) = parsed.get_edns_options().unwrap();

        assert!(options
            .iter()
            .any(|(code, data)| *code == EdnsOption::NSID.to_u16() && data == b"ns1"));
        assert!(options
            .iter()
            .any(|(code, _)| *code == EdnsOption::Padding.to_u16()));
        assert_eq!(parsed.header.additional_count, 1);
        assert_eq!(parsed.additionals.len(), 1);
    }

    #[test]
    fn test_new_response_helper() {
        let response = Message::new_response(99, ResponseCode::NameError);
        assert!(response.header.is_response);
        assert_eq!(response.header.id, 99);
        assert!(matches!(
            response.header.response_code,
            ResponseCode::NameError
        ));
    }
}
