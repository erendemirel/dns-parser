pub mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod question;
pub mod resource_record;
pub mod types;

pub use message::Message;
pub use error::Error;
pub use error::Result;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::collections::HashMap;
    
    use crate::name::DnsName;
    use crate::message::Message;
    use crate::types::{RecordType, Class, EdnsOption};
    use crate::header::Header;
    use crate::question::Question;
    use crate::resource_record::{ResourceRecord, RData};
    
    #[test]
    fn test_dns_name() {
        let name = DnsName::new("www.example.com").unwrap();
        assert_eq!(name.to_string(), "www.example.com");
        
        let root = DnsName::new(".").unwrap();
        assert_eq!(root.to_string(), ".");
        
        let mut buffer = Vec::new();
        let mut positions = HashMap::new();
        
        name.write(&mut buffer, &mut positions);
        assert!(buffer.len() > 0);
        
        let (parsed_name, _) = DnsName::parse(&buffer, 0, &buffer).unwrap();
        assert_eq!(parsed_name.to_string(), "www.example.com");
    }
    
    #[test]
    fn test_dns_header() {
        let header = Header::new_query(1234);
        assert_eq!(header.id, 1234);
        assert_eq!(header.is_response, false);
        
        let mut buffer = Vec::new();
        header.write(&mut buffer);
        assert_eq!(buffer.len(), 12); // DNS header is 12 bytes
        
        let (parsed_header, _) = Header::parse(&buffer).unwrap();
        assert_eq!(parsed_header.id, 1234);
        assert_eq!(parsed_header.is_response, false);
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
    fn test_dns_resource_record() {
        let name = DnsName::new("example.com").unwrap();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        
        let record = ResourceRecord::new(
            name,
            RecordType::A,
            Class::IN,
            3600,
            RData::A(ip)
        );
        
        let mut buffer = Vec::new();
        let mut positions = HashMap::new();
        record.write(&mut buffer, &mut positions);
        
        let (parsed_record, _) = ResourceRecord::parse(&buffer, 0).unwrap();
        assert_eq!(parsed_record.name.to_string(), "example.com");
        assert!(matches!(parsed_record.record_type, RecordType::A));
        assert!(matches!(parsed_record.class, Class::IN));
        assert_eq!(parsed_record.ttl, 3600);
        
        if let RData::A(parsed_ip) = parsed_record.data {
            assert_eq!(parsed_ip, ip);
        } else {
            panic!("Expected A record data");
        }
    }
    
    #[test]
    fn test_dns_message_query() {
        let query = Message::new_query(1234, "example.com", RecordType::A).unwrap();
        assert_eq!(query.header.id, 1234);
        assert_eq!(query.header.is_response, false);
        assert_eq!(query.questions.len(), 1);
        assert_eq!(query.questions[0].name.to_string(), "example.com");
        
        let query_bytes = query.to_bytes();
        let parsed_query = Message::parse(&query_bytes).unwrap();
        
        assert_eq!(parsed_query.header.id, 1234);
        assert_eq!(parsed_query.header.is_response, false);
        assert_eq!(parsed_query.questions.len(), 1);
        assert_eq!(parsed_query.questions[0].name.to_string(), "example.com");
    }
    
    #[test]
    fn test_dns_message_response() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let response_bytes = Message::create_a_response(1234, "example.com", ip, 3600).unwrap();
        let response = Message::parse(&response_bytes).unwrap();
        
        assert_eq!(response.header.id, 1234);
        assert_eq!(response.header.is_response, true);
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
    fn test_edns_padding() {
        let mut message = Message::new_query(1234, "example.com", RecordType::A).unwrap();
        
        // Add EDNS options with padding directly
        let padding_data = vec![0u8; 20]; // 20 bytes of padding
        let options = vec![(EdnsOption::Padding.to_u16(), padding_data)];
        
        message.add_edns_options(
            4096,  // UDP payload size
            0,     // Extended RCODE
            0,     // Version
            0,     // Flags
            options
        );
        
        // Verify that we have 1 addtional record
        assert_eq!(message.additionals.len(), 1, "Should have 1 additional record");
        
        let bytes = message.to_bytes();
        println!("Serialized message size: {} bytes", bytes.len());
        
        let parsed = Message::parse(&bytes).unwrap();
        
        // Should have the additional section
        assert_eq!(parsed.additionals.len(), 1, "Parsed message should have 1 additional record");
        
        let mut found_padding = false;
        
        if let Some((udp_size, ext_rcode, version, flags, options)) = parsed.get_edns_options() {
            println!("Found EDNS options: size={}, rcode={}, version={}, flags={}, options={}",
                udp_size, ext_rcode, version, flags, options.len());
            
            for (code, data) in options {
                if code == EdnsOption::Padding.to_u16() {
                    found_padding = true;
                    assert_eq!(data.len(), 20, "Padding should be 20 bytes");
                    println!("Found padding option with {} bytes", data.len());
                }
            }
        }
        
        assert!(found_padding, "Padding option not found in EDNS OPT record");
    }
} 