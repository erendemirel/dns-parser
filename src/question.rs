use crate::error::{Error, Result};
use crate::name::DnsName;
use crate::types::{Class, RecordType};
use std::collections::HashMap;

/// DNS Question
/// 
/// RFC 1035 Format:
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                     QNAME                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone)]
pub struct Question {

    pub name: DnsName,
    
    pub qtype: RecordType,
    
    pub qclass: Class,
}

impl Question {
    pub fn new(name: DnsName, qtype: RecordType, qclass: Class) -> Self {
        Question { name, qtype, qclass }
    }
    
    pub fn parse(buffer: &[u8], offset: usize) -> Result<(Self, usize)> {
        let (name, name_size) = DnsName::parse(buffer, offset, buffer)?;
        
        let pos = offset + name_size;
        if pos + 4 > buffer.len() {
            return Err(Error::Underrun);
        }
        
        let qtype = RecordType::from_u16(u16::from_be_bytes([buffer[pos], buffer[pos + 1]]));
        let qclass = Class::from_u16(u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]));
        
        let question = Question { name, qtype, qclass };
        Ok((question, name_size + 4)) // 4 bytes for qtype and qclass
    }
    
    pub fn write(&self, buffer: &mut Vec<u8>, name_positions: &mut HashMap<String, usize>) -> usize {
        let start_len = buffer.len();
        
        let _name_size = self.name.write(buffer, name_positions);
        
        buffer.extend_from_slice(&self.qtype.to_u16().to_be_bytes());
        buffer.extend_from_slice(&self.qclass.to_u16().to_be_bytes());
        
        buffer.len() - start_len
    }
} 