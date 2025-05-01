use crate::error::{Error, Result};
use crate::types::{OpCode, ResponseCode};

/// DNS Message Header
/// 
/// Structure as defined in RFC 1035, Section 4.1.1:
/// 
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
/// 
/// Note: AD and CD flags were added in RFC 2065 (DNSSEC)
#[derive(Debug, Clone)]
pub struct Header {
    pub id: u16,
    
    pub is_response: bool,
    
    pub opcode: OpCode,
    
    pub authoritative_answer: bool,
    
    pub truncation: bool,
    
    /// If RD is set, it directs the name server to pursue the query recursively.
    pub recursion_desired: bool,
    
    pub recursion_available: bool,
    
    /// Reserved for future use. Must be zero in all queries and responses.
    pub z: bool,
    
    /// Authentic Data bit for DNSSEC (RFC 2065)
    pub authentic_data: bool,
    
    /// Checking Disabled bit for DNSSEC (RFC 2065)
    pub checking_disabled: bool,
    
    pub response_code: ResponseCode,
    
    pub question_count: u16,
    
    pub answer_count: u16,
    
    pub nameserver_count: u16,
    
    /// Number of resource records in the additional records section.
    pub additional_count: u16,
}

impl Header {
    pub fn new_query(id: u16) -> Self {
        Header {
            id,
            is_response: false,
            opcode: OpCode::Query,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: true,
            recursion_available: false,
            z: false,
            authentic_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            question_count: 0,
            answer_count: 0,
            nameserver_count: 0,
            additional_count: 0,
        }
    }

    pub fn new_response(id: u16, response_code: ResponseCode) -> Self {
        Header {
            id,
            is_response: true,
            opcode: OpCode::Query,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: true,
            z: false,
            authentic_data: false,
            checking_disabled: false,
            response_code,
            question_count: 0,
            answer_count: 0,
            nameserver_count: 0,
            additional_count: 0,
        }
    }

    pub fn parse(buffer: &[u8]) -> Result<(Self, usize)> {
        if buffer.len() < 12 {
            return Err(Error::Underrun);
        }

        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        
        let flags = u16::from_be_bytes([buffer[2], buffer[3]]);
        let is_response = (flags & 0x8000) != 0;
        let opcode = OpCode::from_u8(((flags & 0x7800) >> 11) as u8);
        let authoritative_answer = (flags & 0x0400) != 0;
        let truncation = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let z = (flags & 0x0040) != 0;
        let authentic_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let response_code = ResponseCode::from_u8((flags & 0x000F) as u8);
        
        let question_count = u16::from_be_bytes([buffer[4], buffer[5]]);
        let answer_count = u16::from_be_bytes([buffer[6], buffer[7]]);
        let nameserver_count = u16::from_be_bytes([buffer[8], buffer[9]]);
        let additional_count = u16::from_be_bytes([buffer[10], buffer[11]]);

        let header = Header {
            id,
            is_response,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            z,
            authentic_data,
            checking_disabled,
            response_code,
            question_count,
            answer_count,
            nameserver_count,
            additional_count,
        };

        Ok((header, 12))
    }

    pub fn write(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.id.to_be_bytes());
        
        let mut flags: u16 = 0;
        if self.is_response { flags |= 0x8000; }
        flags |= (self.opcode.to_u8() as u16) << 11;
        if self.authoritative_answer { flags |= 0x0400; }
        if self.truncation { flags |= 0x0200; }
        if self.recursion_desired { flags |= 0x0100; }
        if self.recursion_available { flags |= 0x0080; }
        if self.z { flags |= 0x0040; }
        if self.authentic_data { flags |= 0x0020; }
        if self.checking_disabled { flags |= 0x0010; }
        flags |= self.response_code.to_u8() as u16;
        
        buffer.extend_from_slice(&flags.to_be_bytes());
        
        // Counts (8 bytes total)
        buffer.extend_from_slice(&self.question_count.to_be_bytes());
        buffer.extend_from_slice(&self.answer_count.to_be_bytes());
        buffer.extend_from_slice(&self.nameserver_count.to_be_bytes());
        buffer.extend_from_slice(&self.additional_count.to_be_bytes());
    }
} 