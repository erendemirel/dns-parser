use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::header::Header;
use crate::name::DnsName;
use crate::question::Question;
use crate::resource_record::{RData, ResourceRecord};
use crate::types::{Class, RecordType, ResponseCode, EdnsOption};

/// DNS Message
///
/// A complete DNS message, as specified in RFC 1035.
/// A message consists of a header, question section, and three resource record sections.
///
/// Structure as defined in RFC 1035, Section 4.1:
///
/// ```text
/// +---------------------+
/// |        Header       |
/// +---------------------+
/// |       Question      | the question for the name server
/// +---------------------+
/// |        Answer       | RRs answering the question
/// +---------------------+
/// |      Authority      | RRs pointing toward an authority
/// +---------------------+
/// |      Additional     | RRs holding additional information
/// +---------------------+
/// ```
#[derive(Debug, Clone)]
pub struct Message {

    pub header: Header,
    
    pub questions: Vec<Question>,
    
    pub answers: Vec<ResourceRecord>,
    
    pub authorities: Vec<ResourceRecord>,
    
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    pub fn new() -> Self {
        Message {
            header: Header::new_query(0),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
    
    pub fn new_query(id: u16, name: &str, record_type: RecordType) -> Result<Self> {
        let dns_name = DnsName::new(name)?;
        let question = Question::new(dns_name, record_type, Class::IN);
        
        let mut message = Message::new();
        message.header = Header::new_query(id);
        message.header.question_count = 1;
        message.questions.push(question);
        
        Ok(message)
    }
    
    pub fn new_response(id: u16, response_code: ResponseCode) -> Self {
        let mut message = Message::new();
        message.header = Header::new_response(id, response_code);
        message
    }
    
    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.question_count = self.questions.len() as u16;
    }
    
    pub fn add_answer(&mut self, answer: ResourceRecord) {
        self.answers.push(answer);
        self.header.answer_count = self.answers.len() as u16;
    }
    
    pub fn add_authority(&mut self, authority: ResourceRecord) {
        self.authorities.push(authority);
        self.header.nameserver_count = self.authorities.len() as u16;
    }
    
    pub fn add_additional(&mut self, additional: ResourceRecord) {
        self.additionals.push(additional);
        self.header.additional_count = self.additionals.len() as u16;
    }
    
    pub fn add_a_answer(&mut self, name: &str, ip: Ipv4Addr, ttl: u32) -> Result<()> {
        let dns_name = DnsName::new(name)?;
        let record = ResourceRecord::new(
            dns_name,
            RecordType::A,
            Class::IN,
            ttl,
            RData::A(ip),
        );
        self.add_answer(record);
        Ok(())
    }
    
    pub fn add_aaaa_answer(&mut self, name: &str, ip: Ipv6Addr, ttl: u32) -> Result<()> {
        let dns_name = DnsName::new(name)?;
        let record = ResourceRecord::new(
            dns_name,
            RecordType::AAAA,
            Class::IN,
            ttl,
            RData::AAAA(ip),
        );
        self.add_answer(record);
        Ok(())
    }
    
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < 12 {
            return Err(Error::Underrun);
        }
        
        let (header, _) = Header::parse(buffer)?;
        
        let mut pos = 12; // Header is 12 bytes
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additionals = Vec::new();
        
        for _ in 0..header.question_count {
            if pos >= buffer.len() {
                return Err(Error::Underrun);
            }
            
            let (question, question_size) = Question::parse(buffer, pos)?;
            questions.push(question);
            pos += question_size;
        }
        
        for _ in 0..header.answer_count {
            if pos >= buffer.len() {
                return Err(Error::Underrun);
            }
            
            let (answer, answer_size) = ResourceRecord::parse(buffer, pos)?;
            answers.push(answer);
            pos += answer_size;
        }
        
        for _ in 0..header.nameserver_count {
            if pos >= buffer.len() {
                return Err(Error::Underrun);
            }
            
            let (authority, authority_size) = ResourceRecord::parse(buffer, pos)?;
            authorities.push(authority);
            pos += authority_size;
        }
        
        for _ in 0..header.additional_count {
            if pos >= buffer.len() {
                return Err(Error::Underrun);
            }
            
            let (additional, additional_size) = ResourceRecord::parse(buffer, pos)?;
            additionals.push(additional);
            pos += additional_size;
        }
        
        let message = Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        };
        
        Ok(message)
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut name_positions = HashMap::new();
        
        self.header.write(&mut buffer);
        
        for question in &self.questions {
            question.write(&mut buffer, &mut name_positions);
        }
        
        for answer in &self.answers {
            answer.write(&mut buffer, &mut name_positions);
        }
        
        for authority in &self.authorities {
            authority.write(&mut buffer, &mut name_positions);
        }
        
        for additional in &self.additionals {
            additional.write(&mut buffer, &mut name_positions);
        }
        
        buffer
    }
    
    pub fn create_query(id: u16, hostname: &str, record_type: RecordType) -> Result<Vec<u8>> {
        let message = Message::new_query(id, hostname, record_type)?;
        Ok(message.to_bytes())
    }
    
    pub fn create_a_response(id: u16, hostname: &str, ip: Ipv4Addr, ttl: u32) -> Result<Vec<u8>> {
        let mut message = Message::new_response(id, ResponseCode::NoError);
        
        let dns_name = DnsName::new(hostname)?;
        let question = Question::new(dns_name.clone(), RecordType::A, Class::IN);
        message.add_question(question);
        
        let record = ResourceRecord::new(
            dns_name,
            RecordType::A,
            Class::IN,
            ttl,
            RData::A(ip),
        );
        message.add_answer(record);
        
        Ok(message.to_bytes())
    }
    
    /// Add EDNS(0) options to the message
    /// 
    /// This method adds or updates the OPT record in the additional section of the message.
    /// 
    /// # Arguments
    /// 
    /// * `udp_payload_size` - The maximum UDP payload size
    /// * `extended_rcode` - The extended RCODE
    /// * `version` - The EDNS version
    /// * `flags` - EDNS flags
    /// * `options` - EDNS options to add
    pub fn add_edns_options(
        &mut self, 
        udp_payload_size: u16, 
        extended_rcode: u8, 
        version: u8, 
        flags: u16,
        options: Vec<(u16, Vec<u8>)>
    ) -> &mut Self {
        let mut opt_index = None;
        for (i, rr) in self.additionals.iter().enumerate() {
            if let RecordType::OPT = rr.record_type {
                opt_index = Some(i);
                break;
            }
        }
        
        let opt_data = RData::OPT {
            udp_payload_size,
            extended_rcode,
            version,
            flags,
            options,
        };
        
        let opt_record = ResourceRecord::new(
            DnsName::new(".").unwrap(),
            RecordType::OPT,
            Class::from_u16(udp_payload_size), // Class field is UDP payload size
            ((extended_rcode as u32) << 24) | ((version as u32) << 16) | (flags as u32), // TTL field has special meaning
            opt_data,
        );
        
        if let Some(index) = opt_index {
            self.additionals[index] = opt_record;
        } else {
            self.additionals.push(opt_record);
        }
        
        self.header.additional_count = self.additionals.len() as u16;
        
        self
    }
    
    /// Add padding to the message (RFC 7830)
    /// 
    /// This method adds the EDNS(0) padding option to make the DNS message a specific size.
    /// 
    /// # Arguments
    /// 
    /// * `target_size` - The desired size for the message
    pub fn add_padding(&mut self, target_size: usize) -> Result<&mut Self> {

        let current_size = self.to_bytes().len();
        
        if current_size >= target_size {
            return Ok(self);
        }
        
        // Find and remove any existing OPT record
        let mut existing_opt = None;
        let mut opt_index = None;
        
        for (i, rr) in self.additionals.iter().enumerate() {
            if let RecordType::OPT = rr.record_type {
                opt_index = Some(i);
                if let RData::OPT { udp_payload_size, extended_rcode, version, flags, options } = &rr.data {
                    existing_opt = Some((*udp_payload_size, *extended_rcode, *version, *flags, 
                        options.iter().filter(|&(code, _)| *code != EdnsOption::Padding.to_u16())
                               .map(|(code, data)| (*code, data.clone()))
                               .collect::<Vec<_>>()));
                }
                break;
            }
        }
        
        // Remove existing OPT record if found
        if let Some(i) = opt_index {
            self.additionals.remove(i);
        }
        
        let size_without_opt = self.to_bytes().len();
        
        // OPT record overhead is approximately 11 bytes for an empty record
        // Padding option adds 4 bytes overhead (2 for code, 2 for length)
        let opt_overhead = 15; // 11 bytes for OPT record + 4 for option headers
        
        let padding_size = match target_size.checked_sub(size_without_opt + opt_overhead) {
            Some(size) => size,
            None => 0,
        };
        
        let mut options = Vec::new();
        
        if let Some((_, _, _, _, existing_options)) = &existing_opt {
            options.extend(existing_options.clone());
        }
        
        options.push((EdnsOption::Padding.to_u16(), vec![0; padding_size as usize]));
        
        let udp_size = existing_opt.as_ref().map(|(size, _, _, _, _)| *size).unwrap_or(4096);
        let ext_rcode = existing_opt.as_ref().map(|(_, rcode, _, _, _)| *rcode).unwrap_or(0);
        let version = existing_opt.as_ref().map(|(_, _, ver, _, _)| *ver).unwrap_or(0);
        let flags = existing_opt.as_ref().map(|(_, _, _, f, _)| *f).unwrap_or(0);
        
        let ttl = (ext_rcode as u32) << 24 | (version as u32) << 16 | flags as u32;
        
        let opt_record = ResourceRecord::new(
            DnsName::new(".").unwrap(),
            RecordType::OPT,
            Class::from_u16(udp_size),
            ttl,
            RData::OPT {
                udp_payload_size: udp_size,
                extended_rcode: ext_rcode,
                version,
                flags,
                options,
            },
        );
        
        // Add the OPT record
        self.additionals.push(opt_record);
        
        let final_size = self.to_bytes().len();
        
        if final_size < target_size {
            let additional_padding = target_size - final_size;
            self.additionals.pop();           
            let mut updated_options = Vec::new();
            
            if let Some((_, _, _, _, existing_options)) = &existing_opt {
                updated_options.extend(existing_options.clone());
            }
            
            updated_options.push((
                EdnsOption::Padding.to_u16(), 
                vec![0; (padding_size + additional_padding) as usize]
            ));
            
            let updated_opt_record = ResourceRecord::new(
                DnsName::new(".").unwrap(),
                RecordType::OPT,
                Class::from_u16(udp_size),
                ttl,
                RData::OPT {
                    udp_payload_size: udp_size,
                    extended_rcode: ext_rcode,
                    version,
                    flags,
                    options: updated_options,
                },
            );
            
            self.additionals.push(updated_opt_record);

            self.header.additional_count = self.additionals.len() as u16;
        }
        
        Ok(self)
    }
    
    /// Get EDNS options from the message
    /// 
    /// Returns the EDNS options if an OPT record exists, or None otherwise.
    pub fn get_edns_options(&self) -> Option<(u16, u8, u8, u16, Vec<(u16, Vec<u8>)>)> {
        for rr in &self.additionals {
            if let RecordType::OPT = rr.record_type {
                if let RData::OPT { 
                    udp_payload_size, 
                    extended_rcode, 
                    version, 
                    flags, 
                    options 
                } = &rr.data {
                    return Some((
                        *udp_payload_size,
                        *extended_rcode,
                        *version,
                        *flags,
                        options.clone(),
                    ));
                }
            }
        }
        None
    }
} 