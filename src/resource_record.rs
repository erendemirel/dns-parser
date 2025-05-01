use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::convert::TryInto;

use crate::error::{Error, Result};
use crate::name::DnsName;
use crate::types::{Class, RecordType};

/// DNS Resource Record
/// 
/// RFC 1035 Format:
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone)]
pub struct ResourceRecord {

    pub name: DnsName,
    
    pub record_type: RecordType,
    
    pub class: Class,
    
    pub ttl: u32,
    
    pub data: RData,
}

/// Resource Record Data
///
/// This enum contains the different types of resource record data
/// that can appear in a DNS message.
#[derive(Debug, Clone)]
pub enum RData {
    /// A Record - IPv4 Address (RFC 1035)
    A(Ipv4Addr),
    
    /// AAAA Record - IPv6 Address (RFC 3596)
    AAAA(Ipv6Addr),
    
    /// CNAME Record - Canonical Name (RFC 1035)
    CNAME(DnsName),
    
    /// NS Record - Name Server (RFC 1035)
    NS(DnsName),
    
    /// MX Record - Mail Exchange (RFC 1035)
    MX {
        preference: u16,  /// lower values are preferred
        exchange: DnsName,
    },
    
    /// PTR Record - Pointer (RFC 1035)
    PTR(DnsName),
    
    /// SOA Record - Start of Authority (RFC 1035)
    SOA {
        mname: DnsName,
        rname: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    
    /// TXT Record - Text (RFC 1035)
    TXT(Vec<String>),
    
    /// SRV Record - Service (RFC 2782)
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    
    /// OPT Record - Option (RFC 6891 - EDNS(0))
    OPT {
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        flags: u16,
        options: Vec<(u16, Vec<u8>)>,
    },
    
    /// DS Record - Delegation Signer (RFC 4034)
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    
    /// RRSIG Record - DNSSEC Signature (RFC 4034)
    RRSIG {
        /// Type of the covered record
        type_covered: u16,
        /// Cryptographic algorithm
        algorithm: u8,
        /// Number of labels in the original name
        labels: u8,
        /// Original TTL
        original_ttl: u32,
        /// Signature expiration time
        signature_expiration: u32,
        /// Signature inception time
        signature_inception: u32,
        /// Key tag
        key_tag: u16,
        /// Signer's name
        signer_name: DnsName,
        /// Signature data
        signature: Vec<u8>,
    },
    
    /// NSEC Record - Next Secure Record (RFC 4034)
    NSEC {
        /// Next domain name
        next_domain_name: DnsName,
        /// Type bit maps
        type_bit_maps: Vec<u8>,
    },
    
    /// DNSKEY Record - DNS Key Record (RFC 4034)
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    
    /// NSEC3 Record - NSEC version 3 (RFC 5155)
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner_name: Vec<u8>,
        type_bit_maps: Vec<u8>,
    },
    
    /// NSEC3PARAM Record - NSEC3 Parameters (RFC 5155)
    NSEC3PARAM {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
    },
    
    /// CAA Record - Certification Authority Authorization (RFC 6844/8659)
    CAA {
        flags: u8,
        tag: String,
        value: Vec<u8>,
    },
    
    /// Unknown record type - raw bytes
    Unknown(Vec<u8>),
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high_nibble = (byte >> 4) & 0x0f;
        let low_nibble = byte & 0x0f;
        s.push(std::char::from_digit(high_nibble as u32, 16).unwrap_or('?'));
        s.push(std::char::from_digit(low_nibble as u32, 16).unwrap_or('?'));
    }
    s
}

impl ResourceRecord {
    pub fn new(name: DnsName, record_type: RecordType, class: Class, ttl: u32, data: RData) -> Self {
        ResourceRecord {
            name,
            record_type,
            class,
            ttl,
            data,
        }
    }
    
    pub fn parse(buffer: &[u8], offset: usize) -> Result<(Self, usize)> {
        let original_offset = offset;
        
        // Check if we have enough bytes for the fixed part of the RR header (name size is dynamic)
        // Minimum possible RR header is 1 byte name (root ".") + 10 bytes fixed fields
        if offset + 1 + 10 > buffer.len() {
            return Err(Error::Underrun);
        }

        let (name, name_size) = DnsName::parse(buffer, offset, buffer)?;
        let mut pos = offset + name_size;
        
        if pos + 10 > buffer.len() {
            return Err(Error::Underrun);
        }
        
        let record_type_val = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]);
        let record_type = RecordType::from_u16(record_type_val);
        let class_val = u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]);
        let class = Class::from_u16(class_val);
        let ttl = u32::from_be_bytes([
            buffer[pos + 4],
            buffer[pos + 5],
            buffer[pos + 6],
            buffer[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([buffer[pos + 8], buffer[pos + 9]]) as usize;
        
        pos += 10;
        
        if pos + rdlength > buffer.len() {
            return Err(Error::Underrun);
        }
        
        let rdata_start_pos = pos;

        let data = match record_type {
            RecordType::A => {
                if rdlength != 4 {
                    return Err(Error::InvalidRDataLength { expected: 4, actual: rdlength });
                }
                let ip = Ipv4Addr::new(
                    buffer[pos],
                    buffer[pos + 1],
                    buffer[pos + 2],
                    buffer[pos + 3],
                );
                pos += 4;
                RData::A(ip)
            },
            
            RecordType::AAAA => {
                if rdlength != 16 {
                    return Err(Error::InvalidRDataLength { expected: 16, actual: rdlength });
                }
                let ip_bytes: [u8; 16] = buffer[pos..pos + 16]
                    .try_into()
                    .map_err(|_| Error::Underrun)?; // Should be unreachable due to earlier check
                let ip = Ipv6Addr::from(ip_bytes);
                pos += 16;
                RData::AAAA(ip)
            },
            
            RecordType::CNAME => {
                let (cname, name_bytes) = DnsName::parse(buffer, pos, buffer)?;
                pos += name_bytes;
                RData::CNAME(cname)
            },
            
            RecordType::NS => {
                let (ns, name_bytes) = DnsName::parse(buffer, pos, buffer)?;
                pos += name_bytes;
                RData::NS(ns)
            },
            
            RecordType::MX => {
                if rdlength < 2 + 1 { // Need 2 bytes preference + min 1 byte name (.)
                    return Err(Error::InvalidFormat); // Or a new specific error?
                }
                let preference = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]);
                let (exchange, name_bytes) = DnsName::parse(buffer, pos + 2, buffer)?;
                pos += 2 + name_bytes;
                RData::MX {
                    preference,
                    exchange,
                }
            },
            
            RecordType::PTR => {
                let (ptr, name_bytes) = DnsName::parse(buffer, pos, buffer)?;
                pos += name_bytes;
                RData::PTR(ptr)
            },
            
            RecordType::SOA => {
                let (mname, mname_size) = DnsName::parse(buffer, pos, buffer)?;
                let soa_pos = pos + mname_size;
                let (rname, rname_size) = DnsName::parse(buffer, soa_pos, buffer)?;
                let nums_pos = soa_pos + rname_size;
                
                if nums_pos + 20 > rdata_start_pos + rdlength { // Check against RDLENGTH limit
                    return Err(Error::Underrun);
                }
                
                let serial = u32::from_be_bytes([
                    buffer[nums_pos],
                    buffer[nums_pos + 1],
                    buffer[nums_pos + 2],
                    buffer[nums_pos + 3],
                ]);
                
                let refresh = u32::from_be_bytes([
                    buffer[nums_pos + 4],
                    buffer[nums_pos + 5],
                    buffer[nums_pos + 6],
                    buffer[nums_pos + 7],
                ]);
                
                let retry = u32::from_be_bytes([
                    buffer[nums_pos + 8],
                    buffer[nums_pos + 9],
                    buffer[nums_pos + 10],
                    buffer[nums_pos + 11],
                ]);
                
                let expire = u32::from_be_bytes([
                    buffer[nums_pos + 12],
                    buffer[nums_pos + 13],
                    buffer[nums_pos + 14],
                    buffer[nums_pos + 15],
                ]);
                
                let minimum = u32::from_be_bytes([
                    buffer[nums_pos + 16],
                    buffer[nums_pos + 17],
                    buffer[nums_pos + 18],
                    buffer[nums_pos + 19],
                ]);
                pos = nums_pos + 20;
                RData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            },
            
            RecordType::TXT => {
                let mut strings = Vec::new();
                let mut txt_pos = pos;
                let end_pos = pos + rdlength;
                
                while txt_pos < end_pos {
                    if txt_pos >= buffer.len() {
                        return Err(Error::Underrun);
                    }
                    
                    let len = buffer[txt_pos] as usize;
                    txt_pos += 1;
                    
                    if txt_pos + len > end_pos {
                        return Err(Error::InvalidCharacterStringLength);
                    }
                    if txt_pos + len > buffer.len() {
                        // TODO: Check if this is redundant
                        return Err(Error::Underrun);
                    }

                    let data_slice = &buffer[txt_pos..txt_pos + len];
                    let txt_str = match std::str::from_utf8(data_slice) {
                        Ok(s) => s.to_string(),
                        Err(_) => {
                            format!("0x{}", bytes_to_hex_string(data_slice))
                        }
                    };
                    
                    strings.push(txt_str);
                    txt_pos += len;
                }
                pos = txt_pos;
                RData::TXT(strings)
            },
            
            RecordType::SRV => {
                if rdlength < 6 + 1 {
                    return Err(Error::InvalidFormat);
                }
                
                let priority = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]);
                let weight = u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]);
                let port = u16::from_be_bytes([buffer[pos + 4], buffer[pos + 5]]);
                let (target, name_bytes) = DnsName::parse(buffer, pos + 6, buffer)?;
                pos += 6 + name_bytes;
                RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                }
            },
            
            RecordType::OPT => {
                let mut options = Vec::new();
                let mut opt_pos = pos;
                let end_pos = pos + rdlength;
                
                while opt_pos + 4 <= end_pos {
                    let opt_code = u16::from_be_bytes([buffer[opt_pos], buffer[opt_pos + 1]]);
                    let opt_len = u16::from_be_bytes([buffer[opt_pos + 2], buffer[opt_pos + 3]]) as usize;
                    opt_pos += 4;
                    
                    if opt_pos + opt_len > end_pos { 
                        return Err(Error::Underrun); 
                    }
                    
                    let opt_data = buffer[opt_pos..opt_pos + opt_len].to_vec();
                    options.push((opt_code, opt_data));
                    opt_pos += opt_len;
                }
                
                pos = opt_pos;

                // Extract EDNS parameters from overloaded fields
                let version = ((ttl >> 16) & 0xFF) as u8;
                let extended_rcode = ((ttl >> 24) & 0xFF) as u8;
                let flags = (ttl & 0xFFFF) as u16;
                
                RData::OPT {
                    udp_payload_size: class.to_u16(), // Class field contains UDP payload size
                    extended_rcode,
                    version,
                    flags,
                    options,
                }
            },
            
            RecordType::DS => {
                if rdlength < 4 { // 2 key_tag + 1 algo + 1 digest_type
                    return Err(Error::InvalidRDataLength{ expected: 4, actual: rdlength}); // Min length
                }
                
                let key_tag = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]);
                let algorithm = buffer[pos + 2];
                let digest_type = buffer[pos + 3];
                let digest = buffer[pos + 4..pos + rdlength].to_vec();
                pos += rdlength; // Consume the rest
                RData::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                }
            },
            
            RecordType::RRSIG => {
                if rdlength < 18 + 1 { // 18 bytes fixed fields + min 1 byte name (.)
                    return Err(Error::InvalidFormat); // Min length
                }
                
                let type_covered = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]);
                let algorithm = buffer[pos + 2];
                let labels = buffer[pos + 3];
                
                let original_ttl = u32::from_be_bytes([
                    buffer[pos + 4],
                    buffer[pos + 5],
                    buffer[pos + 6],
                    buffer[pos + 7],
                ]);
                
                let signature_expiration = u32::from_be_bytes([
                    buffer[pos + 8],
                    buffer[pos + 9],
                    buffer[pos + 10],
                    buffer[pos + 11],
                ]);
                
                let signature_inception = u32::from_be_bytes([
                    buffer[pos + 12],
                    buffer[pos + 13],
                    buffer[pos + 14],
                    buffer[pos + 15],
                ]);
                
                let key_tag = u16::from_be_bytes([buffer[pos + 16], buffer[pos + 17]]);
                
                let (signer_name, signer_name_size) = DnsName::parse(buffer, pos + 18, buffer)?;
                let signature_pos = pos + 18 + signer_name_size;
                
                if signature_pos > rdata_start_pos + rdlength {
                    return Err(Error::Underrun);
                }
                
                let signature = buffer[signature_pos..rdata_start_pos + rdlength].to_vec();
                pos = rdata_start_pos + rdlength;
                RData::RRSIG {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    signature_expiration,
                    signature_inception,
                    key_tag,
                    signer_name,
                    signature,
                }
            },
            
            RecordType::NSEC => {
                if rdlength < 1 { // Min 1 byte name (.)
                   return Err(Error::InvalidFormat); // Min length
                }
                let (next_domain_name, name_size) = DnsName::parse(buffer, pos, buffer)?;
                let type_maps_pos = pos + name_size;
                
                if type_maps_pos > rdata_start_pos + rdlength {
                    return Err(Error::Underrun);
                }
                
                let type_bit_maps = buffer[type_maps_pos..rdata_start_pos + rdlength].to_vec();
                pos = rdata_start_pos + rdlength;
                RData::NSEC {
                    next_domain_name,
                    type_bit_maps,
                }
            },
            
            RecordType::DNSKEY => {
                if rdlength < 4 { // flags(2) + proto(1) + algo(1)
                    return Err(Error::InvalidRDataLength{ expected: 4, actual: rdlength}); // Min length
                }
                
                let flags = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]);
                let protocol = buffer[pos + 2];
                let algorithm = buffer[pos + 3];
                let public_key = buffer[pos + 4..pos + rdlength].to_vec();
                pos += rdlength;
                RData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                }
            },
            
            RecordType::NSEC3 => {
                if rdlength < 5 { // hash_algo(1) + flags(1) + iterations(2) + salt_len(1)
                    return Err(Error::InvalidFormat); // Min length
                }
                
                let hash_algorithm = buffer[pos];
                let flags = buffer[pos + 1];
                let iterations = u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]);
                
                let salt_length = buffer[pos + 4] as usize;
                let salt_start = pos + 5;
                if salt_start + salt_length > rdata_start_pos + rdlength {
                    return Err(Error::InvalidInternalFieldLength);
                }
                
                let salt = buffer[salt_start..salt_start + salt_length].to_vec();
                let hash_len_pos = salt_start + salt_length;
                
                if hash_len_pos >= rdata_start_pos + rdlength {
                    return Err(Error::Underrun);
                }
                
                let hash_length = buffer[hash_len_pos] as usize;
                let hash_start = hash_len_pos + 1;
                if hash_start + hash_length > rdata_start_pos + rdlength {
                    return Err(Error::InvalidInternalFieldLength);
                }
                
                let next_hashed_owner_name = buffer[hash_start..hash_start + hash_length].to_vec();
                let type_maps_pos = hash_start + hash_length;
                
                if type_maps_pos > rdata_start_pos + rdlength {
                    return Err(Error::Underrun);
                }
                
                let type_bit_maps = buffer[type_maps_pos..rdata_start_pos + rdlength].to_vec();
                pos = rdata_start_pos + rdlength;
                RData::NSEC3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner_name,
                    type_bit_maps,
                }
            },
            
            RecordType::NSEC3PARAM => {
                if rdlength < 5 { // hash_algo(1) + flags(1) + iterations(2) + salt_len(1)
                    return Err(Error::InvalidFormat); // Min length
                }
                
                let hash_algorithm = buffer[pos];
                let flags = buffer[pos + 1];
                let iterations = u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]);
                
                let salt_length = buffer[pos + 4] as usize;
                let salt_start = pos + 5;
                if salt_start + salt_length > rdata_start_pos + rdlength {
                    return Err(Error::InvalidInternalFieldLength);
                }
                
                let salt = buffer[salt_start..salt_start + salt_length].to_vec();
                pos = salt_start + salt_length; // Consume up to end of salt
                RData::NSEC3PARAM {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                }
            },
            
            RecordType::CAA => {
                if rdlength < 2 { // flags(1) + tag_len(1)
                    return Err(Error::InvalidFormat); // Min length
                }
                
                let flags = buffer[pos];
                let tag_length = buffer[pos + 1] as usize;
                let tag_start = pos + 2;

                if tag_start + tag_length > rdata_start_pos + rdlength {
                    return Err(Error::InvalidInternalFieldLength);
                }
                
                let tag = match std::str::from_utf8(&buffer[tag_start..tag_start + tag_length]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return Err(Error::InvalidCaaTagEncoding),
                };
                
                let value_pos = tag_start + tag_length;
                // No need to check value_pos against RDLENGTH, as value fills the remainder
                // if value_pos > rdata_start_pos + rdlength { return Err(Error::Underrun); }
                
                let value = buffer[value_pos..rdata_start_pos + rdlength].to_vec();
                pos = rdata_start_pos + rdlength;
                RData::CAA {
                    flags,
                    tag,
                    value,
                }
            },
            
            RecordType::Unknown(_) | RecordType::ANY => {
                // For unknown record types or ANY (which shouldn't appear in RDATA),
                // just capture the raw bytes.
                let data = buffer[pos..pos + rdlength].to_vec();
                pos += rdlength;
                RData::Unknown(data)
            },
        };
        
        let bytes_parsed = pos - rdata_start_pos;
        if bytes_parsed != rdlength {
            // This indicates an internal logic error in one of the parsing arms above
            // Or potentially an Overrun if bytes_parsed > rdlength
            return Err(Error::InvalidFormat);
        }

        let rr = ResourceRecord {
            name,
            record_type,
            class,
            ttl,
            data,
        };
        
        // Total bytes consumed for this RR = pos (end of RDATA) - original offset
        Ok((rr, pos - original_offset))
    }
    
    /// Write the resource record to a buffer
    pub fn write(&self, buffer: &mut Vec<u8>, name_positions: &mut HashMap<String, usize>) -> usize {
        let start_pos = buffer.len();
        
        self.name.write(buffer, name_positions);
        
        buffer.extend_from_slice(&self.record_type.to_u16().to_be_bytes());
        
        buffer.extend_from_slice(&self.class.to_u16().to_be_bytes());
        
        buffer.extend_from_slice(&self.ttl.to_be_bytes());
        
        let rdlength_pos = buffer.len();
        buffer.extend_from_slice(&[0, 0]); // Placeholder for RDLENGTH
        
        let rdata_start = buffer.len();
        
        match &self.data {
            RData::A(ip) => {
                buffer.extend_from_slice(&ip.octets());
            },
            
            RData::AAAA(ip) => {
                buffer.extend_from_slice(&ip.octets());
            },
            
            RData::CNAME(cname) => {
                cname.write(buffer, name_positions);
            },
            
            RData::NS(ns) => {
                ns.write(buffer, name_positions);
            },
            
            RData::MX { preference, exchange } => {
                buffer.extend_from_slice(&preference.to_be_bytes());
                exchange.write(buffer, name_positions);
            },
            
            RData::PTR(ptr) => {
                ptr.write(buffer, name_positions);
            },
            
            RData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
                mname.write(buffer, name_positions);
                rname.write(buffer, name_positions);
                buffer.extend_from_slice(&serial.to_be_bytes());
                buffer.extend_from_slice(&refresh.to_be_bytes());
                buffer.extend_from_slice(&retry.to_be_bytes());
                buffer.extend_from_slice(&expire.to_be_bytes());
                buffer.extend_from_slice(&minimum.to_be_bytes());
            },
            
            RData::TXT(strings) => {
                for s in strings {
                    let bytes = s.as_bytes();
                    if bytes.len() > 255 {
                        // TXT strings are limited to 255 bytes
                        buffer.push(255);
                        buffer.extend_from_slice(&bytes[0..255]);
                    } else {
                        buffer.push(bytes.len() as u8);
                        buffer.extend_from_slice(bytes);
                    }
                }
            },
            
            RData::SRV { priority, weight, port, target } => {
                buffer.extend_from_slice(&priority.to_be_bytes());
                buffer.extend_from_slice(&weight.to_be_bytes());
                buffer.extend_from_slice(&port.to_be_bytes());
                target.write(buffer, name_positions);
            },
            
            RData::OPT { udp_payload_size: _, extended_rcode: _, version: _, flags: _, options } => {
                for (code, data) in options {
                    buffer.extend_from_slice(&code.to_be_bytes());
                    buffer.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    buffer.extend_from_slice(data);
                }
            },
            
            RData::DS { key_tag, algorithm, digest_type, digest } => {
                buffer.extend_from_slice(&key_tag.to_be_bytes());
                buffer.push(*algorithm);
                buffer.push(*digest_type);
                buffer.extend_from_slice(digest);
            },
            
            RData::RRSIG { type_covered, algorithm, labels, original_ttl, signature_expiration, 
                          signature_inception, key_tag, signer_name, signature } => {
                buffer.extend_from_slice(&type_covered.to_be_bytes());
                buffer.push(*algorithm);
                buffer.push(*labels);
                buffer.extend_from_slice(&original_ttl.to_be_bytes());
                buffer.extend_from_slice(&signature_expiration.to_be_bytes());
                buffer.extend_from_slice(&signature_inception.to_be_bytes());
                buffer.extend_from_slice(&key_tag.to_be_bytes());
                signer_name.write(buffer, name_positions);
                buffer.extend_from_slice(signature);
            },
            
            RData::NSEC { next_domain_name, type_bit_maps } => {
                next_domain_name.write(buffer, name_positions);
                buffer.extend_from_slice(type_bit_maps);
            },
            
            RData::DNSKEY { flags, protocol, algorithm, public_key } => {
                buffer.extend_from_slice(&flags.to_be_bytes());
                buffer.push(*protocol);
                buffer.push(*algorithm);
                buffer.extend_from_slice(public_key);
            },
            
            RData::NSEC3 { hash_algorithm, flags, iterations, salt, next_hashed_owner_name, type_bit_maps } => {
                buffer.push(*hash_algorithm);
                buffer.push(*flags);
                buffer.extend_from_slice(&iterations.to_be_bytes());
                buffer.push(salt.len() as u8);
                buffer.extend_from_slice(salt);
                buffer.push(next_hashed_owner_name.len() as u8);
                buffer.extend_from_slice(next_hashed_owner_name);
                buffer.extend_from_slice(type_bit_maps);
            },
            
            RData::NSEC3PARAM { hash_algorithm, flags, iterations, salt } => {
                buffer.push(*hash_algorithm);
                buffer.push(*flags);
                buffer.extend_from_slice(&iterations.to_be_bytes());
                buffer.push(salt.len() as u8);
                buffer.extend_from_slice(salt);
            },
            
            RData::CAA { flags, tag, value } => {
                buffer.push(*flags);
                buffer.push(tag.len() as u8);
                buffer.extend_from_slice(tag.as_bytes());
                buffer.extend_from_slice(value);
            },
            
            RData::Unknown(data) => {
                buffer.extend_from_slice(data);
            },
        }
        
        // Calculate RDLENGTH and update it
        let rdata_len = buffer.len() - rdata_start;
        let rdlength_bytes = (rdata_len as u16).to_be_bytes();
        buffer[rdlength_pos] = rdlength_bytes[0];
        buffer[rdlength_pos + 1] = rdlength_bytes[1];
        
        buffer.len() - start_pos
    }
} 