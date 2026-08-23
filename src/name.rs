use std::fmt;
use crate::error::{Error, Result};

const MAX_POINTER_DEPTH: usize = 100;

/// Maximum length of a DNS name (RFC 1035 limit)
const MAX_NAME_LENGTH: usize = 255;

/// Maximum length of a DNS label (RFC 1035 limit)
const MAX_LABEL_LENGTH: usize = 63;

/// This struct stores the parsed name as a sequence of labels
/// and provides methods to parse and serialize names.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsName {
    labels: Vec<String>,
}

impl DnsName {
    pub fn new(name: &str) -> Result<Self> {
        if name.is_empty() {
            return Ok(DnsName { labels: Vec::new() });
        }

        if name == "." {
            return Ok(DnsName { labels: Vec::new() });
        }

        let mut labels = Vec::new();
        let parts = name.split('.').collect::<Vec<&str>>();

        for part in parts {
            if part.is_empty() {
                continue; // Skip empty parts (e.g., trailing dot)
            }

            if part.len() > MAX_LABEL_LENGTH {
                return Err(Error::InvalidName);
            }

            if !is_valid_label(part, labels.is_empty()) {
                return Err(Error::InvalidName);
            }

            labels.push(part.to_string());
        }
        
        let total_len = labels.iter().map(|l| l.len() + 1).sum::<usize>();
        if total_len > MAX_NAME_LENGTH {
            return Err(Error::InvalidName);
        }
        
        Ok(DnsName { labels })
    }
    
    /// Parse a domain name from a DNS message
    /// 
    /// - `buffer`: The DNS message buffer
    /// - `offset`: The offset in the buffer where the name starts
    /// - `original_buffer`: The original complete DNS message, needed for following name pointers
    /// 
    /// Returns the parsed name and the number of bytes consumed from the buffer
    pub fn parse(buffer: &[u8], offset: usize, original_buffer: &[u8]) -> Result<(Self, usize)> {
        let mut labels = Vec::new();
        let mut pos = offset;
        let mut bytes_consumed = 0;
        let mut pointer_depth = 0;
        let mut current_buffer = buffer;
        let mut used_current_buffer = true;
        
        loop {
            if pos >= current_buffer.len() {
                return Err(Error::Underrun);
            }
            
            let label_len = current_buffer[pos];
            
            if (label_len & 0xC0) == 0xC0 {
                if pos + 1 >= current_buffer.len() {
                    return Err(Error::Underrun);
                }
                
                // The offset is the lower 14 bits
                let pointer_offset = ((((label_len & 0x3F) as u16) << 8) | (current_buffer[pos + 1] as u16)) as usize;
                
                if used_current_buffer && bytes_consumed == 0 {
                    bytes_consumed = pos - offset + 2;
                }
                
                if pointer_offset >= original_buffer.len() || pointer_offset >= offset { // Check bounds relative to original buffer start
                     // Note: This check might be overly strict, DNS allows forward pointers in some contexts?
                     if pointer_offset >= original_buffer.len() {
                        return Err(Error::InvalidCompressionPointer);
                     }
                     let absolute_pointer_pos = if used_current_buffer { offset + (pos - offset) } else { pos };
                     if pointer_offset >= absolute_pointer_pos {
                        return Err(Error::InvalidCompressionPointer); // Maybe CompressionLoop is better?
                     }
                }

                if pointer_depth >= MAX_POINTER_DEPTH {
                    return Err(Error::CompressionLoop);
                }
                
                pointer_depth += 1;
                pos = pointer_offset;
                
                current_buffer = original_buffer;
                used_current_buffer = false; 
                continue;
            }
            
            let label_len = label_len as usize;
            
            if label_len == 0 {
                if used_current_buffer && bytes_consumed == 0 {
                    bytes_consumed = pos - offset + 1; // +1 for the terminating 0
                }
                if bytes_consumed == 0 {
                     return Err(Error::Other("Failed to determine bytes consumed for name ending in null byte after pointer jump".to_string()));
                }

                break;
            }
            
            if label_len > MAX_LABEL_LENGTH {
                return Err(Error::InvalidName);
            }
            
            if pos + 1 + label_len > current_buffer.len() {
                return Err(Error::Underrun);
            }
            
            let label_bytes = &current_buffer[pos + 1..pos + 1 + label_len];
            if !is_valid_wire_label(label_bytes, labels.is_empty()) {
                return Err(Error::InvalidName);
            }
            let label = unsafe { String::from_utf8_unchecked(label_bytes.to_vec()) };

            labels.push(label);
            pos += label_len + 1;
        }

        let total_wire_len = labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1; // +1 for terminal zero
        if total_wire_len > MAX_NAME_LENGTH {
            return Err(Error::InvalidName);
        }

        let name = DnsName { labels };
        Ok((name, bytes_consumed))
    }
    
    /// Write the name to a buffer, possibly using compression
    ///
    /// - `buffer`: The buffer to write to
    /// - `name_positions`: A map of previously written names to their positions
    ///
    /// Returns the number of bytes written
    pub fn write(&self, buffer: &mut Vec<u8>, name_positions: &mut std::collections::HashMap<String, usize>) -> usize {
        let start_pos = buffer.len();
        
        if self.labels.is_empty() {
            buffer.push(0);
            return 1;
        }
        
        for i in 0..self.labels.len() {
            let suffix = self.labels[i..].join(".");
            if let Some(&pos) = name_positions.get(&suffix) {
                let pointer = 0xC000 | (pos as u16);
                buffer.extend_from_slice(&pointer.to_be_bytes());
                return buffer.len() - start_pos;
            }
            
            if i < self.labels.len() - 1 {
                let suffix = self.labels[i..].join(".");
                name_positions.insert(suffix, buffer.len());
            }
            
            let label = &self.labels[i];
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
        }
        
        buffer.push(0);
        
        buffer.len() - start_pos
    }
    
    pub fn labels(&self) -> &[String] {
        &self.labels
    }
    
    pub fn to_string(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }
        self.labels.join(".")
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Validates a label when constructing a name from text.
///
/// Allows letters, digits, hyphen, and underscore (needed for SRV style names).
/// A lone `*` is allowed only as the leftmost label (wildcard names).
fn is_valid_label(part: &str, is_leftmost: bool) -> bool {
    if part == "*" {
        return is_leftmost;
    }

    part.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Validates a label decoded from the wire.
fn is_valid_wire_label(label_bytes: &[u8], is_leftmost: bool) -> bool {
    if label_bytes == b"*" {
        return is_leftmost;
    }

    label_bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
} 