use std::fmt;
use std::error::Error as StdError;
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Buffer underrun while parsing (less data than expected)
    Underrun,
    /// Buffer overrun (more data used than RDLENGTH specified)
    Overrun,
    /// Invalid DNS name format (e.g., label too long, invalid characters, bad sequence)
    InvalidName,
    /// Message format error (e.g., invalid field values, inconsistent counts)
    InvalidFormat,
    /// Expected specific length for RDATA based on type (e.g., A, AAAA)
    InvalidRDataLength {
        expected: usize,
        actual: usize,
    },
    /// Invalid length specified for a character string (e.g., in TXT)
    InvalidCharacterStringLength,
    /// Invalid length specified for internal RDATA field (e.g., NSEC3 salt, CAA tag)
    InvalidInternalFieldLength,
    /// Compression pointer points outside the valid buffer range
    InvalidCompressionPointer,
    /// Compression pointer loop detected
    CompressionLoop,
    /// Invalid record type value encountered during parsing
    InvalidRecordTypeValue(u16),
    /// Invalid class value encountered during parsing
    InvalidClassValue(u16),
    /// Invalid OpCode value encountered during parsing
    InvalidOpCodeValue(u8),
    /// Invalid RCODE value encountered during parsing
    InvalidRCodeValue(u8),
    /// CAA record tag contained invalid UTF-8
    InvalidCaaTagEncoding,
    /// Generic error with message (use sparingly)
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Underrun => write!(f, "buffer underrun: less data than expected"),
            Error::Overrun => write!(f, "buffer overrun: more data parsed than expected by RDLENGTH"),
            Error::InvalidName => write!(f, "invalid DNS name format"),
            Error::InvalidFormat => write!(f, "invalid DNS message format"),
            Error::InvalidRDataLength { expected, actual } => {
                write!(f, "invalid RDATA length: expected {}, got {}", expected, actual)
            }
            Error::InvalidCharacterStringLength => write!(f, "invalid length for character string (e.g., TXT)"),
            Error::InvalidInternalFieldLength => write!(f, "invalid length for internal RDATA field (e.g., NSEC3 salt)"),
            Error::InvalidCompressionPointer => write!(f, "compression pointer points outside valid buffer range"),
            Error::CompressionLoop => write!(f, "compression pointer loop detected"),
            Error::InvalidRecordTypeValue(val) => write!(f, "invalid record type value: {}", val),
            Error::InvalidClassValue(val) => write!(f, "invalid class value: {}", val),
            Error::InvalidOpCodeValue(val) => write!(f, "invalid opcode value: {}", val),
            Error::InvalidRCodeValue(val) => write!(f, "invalid rcode value: {}", val),
            Error::InvalidCaaTagEncoding => write!(f, "invalid UTF-8 encoding in CAA tag"),
            Error::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl StdError for Error {} 