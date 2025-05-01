/// DNS Record Type Codes
/// As per RFC 1035 and subsequent updates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,         // RFC 1035 - IPv4 address record
    NS = 2,        // RFC 1035 - Name server record
    CNAME = 5,     // RFC 1035 - Canonical name record
    SOA = 6,       // RFC 1035 - Start of authority record
    PTR = 12,      // RFC 1035 - Pointer record
    MX = 15,       // RFC 1035 - Mail exchange record
    TXT = 16,      // RFC 1035 - Text record
    AAAA = 28,     // RFC 3596 - IPv6 address record
    SRV = 33,      // RFC 2782 - Service locator
    // DNSSEC record types (RFC 4034)
    DS = 43,       // RFC 4034 - Delegation Signer
    RRSIG = 46,    // RFC 4034 - DNSSEC signature
    NSEC = 47,     // RFC 4034 - Next Secure record
    DNSKEY = 48,   // RFC 4034 - DNS Key record
    NSEC3 = 50,    // RFC 5155 - NSEC version 3
    NSEC3PARAM = 51, // RFC 5155 - NSEC3 parameters
    // Other record types
    CAA = 257,     // RFC 6844/8659 - Certification Authority Authorization
    OPT = 41,      // RFC 6891 - Option record for EDNS(0)
    ANY = 255,     // RFC 1035 - Request for all records
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(value: u16) -> RecordType {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            41 => RecordType::OPT,
            43 => RecordType::DS,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            255 => RecordType::ANY,
            257 => RecordType::CAA,
            _ => RecordType::Unknown(value),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::DS => 43,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::ANY => 255,
            RecordType::CAA => 257,
            RecordType::Unknown(value) => *value,
        }
    }
}

/// DNS Class Codes
/// As per RFC 1035
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Class {
    IN = 1,        // RFC 1035 - Internet
    CS = 2,        // RFC 1035 - CSNET (obsolete)
    CH = 3,        // RFC 1035 - CHAOS
    HS = 4,        // RFC 1035 - Hesiod
    ANY = 255,     // RFC 1035 - Any class
    Unknown(u16),
}

impl Class {
    pub fn from_u16(value: u16) -> Class {
        match value {
            1 => Class::IN,
            2 => Class::CS,
            3 => Class::CH,
            4 => Class::HS,
            255 => Class::ANY,
            _ => Class::Unknown(value),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            Class::ANY => 255,
            Class::Unknown(value) => *value,
        }
    }
}

/// RCODE (Response Code) values as defined in RFC 1035
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    NoError = 0,           // No error
    FormatError = 1,       // Format error
    ServerFailure = 2,     // Server failure
    NameError = 3,         // Name error (name does not exist)
    NotImplemented = 4,    // Not implemented
    Refused = 5,           // Refused
    Unknown(u8),
}

impl ResponseCode {
    pub fn from_u8(value: u8) -> ResponseCode {
        match value {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::Unknown(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Unknown(value) => *value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Query = 0,             // Standard query
    IQuery = 1,            // Inverse query (obsolete)
    Status = 2,            // Server status request
    // Values 3-15 are reserved
    Unknown(u8),
}

impl OpCode {
    pub fn from_u8(value: u8) -> OpCode {
        match value {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            _ => OpCode::Unknown(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Unknown(value) => *value,
        }
    }
}

/// EDNS Option Codes (RFC 6891 and updates)
#[repr(u16)]
pub enum EdnsOption {
    // RFC 6891 - EDNS(0)
    LLQ = 1,               // Long-lived query
    UL = 2,                // Update lease
    NSID = 3,              // Name server identifier
    // RFC 7830
    Padding = 12,          // Padding
    // RFC 7873
    Cookie = 10,           // DNS Cookies
}

impl EdnsOption {
    pub fn from_u16(value: u16) -> u16 {
        value
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            EdnsOption::LLQ => 1,
            EdnsOption::UL => 2,
            EdnsOption::NSID => 3,
            EdnsOption::Padding => 12,
            EdnsOption::Cookie => 10,
        }
    }
} 