#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_parser::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::parse(data) {
        let encoded = message.to_bytes();
        let _ = Message::parse(&encoded);
    }
});
