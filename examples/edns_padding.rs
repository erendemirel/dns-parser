use std::net::Ipv4Addr;

use dns_parser::error::Result;
use dns_parser::message::Message;
use dns_parser::types::{EdnsOption, RecordType};

fn main() -> Result<()> {
    println!("=== DNS Parser Example with EDNS Support ===\n");

    let query_id = 1234;
    let hostname = "example.com";
    let mut query = Message::new_query(query_id, hostname, RecordType::A)?;

    println!("Created DNS query for {} (A record)", hostname);

    let target_size = 128;
    query.add_padding(target_size)?;

    let query_bytes = query.to_bytes();
    println!("Query size: {} bytes (with EDNS padding)", query_bytes.len());

    let query_message = Message::parse(&query_bytes)?;
    println!("--- Parsed DNS Query ---");
    println!("ID: {}", query_message.header.id);
    println!("Questions: {}", query_message.questions.len());
    println!("Additional RRs: {}", query_message.additionals.len());

    if let Some((udp_size, _ext_rcode, version, _flags, options)) = query_message.get_edns_options()
    {
        println!("EDNS: UDP Buffer Size: {}, Version: {}", udp_size, version);

        for (opt_code, data) in options {
            if opt_code == EdnsOption::Padding.to_u16() {
                println!("  EDNS Padding: {} bytes", data.len());
            } else {
                println!("  EDNS Option: Code {}, {} bytes", opt_code, data.len());
            }
        }
    }

    println!();

    let ip = Ipv4Addr::new(93, 184, 216, 34);
    let ttl = 3600;
    let mut response = Message::parse(&Message::create_a_response(query_id, hostname, ip, ttl)?)?;

    response.add_padding(target_size)?;
    let response_bytes = response.to_bytes();

    println!("Created DNS response for {} -> {}", hostname, ip);
    println!(
        "Response size: {} bytes (with EDNS padding)",
        response_bytes.len()
    );

    let response_message = Message::parse(&response_bytes)?;
    println!("--- Parsed DNS Response ---");
    println!("ID: {}", response_message.header.id);
    println!("Questions: {}", response_message.questions.len());
    println!("Answers: {}", response_message.answers.len());
    println!("Additional RRs: {}", response_message.additionals.len());

    if let Some((udp_size, _ext_rcode, version, _flags, options)) =
        response_message.get_edns_options()
    {
        println!("EDNS: UDP Buffer Size: {}, Version: {}", udp_size, version);

        for (opt_code, data) in options {
            if opt_code == EdnsOption::Padding.to_u16() {
                println!("  EDNS Padding: {} bytes", data.len());
            } else {
                println!("  EDNS Option: Code {}, {} bytes", opt_code, data.len());
            }
        }
    }

    for (i, a) in response_message.answers.iter().enumerate() {
        println!(
            "  Answer #{}: {} {:?} {} TTL:{}",
            i + 1,
            a.name,
            a.record_type,
            match &a.data {
                dns_parser::resource_record::RData::A(ip) => format!("A:{}", ip),
                _ => format!("{:?}", a.data),
            },
            a.ttl
        );
    }

    println!("\n=== DNS Parser Example Completed ===");
    Ok(())
}
