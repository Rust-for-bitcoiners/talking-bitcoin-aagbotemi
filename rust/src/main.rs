use chrono::Utc;
use dns_lookup::lookup_host;
use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{
    consensus::{deserialize_partial, encode::serialize_hex},
    Block,
};
use rand::seq::SliceRandom;
use rand::thread_rng;
use tokio::time::{timeout, Duration};

const PROTOCOL_VERSION: i32 = 70015;
const REGTEST_MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // the magic value for the regtest network
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9]; // the magic value for the mainnet

// Define the fields
struct NetAddress {
    services: u64,
    ip: Ipv6Addr,
    port: u16,
}

// Define the fields
struct VersionMessage {
    version: i32,
    services: u64,
    timestamp: i64,
    addr_recv: NetAddress,
    addr_from: NetAddress,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool,
}

// Function to serialize `NetAddress`
fn serialize_net_address(addr: &NetAddress) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&addr.services.to_le_bytes());
    bytes.extend_from_slice(&addr.ip.octets());
    bytes.extend_from_slice(&addr.port.to_le_bytes());

    bytes
}

// Function to serialize `VersionMessage`
fn serialize_version_msg(msg: &VersionMessage) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&msg.version.to_le_bytes());
    bytes.extend_from_slice(&msg.services.to_le_bytes());
    bytes.extend_from_slice(&msg.timestamp.to_le_bytes());
    bytes.extend_from_slice(&serialize_net_address(&msg.addr_recv));
    bytes.extend_from_slice(&serialize_net_address(&msg.addr_from));
    bytes.extend_from_slice(&msg.nonce.to_le_bytes());
    bytes.extend_from_slice(&msg.user_agent.as_bytes());
    bytes.extend_from_slice(&msg.start_height.to_le_bytes());
    bytes.push(msg.relay as u8);

    bytes
}

// Function to convert hex string to bytes
fn hex_to_bytes(hex_string: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    // refer [hex to bytes conversion](https://github.com/bitcoin-dev-project/rust-for-bitcoiners/blob/main/tutorials/de_se_rialization/hex_bytes_conversions.md)
    (0..hex_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16))
        .collect()
}

// Function to convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02X}", byte)).collect()
}

// Function to create a block request message
fn request_block_message(hash: &str) -> Vec<u8> {
    let mut message = Vec::new();

    // Count: 1 inventory entry (u32, little-endian)
    message.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    // Type: MSG_BLOCK (u32, little-endian)
    message.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);

    // Block hash (32 bytes, internal byte order)
    let hash_bytes = hex_to_bytes(hash).expect("Invalid hash");
    message.extend_from_slice(&hash_bytes);

    message
}

// Function to create a message
fn create_message(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&MAINNET_MAGIC);

    // padding command dynamically
    let mut padded_command = [0u8; 12];
    padded_command[..command.len()].copy_from_slice(command.as_bytes());
    message.extend_from_slice(&padded_command);

    message.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let checksum = sha256d::Hash::hash(&payload)[0..4].to_vec();
    message.extend_from_slice(&checksum);
    message.extend_from_slice(payload);

    message
}

// Function to check if a received message is a "verack"
// A "verack" message in the Bitcoin protocol is short for "version acknowledgement."
fn is_verack(data: &[u8]) -> bool {
    data.starts_with(&MAINNET_MAGIC) && data[4..12].starts_with(b"verack\0\0")
}

// Function to shuffle a slice of DNS seeds
fn randomize_slice<'a>(input: &'a [&'a str]) -> Vec<&'a str> {
    let mut rng = thread_rng();
    let mut vec = input.to_vec(); // Convert slice to vector
    vec.shuffle(&mut rng); // Shuffle the vector
    vec // Return the vector (or convert to a slice if needed)
}

// Function to get a valid IP from DNS seeds
async fn get_valid_ip() -> Result<(TcpStream, IpAddr), String> {
    const DNS_SEEDS: [&str; 4] = [
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "seed.bitcoinstats.com",
    ];
    // todo!("Initially test with regtest with debug=net option");
    // todo!("then test with your local full node");
    // todo!("Then choose an ip from randomly iterating over DNS_SEEDS")
    for seed in randomize_slice(&DNS_SEEDS) {
        if let Ok(ips) = lookup_host(seed) {
            for ip in ips {
                if let Ok(stream) = TcpStream::connect((ip, 8333)).await {
                    return Ok((stream, ip));
                }
            }
        }
    }
    Err("Failed to connect to any Bitcoin node".to_string())
}

// Function to read data from the stream until an error or EOF occurs
// bitcoin messages did not end with any special character
// So this function will keep reading from the stream until the read results in an error or 0
async fn till_read_succeeds(stream: &mut TcpStream, buffer: &mut Vec<u8>) {
    loop {
        let mut t = [0; 1024];
        if let Ok(n) = stream.read(&mut t).await {
            if n == 0 {
                return;
            }
            buffer.extend(t);
            tracing::info!("read {n} bytes");
        } else {
            tracing::error!("Error in read");
            return;
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        // Display the thread ID an event was recorded on
        .with_thread_ids(false)
        // Don't display the event's target (module path)
        .with_target(false)
        // Build the subscriber
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let (mut stream, ip) = get_valid_ip().await.unwrap();

    let ip6 = match ip {
        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
        IpAddr::V6(addr) => addr,
    };

    // Construct and send the version message
    let version_msg = VersionMessage {
        version: PROTOCOL_VERSION,
        services: 0,
        timestamp: Utc::now().timestamp(),
        addr_recv: NetAddress {
            services: 0,
            ip: ip6,
            port: 8333,
        },
        addr_from: NetAddress {
            services: 0,
            ip: "fe80::86fc:93aa:d18c:93ef"
                .parse::<Ipv6Addr>()
                .ok()
                .unwrap()
                .octets()
                .into(),
            port: 0,
        },
        nonce: rand::random(),
        user_agent: "/Satoshi:0.21.0/".to_string(),
        start_height: 0,
        relay: false,
    };

    let serialized_version = serialize_version_msg(&version_msg);
    tracing::info!("Received serialized_version {:?}", serialized_version);
    let version_message = create_message("version", &serialized_version);
    tracing::info!("Received version_message {:?}", version_message);
    stream.write_all(&version_message).await?;

    let mut buffer = Vec::new();
    stream.read_buf(&mut buffer).await?;
    tracing::info!("Received version message {:?}", buffer);

    // get_data_with_timeout(&mut stream, &mut buffer).await;

    buffer.clear();
    stream.read_buf(&mut buffer).await?; // Reading verack message
    tracing::info!("Received raw response: {:?}", buffer);

    if buffer.windows(12).any(|window| is_verack(window)) {
        tracing::info!("Received verack message");

        // Example block hash to request
        let block_hash = "0000000000000000000b4d0a86d3c3cdb66b3c8a5ff50e2b7d3e5b2aaf3f2e3a";
        let block_request = request_block_message(block_hash);
        let block_message = create_message("getdata", &block_request);
        stream.write_all(&block_message).await?;

        // get_data_with_timeout(&mut stream, &mut buffer).await;

        if starts_with_magic(&buffer) {
            if let Some(block_payload) = get_block_payload(&buffer) {
                tracing::info!("Received block payload of size: {}", block_payload.len());
            } else {
                tracing::error!("Block payload not found in the received message");
            }
        } else {
            tracing::error!("Received message does not start with the expected magic value");
        }
    } else {
        tracing::error!("Did not receive verack message");
    }

    Ok(())
}

// Read data with a specified timeout
// A bitcoin peer will be continuously sending you messages
// At some point you need to pause reading them and process the messages
// So this function reads till a specified timeout
async fn get_data_with_timeout(mut stream: &mut TcpStream, mut buffer: &mut Vec<u8>) {
    let timeout_duration = Duration::from_secs(10);
    let _ = timeout(
        timeout_duration,
        till_read_succeeds(&mut stream, &mut buffer),
    )
    .await;
}

// Retrieve the block payload from the received data
fn get_block_payload(buffer: &[u8]) -> Option<&[u8]> {
    // todo!("The bitcoin node will keep sending you messages like ping, inv etc.,");
    // todo!("One of them will be your required block message");
    // todo!("How will you identify that?")

    if buffer.len() < 24 {
        return None;
    }

    let mut index = 0;
    while index + 24 <= buffer.len() {
        if &buffer[index..index + 4] == &MAINNET_MAGIC
            && &buffer[index + 4..index + 10] == b"block\0"
        {
            let payload_length = u32::from_le_bytes([
                buffer[index + 16],
                buffer[index + 17],
                buffer[index + 18],
                buffer[index + 19],
            ]) as usize;
            if index + 24 + payload_length <= buffer.len() {
                return Some(&buffer[index + 24..index + 24 + payload_length]);
            }
        }
        index += 1;
    }
    None
}

// Check if the buffer starts with the magic network characters
fn starts_with_magic(buffer: &[u8]) -> bool {
    // todo!("check whether the buffer strts with magic network characters")
    buffer.starts_with(&MAINNET_MAGIC)
}
