use std::{env, fmt::Display, fs};

fn main() {
    let if_sort = parse_optional_sort_flag(env::args()).unwrap();

    let data = fs::read("mdf-kospi200.20110216-0.pcap").unwrap();

    let flag = is_big_endian(&data);

    let mut messages: Vec<Message<'_>> = Vec::with_capacity(2048);

    // Global header size
    let mut offset = 24;

    while offset + 16 <= data.len() {
        let packet_header = parse_packet_header(&data[offset..offset + 16], flag);

        // Ignore the packet header bytes
        offset += 16;

        if packet_header.len == 257 {
            // Select the bytes to be parser
            let dd = &data[offset..offset + packet_header.len as usize];

            let message = parse_message(dd, packet_header.ts_sec).unwrap();
            messages.push(message);

            // Update the offset to handle next packet
            offset += packet_header.len as usize;
        } else {
            // Ignore the packet bytes of irrelevant data
            offset += packet_header.len as usize;
        }
    }

    if if_sort {
        messages.sort_unstable_by(|a, b| {
            a.acc_time
                .partial_cmp(&b.acc_time)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    for m in messages {
        print!("{}\n", m)
    }
}

#[allow(unused)]
#[derive(Debug)]
struct Message<'a> {
    pkt_time: u32,
    acc_time: u32,
    issue_code: &'a str,
    bqty5: f64,
    bprice5: f64,
    bqty4: f64,
    bprice4: f64,
    bqty3: f64,
    bprice3: f64,
    bqty2: f64,
    bprice2: f64,
    bqty1: f64,
    bprice1: f64,
    aqty1: f64,
    aprice1: f64,
    aqty2: f64,
    aprice2: f64,
    aqty3: f64,
    aprice3: f64,
    aqty4: f64,
    aprice4: f64,
    aqty5: f64,
    aprice5: f64,
}

impl Display for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}@{} {}@{}",
            self.pkt_time,
            format_time(self.acc_time),
            self.issue_code,
            self.bqty5,
            self.bprice5,
            self.bqty4,
            self.bprice4
        )
    }
}

fn format_time(n: u32) -> String {
    let hh = n / 1_000_000;
    let mm = (n / 10_000) % 100;
    let ss = (n / 100) % 100;
    let uu = n % 100;

    format!("{:02}:{:02}:{:02}:{:02}", hh, mm, ss, uu)
}

fn parse_message<'a>(msg: &'a [u8], pkt_time: u32) -> Result<Message<'a>, ParseError> {
    let msg = &msg[42..];

    let acc_time = parse_hhmmssuu((&msg[206..214]).try_into().unwrap());
    let issue_code = str::from_utf8(&msg[5..17]).map_err(|_| ParseError::InvalidUtf8)?;
    let bqty5 = str::from_utf8(&msg[82..89])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice5 = str::from_utf8(&msg[77..82])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty4 = str::from_utf8(&msg[70..77])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice4 = str::from_utf8(&msg[65..70])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty3 = str::from_utf8(&msg[58..65])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice3 = str::from_utf8(&msg[53..58])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty2 = str::from_utf8(&msg[46..53])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice2 = str::from_utf8(&msg[41..46])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty1 = str::from_utf8(&msg[34..41])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice1 = str::from_utf8(&msg[29..34])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty5 = str::from_utf8(&msg[149..156])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice5 = str::from_utf8(&msg[144..149])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty4 = str::from_utf8(&msg[137..144])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice4 = str::from_utf8(&msg[132..137])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty3 = str::from_utf8(&msg[125..132])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice3 = str::from_utf8(&msg[120..125])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty2 = str::from_utf8(&msg[113..120])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice2 = str::from_utf8(&msg[108..113])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty1 = str::from_utf8(&msg[101..108])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice1 = str::from_utf8(&msg[96..101])
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim()
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    Ok(Message {
        pkt_time,
        acc_time,
        issue_code,
        bqty5,
        bprice5,
        bqty4,
        bprice4,
        bqty3,
        bprice3,
        bqty2,
        bprice2,
        bqty1,
        bprice1,
        aqty1,
        aprice1,
        aqty2,
        aprice2,
        aqty3,
        aprice3,
        aqty4,
        aprice4,
        aqty5,
        aprice5,
    })
}

#[allow(unused)]
#[derive(Debug)]
enum ParseError {
    UnexpectedLength(usize),
    InvalidUtf8,
    InvalidNumber,
}

fn is_big_endian(data: &[u8]) -> bool {
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());

    match magic {
        0xA1B2C3D4 => true,
        _ => panic!("Unknown magic number: 0x{:08x}", magic),
    }
}

fn parse_packet_header(data: &[u8], big_endian: bool) -> PacketHeader {
    match big_endian {
        false => PacketHeader {
            ts_sec: read_u32_be(&data[..4]),
            len: read_u32_be(&data[12..]),
        },
        true => PacketHeader {
            ts_sec: read_u32_le(&data[..4]),
            len: read_u32_le(&data[12..]),
        },
    }
}

pub struct PacketHeader {
    pub ts_sec: u32,
    pub len: u32,
}

fn read_u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes(data.try_into().unwrap())
}

fn read_u32_be(data: &[u8]) -> u32 {
    u32::from_be_bytes(data.try_into().unwrap())
}

fn parse_optional_sort_flag(mut args: env::Args) -> Result<bool, &'static str> {
    args.next();

    match args.next() {
        Some(sort_param) if sort_param == "-r" => Ok(true),
        Some(_) => {
            Err("Unknown argument. Only `-r` allowed for sorting packets by quote accept time")
        }
        None => Ok(false),
    }
}

fn parse_hhmmssuu(bytes: &[u8; 8]) -> u32 {
    let mut n = 0u32;
    for &b in bytes {
        n = n * 10 + (b - b'0') as u32;
    }
    n
}
