use std::{env, fs::File, io::Write};

use memmap2::Mmap;

fn main() {
    let if_sort = parse_optional_sort_flag(env::args()).unwrap();

    let file = File::open("mdf-kospi200.20110216-0.pcap").unwrap();

    let data = unsafe { Mmap::map(&file).unwrap() };

    let flag = is_big_endian(&data);

    let mut messages = Vec::with_capacity(2048);

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

    let mut buf: Vec<u8> = Vec::with_capacity(2048 * 100);

    for msg in messages {
        msg.write_bytes(&mut buf);
    }

    std::io::stdout().lock().write_all(&buf).unwrap();
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

impl Message<'_> {
    pub fn write_bytes(&self, buf: &mut Vec<u8>) {
        let hh = (self.acc_time / 1_000_000) as u8;
        let mm = ((self.acc_time / 10_000) % 100) as u8;
        let ss = ((self.acc_time / 100) % 100) as u8;
        let uu = (self.acc_time % 100) as u8;

        write_int(buf, self.pkt_time);
        buf.push(b' ');
        write_2digits(buf, hh);
        buf.push(b':');
        write_2digits(buf, mm);
        buf.push(b':');
        write_2digits(buf, ss);
        buf.push(b':');
        write_2digits(buf, uu);
        buf.push(b' ');
        buf.extend_from_slice(self.issue_code.as_bytes());
        buf.push(b' ');
        write_float(buf, self.bqty5, 1);
        buf.push(b'@');
        write_float(buf, self.bprice5, 1);
        buf.push(b' ');
        write_float(buf, self.bqty4, 1);
        buf.push(b'@');
        write_float(buf, self.bprice4, 1);
        buf.push(b' ');
        write_float(buf, self.bqty3, 1);
        buf.push(b'@');
        write_float(buf, self.bprice3, 1);
        buf.push(b' ');
        write_float(buf, self.bqty2, 1);
        buf.push(b'@');
        write_float(buf, self.bprice2, 1);
        buf.push(b' ');
        write_float(buf, self.bqty1, 1);
        buf.push(b'@');
        write_float(buf, self.bprice1, 1);
        buf.push(b' ');
        write_float(buf, self.aqty1, 1);
        buf.push(b'@');
        write_float(buf, self.aprice1, 1);
        buf.push(b' ');
        write_float(buf, self.aqty2, 1);
        buf.push(b'@');
        write_float(buf, self.aprice2, 1);
        buf.push(b' ');
        write_float(buf, self.aqty3, 1);
        buf.push(b'@');
        write_float(buf, self.aprice3, 1);
        buf.push(b' ');
        write_float(buf, self.aqty4, 1);
        buf.push(b'@');
        write_float(buf, self.aprice4, 1);
        buf.push(b' ');
        write_float(buf, self.aqty5, 1);
        buf.push(b'@');
        write_float(buf, self.aprice5, 1);
        buf.push(b'\n');
    }
}

#[inline]
fn write_2digits(buf: &mut Vec<u8>, n: u8) {
    buf.push(b'0' + n / 10);
    buf.push(b'0' + n % 10);
}

fn write_int(buf: &mut Vec<u8>, mut n: u32) {
    let mut tmp = [0u8; 10]; // u32::MAX is 10 digits
    let mut pos = 10;
    if n == 0 {
        buf.push(b'0');
        return;
    }
    while n > 0 {
        pos -= 1;
        tmp[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    buf.extend_from_slice(&tmp[pos..]);
}

fn write_float(buf: &mut Vec<u8>, n: f64, decimal_places: usize) {
    if n < 0.0 {
        buf.push(b'-');
    }
    let n = n.abs();
    let int_part = n as u32;
    let frac_part = n - int_part as f64;

    write_int(buf, int_part);

    if decimal_places > 0 {
        buf.push(b'.');
        // shift fractional part into an integer
        let scale = 10u64.pow(decimal_places as u32);
        let frac_digits = (frac_part * scale as f64).round() as u64;
        // must zero-pad — e.g. 0.05 → frac_digits=5, needs "05" not "5"
        let mut tmp = [0u8; 20];
        let mut pos = decimal_places;
        let mut f = frac_digits;
        while pos > 0 {
            pos -= 1;
            tmp[pos] = b'0' + (f % 10) as u8;
            f /= 10;
        }
        buf.extend_from_slice(&tmp[..decimal_places]);
    }
}

fn parse_message<'a>(msg: &'a [u8], pkt_time: u32) -> Result<Message<'a>, ParseError> {
    let msg = &msg[42..];

    let acc_time = parse_hhmmssuu((&msg[206..214]).try_into().unwrap());
    let issue_code = unsafe { str::from_utf8_unchecked(&msg[5..17]) };
    let bqty5 = unsafe { str::from_utf8_unchecked(&msg[82..89]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice5 = unsafe { str::from_utf8_unchecked(&msg[77..82]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty4 = unsafe { str::from_utf8_unchecked(&msg[70..77]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice4 = unsafe { str::from_utf8_unchecked(&msg[65..70]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty3 = unsafe { str::from_utf8_unchecked(&msg[58..65]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice3 = unsafe { str::from_utf8_unchecked(&msg[53..58]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty2 = unsafe { str::from_utf8_unchecked(&msg[46..53]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice2 = unsafe { str::from_utf8_unchecked(&msg[41..46]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bqty1 = unsafe { str::from_utf8_unchecked(&msg[34..41]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let bprice1 = unsafe { str::from_utf8_unchecked(&msg[29..34]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty5 = unsafe { str::from_utf8_unchecked(&msg[149..156]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice5 = unsafe { str::from_utf8_unchecked(&msg[144..149]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty4 = unsafe { str::from_utf8_unchecked(&msg[137..144]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice4 = unsafe { str::from_utf8_unchecked(&msg[132..137]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty3 = unsafe { str::from_utf8_unchecked(&msg[125..132]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice3 = unsafe { str::from_utf8_unchecked(&msg[120..125]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty2 = unsafe { str::from_utf8_unchecked(&msg[113..120]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice2 = unsafe { str::from_utf8_unchecked(&msg[108..113]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aqty1 = unsafe { str::from_utf8_unchecked(&msg[101..108]) }
        .parse::<f64>()
        .map_err(|_| ParseError::InvalidNumber)?;

    let aprice1 = unsafe { str::from_utf8_unchecked(&msg[96..101]) }
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
