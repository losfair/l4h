//! l4h-mk.conf: how the machine is split (DESIGN.md §11.3), `key = value`
//! lines like l4h.conf:
//!
//! ```text
//! partitions = 2               # 1..8
//! p0.cpus = node:0             # or: 4 (a count), 0-15 (CPU numbers), apic:0,2,4
//! p0.mem  = 60G                # or M; partition 0 takes the rest by default
//! p1.pci  = 0000:80:04.0, 0000:80:05.0
//! link.p0-p1 = 1               # a virtual wire between the two netds
//! ```

use l4h_partition::MAX_PARTITIONS;

use crate::io::Vec;
use crate::pci::parse_bdf;

#[derive(Clone, Copy)]
pub enum Cpus {
    Default,
    Count(u32),
    /// CPU numbers, in MADT order: [first, last].
    Range(u32, u32),
    Node(u32),
    Apic(Vec<u32, 256>),
}

#[derive(Clone, Copy)]
pub struct Part {
    pub cpus: Cpus,
    pub mem: Option<u64>,
    pub pci: Vec<u16, 64>,
}

pub struct Conf {
    pub partitions: usize,
    pub parts: [Part; MAX_PARTITIONS],
    pub links: Vec<(u8, u8), 32>,
}

fn bad(line: &str) -> ! {
    crate::fail(format_args!("l4h-mk.conf: cannot use '{}'", line))
}

fn size(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, shift) = match v.as_bytes().last()? {
        b'G' | b'g' => (&v[..v.len() - 1], 30),
        b'M' | b'm' => (&v[..v.len() - 1], 20),
        b'T' | b't' => (&v[..v.len() - 1], 40),
        _ => (v, 0),
    };
    num.trim().parse::<u64>().ok().map(|n| n << shift)
}

fn part_index(s: &str) -> Option<usize> {
    let n = s.strip_prefix('p')?.parse::<usize>().ok()?;
    (n < MAX_PARTITIONS).then_some(n)
}

impl Conf {
    pub fn parse(text: &[u8]) -> Conf {
        let text = core::str::from_utf8(text).unwrap_or_else(|_| crate::fail(format_args!("l4h-mk.conf is not text")));
        let none = Part { cpus: Cpus::Default, mem: None, pci: Vec::new() };
        let mut c = Conf { partitions: 1, parts: [none; MAX_PARTITIONS], links: Vec::new() };
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else { bad(line) };
            let (key, value) = (key.trim(), value.trim());
            if key == "partitions" {
                c.partitions = match value.parse::<usize>() {
                    Ok(n) if (1..=MAX_PARTITIONS).contains(&n) => n,
                    _ => bad(line),
                };
                continue;
            }
            if let Some(l) = key.strip_prefix("link.") {
                let Some((a, b)) = l.split_once('-') else { bad(line) };
                let (Some(a), Some(b)) = (part_index(a), part_index(b)) else { bad(line) };
                if a == b {
                    bad(line);
                }
                if value == "1" {
                    c.links.must_push((a.min(b) as u8, a.max(b) as u8));
                }
                continue;
            }
            let Some((p, field)) = key.split_once('.') else { bad(line) };
            let Some(k) = part_index(p) else { bad(line) };
            let part = &mut c.parts[k];
            match field {
                "cpus" => {
                    part.cpus = if let Some(n) = value.strip_prefix("node:") {
                        Cpus::Node(n.trim().parse().unwrap_or_else(|_| bad(line)))
                    } else if let Some(list) = value.strip_prefix("apic:") {
                        let mut v = Vec::new();
                        for a in list.split(',') {
                            v.must_push(a.trim().parse().unwrap_or_else(|_| bad(line)));
                        }
                        Cpus::Apic(v)
                    } else if let Some((a, b)) = value.split_once('-') {
                        let (a, b) = (a.trim().parse().unwrap_or_else(|_| bad(line)), b.trim().parse().unwrap_or_else(|_| bad(line)));
                        if a > b {
                            bad(line);
                        }
                        Cpus::Range(a, b)
                    } else {
                        Cpus::Count(value.parse().unwrap_or_else(|_| bad(line)))
                    }
                }
                "mem" => part.mem = Some(size(value).unwrap_or_else(|| bad(line))),
                "pci" => {
                    for b in value.split(',').filter(|s| !s.trim().is_empty()) {
                        part.pci.must_push(parse_bdf(b).unwrap_or_else(|| bad(line)));
                    }
                }
                _ => bad(line),
            }
        }
        for &(a, b) in c.links.iter() {
            if b as usize >= c.partitions {
                crate::fail(format_args!("l4h-mk.conf: link p{}-p{} names a partition beyond {}", a, b, c.partitions));
            }
        }
        c
    }
}
