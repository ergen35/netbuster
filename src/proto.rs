//! Protocole entre la fenêtre (utilisateur normal) et l'assistant administrateur.
//!
//! Commandes : une ligne JSON par commande sur l'entrée standard de l'assistant.
//! Réponses : trames binaires sur sa sortie standard `[tag u8][len u32 LE][données]`.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const TAG_PACKET: u8 = 1;
pub const TAG_REPLY: u8 = 2;
pub const TAG_EVENT: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Cmd {
    Exec { id: u64, prog: String, args: Vec<String> },
    WriteFile { id: u64, path: String, content: String },
    StartCapture { snap: u32 },
    StopCapture,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reply {
    pub id: u64,
    pub ok: bool,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    Hello { uid: u32 },
    CaptureStarted,
    CaptureStopped,
    CaptureError(String),
    CaptureStats { packets: u64, drops: u64 },
}

/// Paquet brut sorti du noyau. Sans en-tête de liaison : `proto` donne le type (0x0800, 0x86dd…).
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub ts_us: u64,
    pub ifindex: u32,
    pub pkttype: u8,
    pub proto: u16,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

const RAW_HEADER: usize = 8 + 4 + 1 + 2 + 4;

impl RawFrame {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ts_us.to_le_bytes());
        out.extend_from_slice(&self.ifindex.to_le_bytes());
        out.push(self.pkttype);
        out.extend_from_slice(&self.proto.to_le_bytes());
        out.extend_from_slice(&self.orig_len.to_le_bytes());
        out.extend_from_slice(&self.data);
    }

    pub fn decode(buf: &[u8]) -> Option<RawFrame> {
        if buf.len() < RAW_HEADER {
            return None;
        }
        Some(RawFrame {
            ts_us: u64::from_le_bytes(buf[0..8].try_into().ok()?),
            ifindex: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            pkttype: buf[12],
            proto: u16::from_le_bytes(buf[13..15].try_into().ok()?),
            orig_len: u32::from_le_bytes(buf[15..19].try_into().ok()?),
            data: buf[RAW_HEADER..].to_vec(),
        })
    }
}

pub fn write_frame<W: Write>(w: &mut W, tag: u8, payload: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)
}

/// Lit une trame. `Ok(None)` à la fin du flux.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trame trop grande"));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(Some((head[0], data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = RawFrame { ts_us: 42, ifindex: 3, pkttype: 4, proto: 0x0800, orig_len: 1500, data: vec![1, 2, 3] };
        let mut payload = vec![];
        f.encode(&mut payload);
        let mut wire = vec![];
        write_frame(&mut wire, TAG_PACKET, &payload).unwrap();
        let mut cur = std::io::Cursor::new(wire);
        let (tag, data) = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(tag, TAG_PACKET);
        let back = RawFrame::decode(&data).unwrap();
        assert_eq!(back.ifindex, 3);
        assert_eq!(back.proto, 0x0800);
        assert_eq!(back.orig_len, 1500);
        assert_eq!(back.data, vec![1, 2, 3]);
        assert!(read_frame(&mut cur).unwrap().is_none());
    }
}
