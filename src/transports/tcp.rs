use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::Transport;

pub(crate) const HDLC_FLAG: u8 = 0x7E;
pub(crate) const HDLC_ESC: u8 = 0x7D;
pub(crate) const HDLC_ESC_MASK: u8 = 0x20;

pub(crate) fn hdlc_escape(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        if byte == HDLC_ESC || byte == HDLC_FLAG {
            result.push(HDLC_ESC);
            result.push(byte ^ HDLC_ESC_MASK);
        } else {
            result.push(byte);
        }
    }
    result
}

pub(crate) fn hdlc_unescape(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut escape = false;
    for &byte in data {
        if escape {
            result.push(byte ^ HDLC_ESC_MASK);
            escape = false;
        } else if byte == HDLC_ESC {
            escape = true;
        } else {
            result.push(byte);
        }
    }
    result
}

pub struct TcpTransport {
    stream: TcpStream,
    inbox: VecDeque<Vec<u8>>,
    frame_buffer: Vec<u8>,
    connected: bool,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            inbox: VecDeque::new(),
            frame_buffer: Vec::new(),
            connected: true,
        })
    }

    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Self::new(stream)
    }

    fn read_available(&mut self) {
        let mut buf = [0u8; 4096];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    self.connected = false;
                    break;
                }
                Ok(n) => {
                    self.frame_buffer.extend_from_slice(&buf[..n]);
                    self.process_frames();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.connected = false;
                    break;
                }
            }
        }
    }

    fn process_frames(&mut self) {
        loop {
            let Some(start) = self.frame_buffer.iter().position(|&b| b == HDLC_FLAG) else {
                break;
            };

            let Some(end) = self.frame_buffer[start + 1..]
                .iter()
                .position(|&b| b == HDLC_FLAG)
                .map(|p| p + start + 1)
            else {
                break;
            };

            let frame_data = &self.frame_buffer[start + 1..end];
            if !frame_data.is_empty() {
                let unescaped = hdlc_unescape(frame_data);
                if unescaped.len() >= 2 {
                    self.inbox.push_back(unescaped);
                }
            }

            self.frame_buffer = self.frame_buffer[end..].to_vec();
        }
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, data: &[u8]) {
        let escaped = hdlc_escape(data);
        let mut frame = Vec::with_capacity(escaped.len() + 2);
        frame.push(HDLC_FLAG);
        frame.extend(escaped);
        frame.push(HDLC_FLAG);

        if self.stream.write_all(&frame).is_err() || self.stream.flush().is_err() {
            self.connected = false;
        }
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        self.read_available();
        self.inbox.pop_front()
    }

    fn bandwidth_available(&self) -> bool {
        true
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdlc_roundtrip() {
        let data = vec![0x00, 0x7E, 0x7D, 0xFF, 0x01];
        let escaped = hdlc_escape(&data);
        let unescaped = hdlc_unescape(&escaped);
        assert_eq!(data, unescaped);
    }

    #[test]
    fn hdlc_escape_flag() {
        let data = vec![HDLC_FLAG];
        let escaped = hdlc_escape(&data);
        assert_eq!(escaped, vec![HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK]);
    }

    #[test]
    fn hdlc_escape_esc() {
        let data = vec![HDLC_ESC];
        let escaped = hdlc_escape(&data);
        assert_eq!(escaped, vec![HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK]);
    }
}
