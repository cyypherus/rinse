use crate::{InboundPacket, Interface, InterfaceError, OutboundPacket};
use std::sync::Mutex;
use tokio::net::TcpStream;

const FLAG: u8 = 0x7e;
const ESCAPE: u8 = 0x7d;

pub struct TcpHdlcInterface {
    stream: TcpStream,
    inbound: Mutex<Vec<u8>>,
}

impl TcpHdlcInterface {
    pub async fn connect(address: &str) -> std::io::Result<Self> {
        Self::new(TcpStream::connect(address).await?)
    }

    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            inbound: Mutex::new(Vec::new()),
        })
    }
}

impl Interface for TcpHdlcInterface {
    async fn receive(&self) -> Result<InboundPacket, InterfaceError> {
        loop {
            {
                let mut inbound = self.inbound.lock().unwrap();
                if let Some(start) = inbound.iter().position(|byte| *byte == FLAG)
                    && let Some(relative_end) =
                        inbound[start + 1..].iter().position(|byte| *byte == FLAG)
                {
                    let end = start + 1 + relative_end;
                    let encoded = inbound[start + 1..end].to_vec();
                    inbound.drain(..=end);
                    let mut frame = Vec::with_capacity(encoded.len());
                    let mut escaped = false;
                    for byte in encoded {
                        if escaped {
                            frame.push(byte ^ 0x20);
                            escaped = false;
                        } else if byte == ESCAPE {
                            escaped = true;
                        } else {
                            frame.push(byte);
                        }
                    }
                    if frame.len() >= 2 {
                        return Ok(InboundPacket::new(frame));
                    }
                    continue;
                }
            }
            self.stream.readable().await.map_err(InterfaceError::Io)?;
            let mut bytes = [0; 65_536];
            match self.stream.try_read(&mut bytes) {
                Ok(0) => return Err(InterfaceError::Closed),
                Ok(read) => self
                    .inbound
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(InterfaceError::Io(error)),
            }
        }
    }

    async fn send(&self, packet: OutboundPacket) -> Result<(), InterfaceError> {
        let mut frame = Vec::with_capacity(packet.len() + 2);
        frame.push(FLAG);
        for byte in packet.into_bytes() {
            if matches!(byte, FLAG | ESCAPE) {
                frame.push(ESCAPE);
                frame.push(byte ^ 0x20);
            } else {
                frame.push(byte);
            }
        }
        frame.push(FLAG);
        let mut written = 0;
        while written < frame.len() {
            self.stream.writable().await.map_err(InterfaceError::Io)?;
            match self.stream.try_write(&frame[written..]) {
                Ok(0) => return Err(InterfaceError::Closed),
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(InterfaceError::Io(error)),
            }
        }
        Ok(())
    }

    async fn close(&self) -> Result<(), InterfaceError> {
        socket2::SockRef::from(&self.stream)
            .shutdown(std::net::Shutdown::Both)
            .map_err(InterfaceError::Io)
    }
}
