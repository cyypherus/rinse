use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, NodeAddr, NodeId, SecretKey};
use tokio::sync::mpsc;

use crate::Transport;

pub const ALPN: &[u8] = b"rinse/1";

#[derive(Debug)]
pub enum IrohError {
    Endpoint(String),
    Connection(String),
    Closed,
}

impl std::fmt::Display for IrohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrohError::Endpoint(e) => write!(f, "endpoint error: {}", e),
            IrohError::Connection(e) => write!(f, "connection error: {}", e),
            IrohError::Closed => write!(f, "endpoint closed"),
        }
    }
}

impl std::error::Error for IrohError {}

type Inbox = Arc<Mutex<VecDeque<Vec<u8>>>>;
type Outbox = Arc<Mutex<VecDeque<Vec<u8>>>>;

pub struct IrohTransport {
    peer_id: NodeId,
    inbox: Inbox,
    outbox: Outbox,
    connected: Arc<AtomicBool>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl IrohTransport {
    pub fn peer_id(&self) -> NodeId {
        self.peer_id
    }

    pub(crate) fn from_connection(peer_id: NodeId, conn: Connection) -> Self {
        let inbox: Inbox = Arc::new(Mutex::new(VecDeque::new()));
        let outbox: Outbox = Arc::new(Mutex::new(VecDeque::new()));
        let connected = Arc::new(AtomicBool::new(true));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        tokio::spawn(connection_task(
            conn,
            inbox.clone(),
            outbox.clone(),
            connected.clone(),
            shutdown_rx,
        ));

        Self {
            peer_id,
            inbox,
            outbox,
            connected,
            shutdown_tx: Some(shutdown_tx),
        }
    }
}

impl Drop for IrohTransport {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }
}

impl Transport for IrohTransport {
    fn send(&mut self, data: &[u8]) {
        self.outbox.lock().unwrap().push_back(data.to_vec());
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbox.lock().unwrap().pop_front()
    }

    fn bandwidth_available(&self) -> bool {
        true
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }
}

async fn connection_task(
    conn: Connection,
    inbox: Inbox,
    outbox: Outbox,
    connected: Arc<AtomicBool>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let (send, recv) = match conn.open_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            log::warn!("Failed to open bidirectional stream: {}", e);
            connected.store(false, Ordering::SeqCst);
            return;
        }
    };

    let inbox_clone = inbox.clone();
    let read_task = read_loop(recv, inbox_clone);

    let write_task = write_loop(send, outbox);

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
        _ = shutdown_rx.recv() => {}
        _ = conn.closed() => {}
    }

    connected.store(false, Ordering::SeqCst);
}

async fn read_loop(mut recv: RecvStream, inbox: Inbox) {
    let mut len_buf = [0u8; 4];

    loop {
        if let Err(e) = recv.read_exact(&mut len_buf).await {
            log::debug!("Iroh read error (length): {}", e);
            break;
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            log::warn!("Iroh: received oversized frame ({})", len);
            break;
        }

        let mut data = vec![0u8; len];
        if let Err(e) = recv.read_exact(&mut data).await {
            log::debug!("Iroh read error (data): {}", e);
            break;
        }

        inbox.lock().unwrap().push_back(data);
    }
}

async fn write_loop(mut send: SendStream, outbox: Outbox) {
    let mut interval = tokio::time::interval(Duration::from_micros(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let packets: Vec<Vec<u8>> = outbox.lock().unwrap().drain(..).collect();
        for data in packets {
            let len = (data.len() as u32).to_be_bytes();
            if send.write_all(&len).await.is_err() {
                return;
            }
            if send.write_all(&data).await.is_err() {
                return;
            }
        }
    }
}

pub struct IrohNode {
    endpoint: Endpoint,
    secret_key: SecretKey,
}

impl IrohNode {
    pub async fn new() -> Result<Self, IrohError> {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        Self::with_secret_key(secret_key).await
    }

    pub async fn with_secret_key(secret_key: SecretKey) -> Result<Self, IrohError> {
        let endpoint = Endpoint::builder()
            .secret_key(secret_key.clone())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| IrohError::Endpoint(e.to_string()))?;

        log::info!("Iroh node started: {}", endpoint.node_id());

        Ok(Self {
            endpoint,
            secret_key,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub async fn node_addr(&self) -> Result<NodeAddr, IrohError> {
        self.endpoint
            .node_addr()
            .await
            .map_err(|e| IrohError::Endpoint(e.to_string()))
    }

    pub async fn connect(&self, addr: NodeAddr) -> Result<IrohTransport, IrohError> {
        let peer_id = addr.node_id;
        log::info!("Connecting to Iroh peer: {}", peer_id);

        let conn = self
            .endpoint
            .connect(addr, ALPN)
            .await
            .map_err(|e| IrohError::Connection(e.to_string()))?;
        log::info!("Connected to Iroh peer: {}", peer_id);

        Ok(IrohTransport::from_connection(peer_id, conn))
    }

    pub async fn accept(&self) -> Result<IrohTransport, IrohError> {
        let conn = self
            .endpoint
            .accept()
            .await
            .ok_or(IrohError::Closed)?
            .await
            .map_err(|e| IrohError::Connection(e.to_string()))?;

        let peer_id = conn
            .remote_node_id()
            .map_err(|e| IrohError::Connection(e.to_string()))?;
        log::info!("Accepted Iroh connection from: {}", peer_id);

        Ok(IrohTransport::from_connection(peer_id, conn))
    }

    pub fn spawn_accept_loop<F>(&self, mut on_accept: F)
    where
        F: FnMut(IrohTransport) + Send + 'static,
    {
        let endpoint = self.endpoint.clone();

        tokio::spawn(async move {
            loop {
                let incoming: iroh::endpoint::Incoming = match endpoint.accept().await {
                    Some(i) => i,
                    None => break,
                };

                match incoming.await {
                    Ok(conn) => {
                        let peer_id = match conn.remote_node_id() {
                            Ok(id) => id,
                            Err(e) => {
                                log::warn!("Failed to get peer ID: {}", e);
                                continue;
                            }
                        };
                        log::info!("Accepted Iroh connection from: {}", peer_id);
                        let transport = IrohTransport::from_connection(peer_id, conn);
                        on_accept(transport);
                    }
                    Err(e) => {
                        log::warn!("Failed to accept connection: {}", e);
                    }
                }
            }
        });
    }

    pub async fn close(self) {
        self.endpoint.close().await;
    }
}
