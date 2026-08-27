#![cfg(feature = "tcp")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

use rinse::{
    BufferChunk, ChannelMessage, ChannelReceive, Destination, InterfaceLimits, MessageType,
    NodeBuilder, NodeConfig, ServiceConfig, ServiceName, StreamId, TcpHdlcInterface as TcpHdlc,
};

const PYTHON_NODE: &str = r#"
import sys
import threading
import time
import RNS
import RNS.Buffer

class BytesMessage(RNS.MessageBase):
    MSGTYPE = 0x0101
    def __init__(self, data=b""):
        self.data = data
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

done = threading.Event()
channel_received = False
buffer_received = False
reader = None
writer = None

def check_done():
    if channel_received and buffer_received:
        done.set()

def buffer_ready(_):
    global buffer_received
    data = reader.read()
    if data == b"rust-buffer":
        buffer_received = True
        check_done()

def finish_writer():
    timeout = time.time() + 2
    while not channel.is_ready_to_send() and time.time() < timeout:
        time.sleep(0.01)
    writer.close()
    check_done()

def message_received(message):
    global channel_received
    if isinstance(message, BytesMessage) and message.data == b"rust-channel":
        channel_received = True
        channel.send(BytesMessage(b"python-channel"))
        writer.write(b"python-buffer")
        writer.flush()
        threading.Thread(target=finish_writer, daemon=True).start()
        return True
    return False

def connected(link):
    global channel, reader, writer
    channel = link.get_channel()
    channel.register_message_type(BytesMessage)
    reader = RNS.Buffer.create_reader(7, channel, buffer_ready)
    writer = RNS.Buffer.create_writer(8, channel)
    channel.add_message_handler(message_received)

rns = RNS.Reticulum(sys.argv[1])
identity = RNS.Identity()
destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "rinseinterop", "channel")
destination.set_link_established_callback(connected)
print(destination.hexhash, flush=True)

def announce():
    while not done.is_set():
        destination.announce()
        time.sleep(0.25)

threading.Thread(target=announce, daemon=True).start()
if done.wait(20):
    print("PYTHON_RECEIVED", flush=True)
    time.sleep(2)
else:
    print("PYTHON_TIMEOUT", flush=True)
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn python_and_rust_exchange_channels_and_buffers() {
    let _ = env_logger::builder().is_test(true).try_init();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let reference = root.join("ref/Reticulum");
    assert!(reference.join("RNS").is_dir());

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let temp = std::env::temp_dir().join(format!("rinse-python-{}", std::process::id()));
    let config_dir = temp.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let mut config = std::fs::File::create(config_dir.join("config")).unwrap();
    write!(
        config,
        "[reticulum]\n  enable_transport = no\n  share_instance = no\n  panic_on_interface_error = yes\n\n[logging]\n  loglevel = 2\n\n[interfaces]\n  [[TCP Server]]\n    type = TCPServerInterface\n    enabled = yes\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n"
    )
    .unwrap();
    let script = temp.join("node.py");
    std::fs::write(&script, PYTHON_NODE).unwrap();

    let mut child = Command::new("python3")
        .arg(&script)
        .arg(&config_dir)
        .env("PYTHONPATH", &reference)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            eprintln!("python: {line}");
            let _ = line_tx.send(line);
        }
    });
    let destination = loop {
        let line = line_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        if line.len() == 32 && line.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            break line;
        }
    };
    let destination: [u8; 16] = hex::decode(destination.trim()).unwrap().try_into().unwrap();

    let interface = TcpHdlc::connect(&format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let builder = NodeBuilder::new(NodeConfig::endpoint()).interface(
        interface,
        InterfaceLimits::new(2048, 256, 1_048_576).unwrap(),
    );
    let (node, runtime) = builder.build().unwrap();
    let run = tokio::spawn(runtime.run());
    let identity = node.generate_identity().await.unwrap();
    let service = node
        .register_service(
            ServiceConfig::new(
                ServiceName::new("rinseinterop.client").unwrap(),
                identity,
                [],
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let link = tokio::time::timeout(
        Duration::from_secs(10),
        node.open_link(Destination::from_bytes(destination)),
    )
    .await
    .unwrap()
    .unwrap();
    let mut channel = link.send_handle().open_channel().await.unwrap();
    let sender = channel.send_handle();
    sender
        .send(
            ChannelMessage::new(
                MessageType::new(0x0101).unwrap(),
                bytes::Bytes::from_static(b"rust-channel"),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut buffer = sender.open_buffer(StreamId::new(7).unwrap()).await.unwrap();
    assert_eq!(
        buffer
            .write(bytes::Bytes::from_static(b"rust-buffer"))
            .await
            .unwrap(),
        11
    );
    assert_eq!(buffer.finish(bytes::Bytes::new()).await.unwrap(), 0);

    let mut message_received = false;
    let mut buffer_received = Vec::new();
    while !message_received || buffer_received != b"python-buffer" {
        match tokio::time::timeout(Duration::from_secs(10), channel.receive())
            .await
            .unwrap()
            .unwrap()
        {
            ChannelReceive::Message(message) => {
                assert_eq!(message.message_type().get(), 0x0101);
                assert_eq!(message.body(), b"python-channel");
                message_received = true;
            }
            ChannelReceive::Buffer { stream, chunk } => {
                assert_eq!(stream, StreamId::new(8).unwrap());
                match chunk {
                    BufferChunk::Data(data) | BufferChunk::End(data) => {
                        buffer_received.extend_from_slice(&data);
                    }
                }
            }
        }
    }
    assert_eq!(service.destination().as_bytes().len(), 16);

    let python_result = tokio::task::spawn_blocking(move || {
        loop {
            let line = line_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            if line == "PYTHON_RECEIVED" || line == "PYTHON_TIMEOUT" {
                break line;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(python_result, "PYTHON_RECEIVED");

    let report = tokio::time::timeout(Duration::from_secs(10), node.shutdown())
        .await
        .unwrap();
    assert_eq!(run.await.unwrap().unwrap(), report);
    tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(temp);
}
