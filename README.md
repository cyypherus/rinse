<div align="center">

# rinse

**A Reticulum network stack implementation in Rust**

</div>

> [!NOTE]
> `rinse` implements the core Reticulum networking primitives: nodes, links, announces, path discovery, and request/response
>
> `rinse` does not provide a CLI or daemon - it's primarily a library for building Reticulum applications

# Reticulum

Reticulum is a cryptography-based networking stack for wide-area networks built on any available medium.

The reference implementation is [Reticulum](https://github.com/markqvist/Reticulum) by Mark Qvist, with documentation at [reticulum.network](https://reticulum.network/).

# Features

- `default` - core node implementation with no transport
- `tcp` - TCP transport using HDLC framing
- `config` - TOML configuration file support
- `relay` - feature gate for the relay binary dependencies

# Usage

```rust
use rinse::config::{Config, InterfaceConfig, load_or_generate_identity};
use rinse::{Interface, Node, TcpTransport};

let config = Config::load()?;
let identity = load_or_generate_identity()?;

let mut node: Node<TcpTransport> = Node::new(config.network.relay);
let service = node.add_service("myapp", &["/ping"], &identity);

for (name, iface) in config.enabled_interfaces() {
    if let InterfaceConfig::TCPClientInterface { target_host, target_port, .. } = iface {
        let addr = format!("{}:{}", target_host, target_port);
        let transport = TcpTransport::connect(&addr).await?;
        node.add_interface(Interface::new(transport));
    }
}

node.announce(service);

tokio::spawn(node.clone().run());

while let Some(req) = node.recv_request(service).await {
    if req.path == "/ping" {
        node.respond(service, req.request_id, b"pong", None, false).await?;
    }
}
```

# Examples

- [`serve`](examples/serve.rs) - file server that serves a directory over Reticulum
- [`request`](examples/request.rs) - CLI client for making requests to Reticulum nodes
- [`page`](examples/page) - interactive micron page server with guestbook

```sh
cargo run --example serve --features config,tcp -- ./public files
cargo run --example request --features config,tcp -- <node_id> /path
cargo run --example page --features config,tcp
```

# Binaries

- [`rinse-relay`](src/bin/relay.rs) - transport node that forwards packets between interfaces, with TUI stats

```sh
cargo run --bin rinse-relay --features relay,tcp
```
