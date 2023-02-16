use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use async_trait::async_trait;
use russh::server::{Msg, Session};
use russh::*;
use russh_keys::*;
use tokio::sync::Mutex;

use clap::Parser;

/// Simple SSH server written in Rust.
///
/// Based on the `echoserver` example:
///
/// - <https://github.com/warp-tech/russh/blob/v0.34.0/russh/examples/echoserver.rs>
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to bind to.
    ///
    /// Overrides the value from the config file.
    #[arg(short, long)]
    address: Option<String>,

    /// Port number to listen on.
    ///
    /// Overrides the value from the config file.
    #[arg(short, long)]
    port: Option<u16>,

    /// Path to configuration file.
    #[arg(short, long, default_value = "russh-server.toml")]
    config_file: PathBuf,
}

fn default_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    22
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    /// Use a fixed host key.
    ///
    /// This is a serialized ed25519 key pair from the `ed25519-dalek` crate. See
    /// <https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/struct.Keypair.html> for details.
    host_key: Option<PathBuf>,

    /// Address to bind to.
    #[serde(default = "default_address")]
    address: String,

    /// Port number to listen on.
    #[serde(default = "default_port")]
    port: u16,

    // User configuration.
    users: HashMap<String, UserConfig>,
}

#[derive(Debug, Deserialize)]
struct UserConfig {
    password: Option<String>,

    #[serde(default)]
    keys: Vec<String>,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let args = Args::parse();
    let config_file: ConfigFile =
        toml::from_str(&std::fs::read_to_string(args.config_file).unwrap()).unwrap();

    let host_key = if let Some(path) = &config_file.host_key {
        log::debug!("Reading host key from {}...", path.display());
        let mut f = File::open(path).unwrap();
        let mut buffer: [u8; 64] = [0; 64];
        f.read_exact(&mut buffer).unwrap();
        let kp = ed25519_dalek::Keypair::from_bytes(&buffer).unwrap();
        russh_keys::key::KeyPair::Ed25519(kp)
    } else {
        log::debug!("Generating new host key...");
        russh_keys::key::KeyPair::generate_ed25519().unwrap()
    };

    let config = Arc::new(russh::server::Config {
        connection_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        users: Arc::new(config_file.users),
        id: 0,
    };

    let address = args.address.unwrap_or(config_file.address);
    let port = args.port.unwrap_or(config_file.port);
    log::info!("Listening on {}:{}...", address, port);
    russh::server::run(config, (address, port), sh)
        .await
        .unwrap();
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), russh::server::Handle>>>,
    users: Arc<HashMap<String, UserConfig>>,
    id: usize,
}

impl Server {
    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for ((id, channel), ref mut s) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
}

#[async_trait]
impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn channel_open_session(
        self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert((self.id, channel.id()), session.handle());
        }
        Ok((self, true, session))
    }

    async fn auth_password(
        self,
        user: &str,
        password: &str,
    ) -> Result<(Self, server::Auth), Self::Error> {
        let result = self
            .users
            .get(user)
            .and_then(|userconfig| userconfig.password.as_ref())
            .filter(|pw| pw == &password)
            .map(|_| server::Auth::Accept)
            .unwrap_or_else(|| server::Auth::Reject {
                proceed_with_methods: Some(MethodSet::all()),
            });
        Ok((self, result))
    }

    async fn auth_publickey(
        self,
        user: &str,
        k: &key::PublicKey,
    ) -> Result<(Self, server::Auth), Self::Error> {
        let result = self
            .users
            .get(user)
            .filter(|userconfig| userconfig.keys.contains(&k.fingerprint()))
            .map(|_| server::Auth::Accept)
            .unwrap_or_else(|| server::Auth::Reject {
                proceed_with_methods: Some(MethodSet::all()),
            });
        Ok((self, result))
    }

    async fn data(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        let data = CryptoVec::from(format!("Got data: {}\r\n", String::from_utf8_lossy(data)));
        self.post(data.clone()).await;
        session.data(channel, data);
        Ok((self, session))
    }

    async fn tcpip_forward(
        self,
        address: &str,
        port: &mut u32,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        let handle = session.handle();
        let address = address.to_string();
        let port = *port;
        tokio::spawn(async move {
            let mut channel = handle
                .channel_open_forwarded_tcpip(address, port, "1.2.3.4", 1234)
                .await
                .unwrap();
            let _ = channel.data(&b"Hello from a forwarded port"[..]).await;
            let _ = channel.eof().await;
        });
        Ok((self, true, session))
    }
}
