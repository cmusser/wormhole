#![warn(rust_2018_idioms)]

use futures::FutureExt;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, info_span};
use tracing_futures::Instrument;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use wormhole::session::run_session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    #[derive(Debug, StructOpt)]
    #[structopt(name = "wormhole", about = "Secure TCP tunnel.")]
    struct Opt {
        /// Act as a gateway for a server, rather than a proxy for clients
        #[structopt(short = "S", long)]
        server_proxy: bool,

        /// Address:port for client connections.
        #[structopt(short, long, default_value = "127.0.0.1:8081")]
        client: String,

        /// Address:port of server (in gateway mode) or remote gateway (in proxy mode)
        #[structopt(short, long, default_value = "127.0.0.1:8080")]
        server: String,

        /// File containing shared key
        #[structopt(short, long, default_value = "key.yaml")]
        key_file: String,
    }

    let opt = Opt::from_args();

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed to set tracing default.");

    let mut key_file = File::open(&PathBuf::from(opt.key_file))?;
    let mut key_yaml = String::new();
    key_file.read_to_string(&mut key_yaml)?;
    let key: Vec<u8> = serde_yaml::from_str(&key_yaml)?;
    let mut incoming = TcpListener::bind(opt.client.clone()).await?;

    let server_span = info_span!(
        "wormhole", mode = if opt.server_proxy { "server proxy" } else { "client proxy" },
        listen_addr = %opt.client, server_addr = %opt.server);
    let _span = server_span.enter();

    info!("accepting connections");
    loop {
        match incoming.accept().await {
            Ok((client, _)) => {
                match TcpStream::connect(opt.server.clone()).await {
                    Ok(server) => {
                        let client_addr = client.peer_addr();
                        let server_addr = server.peer_addr();
                        let session = run_session(key.clone(), opt.server_proxy, client, server)
                            .instrument(info_span!("session", ?client_addr, ?server_addr))
                            .map(|r| {
                                if let Err(e) = r {
                                    error!(?e, "session failure");
                                }
                            });
                        tokio::spawn(session);
                    }
                    Err(e) => error!(?e, "connect failure"),
                };
            }
            Err(e) => error!(?e, "accept"),
        }
    }
}
