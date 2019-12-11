use crate::transport::sodium_secretstream::{DecryptingReader, EncryptingReader};
//use crate::transport::test::{AddHeaderReader, Header, PassThroughReader};
use core::pin::Pin;
use futures::{
    future::{select, Either},
    task::{Context, Poll},
};
use futures_util::future::FutureExt;
use sodiumoxide::crypto::secretstream::HEADERBYTES;
use std::sync::{Arc, Mutex};
use tokio::{
    io::{copy, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{tcp::WriteHalf, TcpStream},
};
use tracing::{error, info};

fn reader_finish(closed_by: &str, result: Result<u64, std::io::Error>) {
    match result {
        Ok(bytes_read) => info!(closed_by, bytes_read),
        Err(e) => error!(%e),
    }
}

pub async fn run_session(
    key_data: Vec<u8>,
    is_server_proxy: bool,
    mut client: TcpStream,
    mut server: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client_reader, client_writer) = client.split();
    let (mut server_reader, server_writer) = server.split();
    let mut server_writer = ClonedWriter(Arc::new(Mutex::new(server_writer)));
    let mut server_writer_to_close = server_writer.clone();
    let mut client_writer = ClonedWriter(Arc::new(Mutex::new(client_writer)));
    let mut client_writer_to_close = client_writer.clone();

    info!("started");
    let mut remote_header = [0; HEADERBYTES];
    if is_server_proxy {
        // Set up reader that will encrypt server packets; send the encryption
        // header to the peer proxy so it can decrypt them.
        let mut encrypt_from_server = EncryptingReader::new(&key_data, &mut server_reader)?;
        client_writer
            .write_all(encrypt_from_server.header_bytes())
            .await?;

        // Read the encryption header from the peer proxy and use it to set up
        // the reader that will decrypt packets from the client.
        client_reader.read_exact(&mut remote_header).await?;
        info!("received header from client proxy");
        let mut decrypt_from_client =
            DecryptingReader::new(&remote_header, &key_data, &mut client_reader)?;

        // Decrypt client packets and forward to server; encrypt server packets
        // and forward to client. When one of the connections is closed by the peer,
        // close the other connection.
        select(
            copy(&mut decrypt_from_client, &mut server_writer),
            copy(&mut encrypt_from_server, &mut client_writer),
        )
        .then(|either| match either {
            Either::Left((client_read_result, _server_to_client)) => {
                reader_finish("client proxy", client_read_result);
                server_writer_to_close.shutdown()
            }
            Either::Right((server_read_result, _client_to_server)) => {
                reader_finish("server", server_read_result);
                client_writer_to_close.shutdown()
            }
        })
        .await?;
    } else {
        // Set up reader that will encrypt client packets and send the
        // encryption header to the peer proxy so it can decrypt them.
        let mut encrypt_from_client = EncryptingReader::new(&key_data, &mut client_reader)?;
        server_writer
            .write_all(encrypt_from_client.header_bytes())
            .await?;

        // Read the encryption header from the peer proxy and use it to set up
        // the reader that will decrypt packets from the server.
        server_reader.read_exact(&mut remote_header).await?;
        info!("received header from server proxy");
        let mut decrypt_from_server =
            DecryptingReader::new(&remote_header, &key_data, &mut server_reader)?;

        // Decrypt server packets and forward to client; encrypt client packets
        // and forward to server. As above, when one of the connections is closed
        // by the peer, close the other connection.
        select(
            copy(&mut encrypt_from_client, &mut server_writer),
            copy(&mut decrypt_from_server, &mut client_writer),
        )
        .then(|either| match either {
            Either::Left((client_read_result, _server_to_client)) => {
                reader_finish("client", client_read_result);
                server_writer_to_close.shutdown()
            }
            Either::Right((server_read_result, _client_to_server)) => {
                reader_finish("server proxy", server_read_result);
                client_writer_to_close.shutdown()
            }
        })
        .await?;
    }
    info!("done");
    Ok(())
}

#[derive(Clone)]
struct ClonedWriter<'a>(Arc<Mutex<WriteHalf<'a>>>);

impl<'a> AsyncWrite for ClonedWriter<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        let mut write_half = self.0.lock().unwrap();
        Pin::new(&mut *write_half).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        let mut write_half = self.0.lock().unwrap();
        Pin::new(&mut *write_half).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        let mut write_half = self.0.lock().unwrap();
        Pin::new(&mut *write_half).poll_shutdown(cx)
    }
}
