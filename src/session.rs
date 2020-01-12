use crate::transport::sodium_secretstream::{decrypting_reader, encrypting_reader};
use core::pin::Pin;
use futures::{
    future::{select, Either},
    task::{Context, Poll},
};
use futures_util::future::FutureExt;
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{tcp::WriteHalf, TcpStream},
};
use tracing::{error, info, info_span};
use tracing_futures::Instrument;

fn reader_finish(closed_by: &str, result: Result<(usize, usize), Box<dyn std::error::Error>>) {
    match result {
        Ok((messages, bytes_transferred)) => info!(closed_by, messages, bytes_transferred, "done"),
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
    if is_server_proxy {
        let encrypt_from_server =
            encrypting_reader(&key_data, &mut server_reader, &mut client_writer)
                .instrument(info_span!("encrypting_reader"));

        let decrypt_from_client =
            decrypting_reader(&key_data, &mut client_reader, &mut server_writer)
                .instrument(info_span!("decrypting_reader"));

        select(decrypt_from_client.boxed(), encrypt_from_server.boxed())
            .then(|either| match either {
                Either::Left((client_read_result, _encrypt_from_server)) => {
                    reader_finish("client proxy", client_read_result);
                    server_writer_to_close.shutdown()
                }
                Either::Right((server_read_result, _decrypt_from_client)) => {
                    reader_finish("server", server_read_result);
                    client_writer_to_close.shutdown()
                }
            })
            .await?;
    } else {
        let encrypt_from_client =
            encrypting_reader(&key_data, &mut client_reader, &mut server_writer)
                .instrument(info_span!("encrypting_reader"));

        let decrypt_from_server =
            decrypting_reader(&key_data, &mut server_reader, &mut client_writer)
                .instrument(info_span!("decrypting_reader"));

        select(encrypt_from_client.boxed(), decrypt_from_server.boxed())
            .then(|either| match either {
                Either::Left((client_read_result, _decrypt_from_server)) => {
                    reader_finish("client", client_read_result);
                    server_writer_to_close.shutdown()
                }
                Either::Right((server_read_result, _encrypt_from_client)) => {
                    reader_finish("server proxy", server_read_result);
                    client_writer_to_close.shutdown()
                }
            })
            .await?;
    }
    Ok(())
}

#[derive(Clone)]
pub struct ClonedWriter<'a>(Arc<Mutex<WriteHalf<'a>>>);

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
