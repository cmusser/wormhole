use core::pin::Pin;
use futures::task::{Context, Poll};
use sodiumoxide::crypto::secretstream::{Header, Key, Pull, Push, Stream, Tag, ABYTES};
use tokio::{io::AsyncRead, net::tcp::ReadHalf};
use tracing::trace;

pub struct EncryptingReader<'a> {
    pub header: Header,
    stream: Stream<Push>,
    reader: &'a mut ReadHalf<'a>,
}

impl<'a> EncryptingReader<'a> {
    pub fn new(key_data: &[u8], reader: &'a mut ReadHalf<'a>) -> Self {
        let key = Key::from_slice(key_data).unwrap();
        let (stream, header) = Stream::init_push(&key).unwrap();
        Self {
            header,
            stream,
            reader,
        }
    }

    pub fn header_bytes(&self) -> &[u8] {
        &self.header[..]
    }
}

impl<'a> AsyncRead for EncryptingReader<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        let mut plaintext: [u8; 2048 - ABYTES] = [0; 2048 - ABYTES];
        let result = Pin::new(&mut self.reader).poll_read(cx, &mut plaintext);
        match result {
            Poll::Ready(result) => {
                trace!(result= ?result);
                if let Ok(bytes) = result {
                    Poll::Ready(Ok(if bytes == 0 {
                        0
                    } else {
                        let ciphertext = self
                            .stream
                            .push(&plaintext[0..bytes], None, Tag::Message)
                            .unwrap();
                        buf[0..ciphertext.len()].clone_from_slice(&ciphertext[..]);
                        ABYTES + bytes
                    }))
                } else {
                    Poll::Ready(result)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct DecryptingReader<'a> {
    stream: Stream<Pull>,
    reader: &'a mut ReadHalf<'a>,
}

impl<'a> DecryptingReader<'a> {
    pub fn new(header_bytes: &[u8], key_data: &[u8], reader: &'a mut ReadHalf<'a>) -> Self {
        let key = Key::from_slice(key_data).unwrap();
        let header = Header::from_slice(header_bytes).unwrap();
        let stream = Stream::init_pull(&header, &key).unwrap();
        Self { stream, reader }
    }
}

impl<'a> AsyncRead for DecryptingReader<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        let mut ciphertext: [u8; 2048] = [0; 2048];
        let result = Pin::new(&mut self.reader).poll_read(cx, &mut ciphertext);
        match result {
            Poll::Ready(result) => {
                trace!(result= ?result);
                if let Ok(bytes) = result {
                    Poll::Ready(Ok(if bytes == 0 {
                        0
                    } else {
                        let plaintext_len = bytes - ABYTES;
                        let (plaintext, _tag) = self
                            .stream
                            .pull(&ciphertext[0..bytes], None)
                            .expect(&format!("stream decrypt for {} bytes failed", bytes));
                        buf[0..plaintext_len].clone_from_slice(&plaintext[0..(plaintext_len)]);
                        plaintext_len
                    }))
                } else {
                    Poll::Ready(result)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
