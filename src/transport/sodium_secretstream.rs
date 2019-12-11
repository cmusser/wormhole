use core::pin::Pin;
use futures::task::{Context, Poll};
use sodiumoxide::crypto::secretstream::{Header, Key, Pull, Push, Stream, Tag, ABYTES};
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::{io::AsyncRead, net::tcp::ReadHalf};
use tracing::trace;

#[derive(Debug)]
pub enum Error {
    KeyInit,
    HeaderInit,
    EncryptionStreamInit,
    DecryptionStreamInit,
    EncryptMsg,
    DecryptMsg(u32, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeyInit => write!(f, "failed to initialize secret key from byte slice"),
            Error::HeaderInit => write!(f, "failed to initialize stream header from byte slice"),
            Error::EncryptionStreamInit => write!(f, "failed to initialize encryption stream"),
            Error::DecryptionStreamInit => write!(f, "failed to initialize decryption stream"),
            Error::EncryptMsg => write!(f, "encryption failed for message"),
            Error::DecryptMsg(seq, len) => {
                write!(f, "decryption failed for message {} (size {})", seq, len)
            }
        }
    }
}
impl std::error::Error for Error {}

pub struct EncryptingReader<'a> {
    pub header: Header,
    stream: Stream<Push>,
    reader: &'a mut ReadHalf<'a>,
}

impl<'a> EncryptingReader<'a> {
    pub fn new(key_data: &[u8], reader: &'a mut ReadHalf<'a>) -> Result<Self, Error> {
        let key = Key::from_slice(key_data).ok_or(Error::KeyInit)?;
        match Stream::init_push(&key) {
            Ok((stream, header)) => Ok(Self {
                header,
                stream,
                reader,
            }),
            Err(_) => Err(Error::EncryptionStreamInit),
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
                match result {
                    Ok(bytes) => {
                        if bytes == 0 {
                            Poll::Ready(Ok(bytes))
                        } else {
                            match self.stream.push(&plaintext[0..bytes], None, Tag::Message) {
                                Ok(ciphertext) => {
                                    buf[0..ciphertext.len()].clone_from_slice(&ciphertext[..]);
                                    Poll::Ready(Ok(ABYTES + bytes))
                                }
                                Err(_e) => Poll::Ready(Err(tokio::io::Error::new(
                                    tokio::io::ErrorKind::InvalidInput,
                                    Error::EncryptMsg,
                                ))),
                            }
                        }
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct DecryptingReader<'a> {
    stream: Stream<Pull>,
    reader: &'a mut ReadHalf<'a>,
    msg_count: AtomicU32,
}

impl<'a> DecryptingReader<'a> {
    pub fn new(
        header_bytes: &[u8],
        key_data: &[u8],
        reader: &'a mut ReadHalf<'a>,
    ) -> Result<Self, Error> {
        let key = Key::from_slice(key_data).ok_or(Error::KeyInit)?;
        let header = Header::from_slice(header_bytes).ok_or(Error::HeaderInit)?;
        match Stream::init_pull(&header, &key) {
            Ok(stream) => {
                trace!("decryption stream initialized");
                Ok(Self {
                    stream,
                    reader,
                    msg_count: AtomicU32::new(0),
                })
            }
            Err(_) => Err(Error::DecryptionStreamInit),
        }
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
                match result {
                    Ok(bytes) => {
                        if bytes == 0 {
                            Poll::Ready(Ok(bytes))
                        } else {
                            self.msg_count.fetch_add(1, Ordering::Relaxed);
                            let plaintext_len = bytes - ABYTES;
                            match self.stream.pull(&ciphertext[0..bytes], None) {
                                Ok((plaintext, _tag)) => {
                                    buf[0..plaintext_len]
                                        .clone_from_slice(&plaintext[0..(plaintext_len)]);
                                    Poll::Ready(Ok(plaintext_len))
                                }
                                Err(_e) => Poll::Ready(Err(tokio::io::Error::new(
                                    tokio::io::ErrorKind::InvalidInput,
                                    Error::DecryptMsg(
                                        self.msg_count.load(Ordering::Relaxed),
                                        bytes,
                                    ),
                                ))),
                            }
                        }
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
