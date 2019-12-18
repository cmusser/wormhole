use crate::session::ClonedWriter;
use bytes::BytesMut;
use sodiumoxide::crypto::secretstream::{Header, Key, Stream, Tag, ABYTES, HEADERBYTES};
use std::fmt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::ReadHalf,
};
use tracing::trace;

#[derive(Debug)]
pub enum Error {
    LibInit,
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
            Error::LibInit => write!(f, "failed to initialize Sodiumoxide crypto library"),
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

const MAX_PLAINTEXT_SZ: usize = 256;
const IO_BUF_SZ: usize = MAX_PLAINTEXT_SZ + ABYTES;

pub async fn encrypting_reader<'a>(
    key_data: &[u8],
    reader: &'a mut ReadHalf<'a>,
    writer: &'a mut ClonedWriter<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::from_slice(key_data).ok_or(Error::KeyInit)?;
    let (mut stream, header) = Stream::init_push(&key).map_err(|_| Error::EncryptionStreamInit)?;
    writer.write_all(&header[..]).await?;

    let mut buf: [u8; MAX_PLAINTEXT_SZ] = [0; MAX_PLAINTEXT_SZ];
    loop {
        let plaintext_len = reader.read(&mut buf[..255]).await?;
        trace!(plaintext_len);
        if plaintext_len == 0 {
            break;
        } else {
            buf[plaintext_len] = 0x80;
            for byte in buf // Clippy recommends all this
                .iter_mut() // instead of a for loop.
                .take(MAX_PLAINTEXT_SZ)
                .skip(plaintext_len + 1)
            {
                *byte = 0;
            }
            let ciphertext = stream
                .push(&buf[0..MAX_PLAINTEXT_SZ], None, Tag::Message)
                .map_err(|_| Error::EncryptMsg)?;
            trace!(
                padded_plaintext_len = buf[..].len(),
                ciphertext_len = ciphertext[..].len()
            );
            writer.write(&ciphertext[..]).await?;
        }
    }
    Ok(())
}

pub async fn decrypting_reader<'a>(
    key_data: &[u8],
    reader: &'a mut ReadHalf<'a>,
    writer: &'a mut ClonedWriter<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::from_slice(key_data).ok_or(Error::KeyInit)?;
    let mut header_bytes = [0; HEADERBYTES];
    reader.read_exact(&mut header_bytes).await?;
    let header = Header::from_slice(&header_bytes).ok_or(Error::HeaderInit)?;
    let mut stream = Stream::init_pull(&header, &key).map_err(|_| Error::DecryptionStreamInit)?;

    let mut buf = BytesMut::with_capacity(IO_BUF_SZ);
    loop {
        let ciphertext_len = reader.read_buf(&mut buf).await?;
        trace!(ciphertext_len);
        if ciphertext_len == 0 {
            break;
        } else if buf.len() == IO_BUF_SZ {
            let (plaintext, _tag) = stream
                .pull(&buf[0..IO_BUF_SZ], None)
                .map_err(|_| Error::DecryptMsg(0, ciphertext_len))?;
            let mut end = MAX_PLAINTEXT_SZ - 1;
            trace!(end, plaintext_len = plaintext.len());
            while end >= 1 {
                if plaintext[end] == 0 {
                    end -= 1;
                }
                if plaintext[end] == 0x80 {
                    trace!(plaintext_len = plaintext[..end].len());
                    writer.write(&plaintext[..end]).await?;
                    buf.clear();
                    break;
                }
            }
        }
    }
    Ok(())
}
