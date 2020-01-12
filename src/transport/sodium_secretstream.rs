use crate::session::ClonedWriter;
use bytes::BytesMut;
use sodiumoxide::crypto::secretstream::{Header, Key, Stream, Tag, ABYTES, HEADERBYTES};
use std::fmt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::ReadHalf,
};
use tracing::{error, trace};

#[derive(Debug)]
pub enum Error {
    LibInit,
    KeyInit,
    HeaderInit,
    EncryptionStreamInit,
    DecryptionStreamInit,
    EncryptMsg,
    DecryptMsg(usize, usize, usize),
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
            Error::DecryptMsg(seq, len, bytes_transferred) => write!(
                f,
                "decryption failed for message {} (size {}), successful_bytes {}",
                seq, len, bytes_transferred
            ),
        }
    }
}
impl std::error::Error for Error {}

const PLAINTEXT_BUF_SZ: usize = 256;
// The plaintext buffer must have at least one byte that serves as a
// boundary from the actual plaintext and any padding needed for the buffer.
const MAX_PLAINTEXT_SZ: usize = PLAINTEXT_BUF_SZ - 1;
const IO_BUF_SZ: usize = PLAINTEXT_BUF_SZ + ABYTES;

pub async fn encrypting_reader<'a>(
    key_data: &[u8],
    reader: &'a mut ReadHalf<'a>,
    writer: &'a mut ClonedWriter<'a>,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let key = Key::from_slice(key_data).ok_or(Error::KeyInit)?;
    let (mut stream, header) = Stream::init_push(&key).map_err(|_| Error::EncryptionStreamInit)?;
    writer.write_all(&header[..]).await?;

    let mut message: usize = 0;
    let mut bytes_transferred: usize = 0;
    let mut buf: [u8; PLAINTEXT_BUF_SZ] = [0; PLAINTEXT_BUF_SZ];
    loop {
        let plaintext_len = reader.read(&mut buf[..MAX_PLAINTEXT_SZ]).await?;
        if plaintext_len == 0 {
            trace!("EOF");
            break;
        } else {
            buf[plaintext_len] = 0x80;
            for byte in buf // Clippy recommends all this
                .iter_mut() // instead of a for loop.
                .take(PLAINTEXT_BUF_SZ)
                .skip(plaintext_len + 1)
            {
                *byte = 0;
            }
            let ciphertext = stream
                .push(&buf[0..PLAINTEXT_BUF_SZ], None, Tag::Message)
                .map_err(|_| Error::EncryptMsg)?;
            writer.write_all(&ciphertext[..]).await?;
            bytes_transferred += plaintext_len;
            message += 1;
            trace!(
                message,
                plaintext_len,
                padded_plaintext_len = buf[..].len(),
                ciphertext_len = ciphertext[..].len(),
            );
        }
    }
    Ok((message, bytes_transferred))
}

pub async fn decrypting_reader<'a>(
    key_data: &[u8],
    reader: &'a mut ReadHalf<'a>,
    writer: &'a mut ClonedWriter<'a>,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let key = Key::from_slice(key_data).ok_or(Error::KeyInit)?;
    let mut header_bytes = [0; HEADERBYTES];
    reader.read_exact(&mut header_bytes).await?;
    let header = Header::from_slice(&header_bytes).ok_or(Error::HeaderInit)?;
    let mut stream = Stream::init_pull(&header, &key).map_err(|_| Error::DecryptionStreamInit)?;

    let mut message: usize = 0;
    let mut bytes_transferred: usize = 0;
    let mut buf = BytesMut::with_capacity(IO_BUF_SZ);
    loop {
        let ciphertext_len = reader.read_buf(&mut buf).await?;
        if ciphertext_len == 0 {
            trace!("EOF");
            break;
        } else if buf.len() == IO_BUF_SZ {
            message += 1;
            let (padded_plaintext, _tag) = stream
                .pull(&buf, None)
                .map_err(|_| Error::DecryptMsg(message, buf.len(), bytes_transferred))?;
            let mut end = MAX_PLAINTEXT_SZ;
            let mut boundary_found = false;
            while end >= 1 {
                if padded_plaintext[end] == 0 {
                    end -= 1;
                }
                if padded_plaintext[end] == 0x80 {
                    boundary_found = true;
                    let plaintext_len = padded_plaintext[..end].len();
                    bytes_transferred += plaintext_len;
                    trace!(
                        message,
                        ciphertext_len,
                        end,
                        padded_plaintext_len = padded_plaintext.len(),
                        plaintext_len,
                    );
                    writer.write_all(&padded_plaintext[..end]).await?;
                    break;
                }
            }
            if boundary_found == false {
                error!("no 0x80 boundary found in plaintext");
            }
            buf.clear();
        }
    }
    Ok((message, bytes_transferred))
}
