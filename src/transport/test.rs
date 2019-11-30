use core::pin::Pin;
use futures::task::{Context, Poll};
use tokio::{io::AsyncRead, net::tcp::ReadHalf};
use tracing::trace;

pub type Header = [u8; 2];

pub struct AddHeaderReader<'a> {
    pub header: Header,
    reader: &'a mut ReadHalf<'a>,
}

impl<'a> AddHeaderReader<'a> {
    pub fn new(header: Header, reader: &'a mut ReadHalf<'a>) -> Self {
        Self { header, reader }
    }
}

impl<'a> AsyncRead for AddHeaderReader<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        buf[..2].copy_from_slice(&self.header);
        let result = Pin::new(&mut self.reader).poll_read(cx, &mut buf[2..]);
        match result {
            Poll::Ready(result) => {
                trace!(result= ?result);
                if let Ok(bytes) = result {
                    Poll::Ready(Ok(if bytes == 0 {
                        0
                    } else {
                        self.header.len() + bytes
                    }))
                } else {
                    Poll::Ready(result)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct PassThroughReader<'a> {
    _header: Header,
    reader: &'a mut ReadHalf<'a>,
}

impl<'a> PassThroughReader<'a> {
    pub fn new(_header: Header, reader: &'a mut ReadHalf<'a>) -> Self {
        Self { _header, reader }
    }
}

impl<'a> AsyncRead for PassThroughReader<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        let result = Pin::new(&mut self.reader).poll_read(cx, buf);
        match result {
            Poll::Ready(bytes_read) => {
                trace!(bytes_read = ?bytes_read);
                Poll::Ready(bytes_read)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
