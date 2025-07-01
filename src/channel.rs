use crate::error::{Error, InnerError};
use mosaic_core::Message;
use quinn::{RecvStream, SendStream};

/// Bidirectional stream
#[derive(Debug)]
pub struct Channel {
    send: SendStream,
    recv: RecvStream,
    partial: Vec<u8>,
    bytes_read: usize,
}

impl Channel {
    /// Create a new `Channel` from streams
    pub(crate) fn new(send: SendStream, recv: RecvStream) -> Channel {
        Channel {
            send,
            recv,
            partial: vec![0; 8],
            bytes_read: 0,
        }
    }

    /// Send a `Message`
    ///
    /// # Errors
    ///
    /// Returns an Err only if there was a QUIC writing problem
    pub async fn send(&mut self, message: Message) -> Result<usize, Error> {
        Ok(self.send.write(message.as_bytes()).await?)
    }

    /// Receive a `Message`
    ///
    /// This is cancel-safe. It remembers partial reads and picks up where it left off.
    ///
    /// # Errors
    ///
    /// Returns an Err if there was a QUIC reading problem or if the incoming
    /// Message was invalid
    pub async fn recv(&mut self) -> Result<Option<Message>, Error> {
        // Get the first 8 bytes
        while self.bytes_read < 8 {
            let Some(n) = self
                .recv
                .read(&mut self.partial[self.bytes_read..8])
                .await?
            else {
                return Ok(None);
            };
            self.bytes_read += n;
            if self.bytes_read >= 8 {
                break;
            }
        }

        // Extract the message length and resize buffer to hold it
        let message_len = (self.partial[1] as usize)
            + ((self.partial[2] as usize) << 8)
            + ((self.partial[3] as usize) << 16);
        self.partial.resize(message_len, 0);

        // Read the remaining bytes
        while self.bytes_read < message_len {
            let Some(n) = self.recv.read(&mut self.partial[self.bytes_read..]).await? else {
                return Ok(None);
            };
            self.bytes_read += n;
            if self.bytes_read >= message_len {
                break;
            }
        }

        let taken = std::mem::replace(&mut self.partial, vec![0; 8]);
        Ok(Some(Message::from_bytes(taken)?))
    }

    /// Finish this `Channel`. Afterwards you cannot write to it anymore.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream was already finished.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.send
            .finish()
            .map_err(|_| InnerError::ChannelAlreadyFinished.into())
    }
}
