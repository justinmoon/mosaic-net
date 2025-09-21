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

        // Extract the message length (32-bit little endian at bytes 4..8)
        let message_len = u32::from_le_bytes(self.partial[4..8].try_into().unwrap()) as usize;
        if message_len < 8 {
            return Err(
                InnerError::General(format!("invalid message length: {message_len}")).into(),
            );
        }
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
        self.bytes_read = 0;

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
