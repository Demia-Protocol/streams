// Local
use crate::{Error, Result, User};

impl<T> User<T> {
    /// Reset message cursors so the next sync reads messages from the beginning again.
    ///
    /// This preserves identity, PSKs, subscribers, topics, latest links, and stored Spongos states.
    /// Use this after adding newly available keys when messages may have been skipped because they
    /// could not be decrypted.
    pub fn reset_message_state(&mut self) -> Result<()> {
        self.stream_address()
            .ok_or(Error::NoStream("reset message state"))?;
        self.state.cursor_store.reset_cursors();
        Ok(())
    }
}
