use std::{
    io::{self, Write},
    sync::Mutex,
};

use async_trait::async_trait;
use rustagon_config::ToggleOutput;

use super::{Alert, FormatOptions, Output, OutputError};

pub struct StdoutOutput<W: Write + Send> {
    writer: Mutex<W>,
    format: FormatOptions,
}

impl<W: Write + Send> StdoutOutput<W> {
    pub fn new(writer: W, format: FormatOptions) -> Self {
        Self {
            writer: Mutex::new(writer),
            format,
        }
    }
}

impl StdoutOutput<io::Stdout> {
    pub fn standard(format: FormatOptions) -> Self {
        Self::new(io::stdout(), format)
    }

    pub fn from_config(config: &ToggleOutput, format: FormatOptions) -> Option<Self> {
        config.enabled.then(|| Self::standard(format))
    }
}

#[async_trait]
impl<W: Write + Send> Output for StdoutOutput<W> {
    async fn deliver(&self, alert: &Alert) -> Result<(), OutputError> {
        let line = alert.format(&self.format)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| OutputError::Channel("stdout lock poisoned".into()))?;
        writeln!(writer, "{line}")?;
        writer.flush()?;
        Ok(())
    }
}
