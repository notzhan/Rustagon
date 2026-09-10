use std::path::{Path, PathBuf};

use async_trait::async_trait;
use rustagon_config::ToggleOutput;

use super::{Alert, FormatOptions, Output, OutputError};

pub struct SyslogOutput {
    socket_path: PathBuf,
    format: FormatOptions,
}

impl SyslogOutput {
    pub fn new(path: impl AsRef<Path>, format: FormatOptions) -> Self {
        Self {
            socket_path: path.as_ref().to_owned(),
            format,
        }
    }

    pub fn from_config(config: &ToggleOutput, format: FormatOptions) -> Option<Self> {
        config.enabled.then(|| Self::new("/dev/log", format))
    }
}

#[async_trait]
impl Output for SyslogOutput {
    async fn deliver(&self, alert: &Alert) -> Result<(), OutputError> {
        let socket = tokio::net::UnixDatagram::unbound()?;
        let message = format!(
            "<{}>{}",
            syslog_pri(&alert.priority),
            alert.format(&self.format)?
        );
        socket
            .send_to(message.as_bytes(), &self.socket_path)
            .await?;
        Ok(())
    }
}

const LOG_USER: u8 = 1;

fn syslog_pri(priority: &str) -> u8 {
    LOG_USER << 3 | severity_number(priority)
}

fn severity_number(priority: &str) -> u8 {
    match priority.to_ascii_lowercase().as_str() {
        "emergency" => 0,
        "alert" => 1,
        "critical" => 2,
        "error" => 3,
        "warning" => 4,
        "notice" => 5,
        "informational" | "info" => 6,
        _ => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_pri_uses_log_user_facility() {
        assert_eq!(syslog_pri("warning"), 12);
        assert_eq!(syslog_pri("error"), 11);
        assert_eq!(syslog_pri("info"), 14);
    }
}
