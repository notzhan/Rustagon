use std::process::Stdio;

use async_trait::async_trait;
use rustagon_config::ProgramOutput as ProgramConfig;
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::Mutex,
};

use super::{Alert, FormatOptions, Output, OutputError};

pub struct ProgramOutput {
    command: String,
    keep_alive: bool,
    process: Mutex<Option<Process>>,
    format: FormatOptions,
}

struct Process {
    child: Child,
    stdin: tokio::process::ChildStdin,
}

impl ProgramOutput {
    pub fn from_config(
        config: &ProgramConfig,
        format: FormatOptions,
    ) -> Result<Option<Self>, OutputError> {
        if !config.enabled {
            return Ok(None);
        }
        if config.program.is_empty() {
            return Err(OutputError::Channel(
                "program_output.program must not be empty".into(),
            ));
        }
        Ok(Some(Self {
            command: config.program.clone(),
            keep_alive: config.keep_alive,
            process: Mutex::new(None),
            format,
        }))
    }

    fn spawn(&self) -> Result<Process, OutputError> {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(&self.command)
            .stdin(Stdio::piped())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| OutputError::Channel("program stdin is unavailable".into()))?;
        Ok(Process { child, stdin })
    }
}

#[async_trait]
impl Output for ProgramOutput {
    async fn deliver(&self, alert: &Alert) -> Result<(), OutputError> {
        let line = format!("{}\n", alert.format(&self.format)?);
        if self.keep_alive {
            let mut process = self.process.lock().await;
            if process.is_none() {
                *process = Some(self.spawn()?);
            }
            let current = process.as_mut().expect("program was initialized");
            current.stdin.write_all(line.as_bytes()).await?;
            current.stdin.flush().await?;
        } else {
            let Process {
                mut child,
                mut stdin,
            } = self.spawn()?;
            stdin.write_all(line.as_bytes()).await?;
            stdin.shutdown().await?;
            drop(stdin);
            let status = child.wait().await?;
            if !status.success() {
                return Err(OutputError::Channel(format!(
                    "program exited with status {status}"
                )));
            }
        }
        Ok(())
    }
}
