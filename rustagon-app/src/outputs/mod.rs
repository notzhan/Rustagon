//! Falco-compatible alert formatting and output channels.

pub mod file;
pub mod http;
pub mod program;
pub mod stdout;
pub mod syslog;

use std::collections::BTreeMap;

use async_trait::async_trait;
use rustagon_config::FalcoConfig;
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::{sync::mpsc, task::JoinHandle};

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub time: String,
    pub rule: String,
    pub priority: String,
    pub source: String,
    pub hostname: String,
    pub message: String,
    pub output_fields: BTreeMap<String, Value>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormatOptions {
    pub json_output: bool,
    pub json_include_output_property: bool,
    pub json_include_message_property: bool,
    pub json_include_output_fields_property: bool,
    pub json_include_tags_property: bool,
}

impl From<&FalcoConfig> for FormatOptions {
    fn from(config: &FalcoConfig) -> Self {
        Self {
            json_output: config.json_output,
            json_include_output_property: config.json_include_output_property,
            json_include_message_property: config.json_include_message_property,
            json_include_output_fields_property: config.json_include_output_fields_property,
            json_include_tags_property: config.json_include_tags_property,
        }
    }
}

impl Alert {
    pub fn text(&self) -> String {
        format!("{}: {} {}", self.time, self.priority, self.message)
    }

    pub fn format(&self, options: &FormatOptions) -> Result<String, OutputError> {
        if !options.json_output {
            return Ok(self.text());
        }

        let mut object = Map::new();
        object.insert("time".into(), self.time.clone().into());
        object.insert("rule".into(), self.rule.clone().into());
        object.insert("priority".into(), self.priority.clone().into());
        object.insert("source".into(), self.source.clone().into());
        object.insert("hostname".into(), self.hostname.clone().into());
        if options.json_include_output_property {
            object.insert("output".into(), self.text().into());
        }
        if options.json_include_message_property {
            object.insert("message".into(), self.message.clone().into());
        }
        if options.json_include_output_fields_property {
            object.insert(
                "output_fields".into(),
                Value::Object(self.output_fields.clone().into_iter().collect()),
            );
        }
        if options.json_include_tags_property {
            object.insert("tags".into(), serde_json::to_value(&self.tags)?);
        }
        Ok(serde_json::to_string(&object)?)
    }
}

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("output I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("output JSON formatting failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("output channel failed: {0}")]
    Channel(String),
}

#[async_trait]
pub trait Output: Send {
    async fn deliver(&self, alert: &Alert) -> Result<(), OutputError>;
}

pub struct Dispatcher {
    sender: mpsc::Sender<Alert>,
    worker: JoinHandle<Result<(), OutputError>>,
}

impl Dispatcher {
    pub fn spawn(outputs: Vec<Box<dyn Output + Sync>>, capacity: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel(capacity);
        let worker = tokio::spawn(async move {
            let mut first_error = None;
            while let Some(alert) = receiver.recv().await {
                for output in &outputs {
                    if let Err(error) = output.deliver(&alert).await {
                        first_error.get_or_insert(error);
                    }
                }
            }
            first_error.map_or(Ok(()), Err)
        });
        Self { sender, worker }
    }

    pub async fn dispatch(&self, alert: Alert) -> Result<(), OutputError> {
        self.sender
            .send(alert)
            .await
            .map_err(|_| OutputError::Channel("output dispatcher stopped".into()))
    }

    pub async fn shutdown(self) -> Result<(), OutputError> {
        drop(self.sender);
        self.worker
            .await
            .map_err(|error| OutputError::Channel(format!("output worker failed: {error}")))?
    }
}
