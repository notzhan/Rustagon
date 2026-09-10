use std::fs;

use async_trait::async_trait;
use rustagon_config::HttpOutput as HttpConfig;

use super::{Alert, FormatOptions, Output, OutputError};

pub struct HttpOutput {
    client: reqwest::Client,
    url: String,
    format: FormatOptions,
}

impl HttpOutput {
    pub fn from_config(
        config: &HttpConfig,
        format: FormatOptions,
    ) -> Result<Option<Self>, OutputError> {
        if !config.enabled {
            return Ok(None);
        }
        if config.url.is_empty() {
            return Err(OutputError::Channel(
                "http_output.url must not be empty".into(),
            ));
        }

        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.insecure)
            .user_agent(&config.user_agent);
        for path in [&config.ca_cert, &config.ca_bundle] {
            if !path.is_empty() {
                let certificate = reqwest::Certificate::from_pem(&fs::read(path)?)
                    .map_err(|error| OutputError::Channel(error.to_string()))?;
                builder = builder.add_root_certificate(certificate);
            }
        }
        if config.mtls {
            let mut identity = fs::read(&config.client_cert)?;
            identity.extend_from_slice(&fs::read(&config.client_key)?);
            builder = builder.identity(
                reqwest::Identity::from_pem(&identity)
                    .map_err(|error| OutputError::Channel(error.to_string()))?,
            );
        }
        let client = builder
            .build()
            .map_err(|error| OutputError::Channel(error.to_string()))?;
        Ok(Some(Self {
            client,
            url: config.url.clone(),
            format,
        }))
    }
}

#[async_trait]
impl Output for HttpOutput {
    async fn deliver(&self, alert: &Alert) -> Result<(), OutputError> {
        let content_type = if self.format.json_output {
            "application/json"
        } else {
            "text/plain"
        };
        self.client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(alert.format(&self.format)?)
            .send()
            .await
            .map_err(|error| OutputError::Channel(error.to_string()))?
            .error_for_status()
            .map_err(|error| OutputError::Channel(error.to_string()))?;
        Ok(())
    }
}
