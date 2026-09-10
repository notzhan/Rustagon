use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

use async_trait::async_trait;
use rustagon_config::FileOutput as FileConfig;

use super::{Alert, FormatOptions, Output, OutputError};

pub struct FileOutput {
    path: PathBuf,
    file: Option<Mutex<File>>,
    format: FormatOptions,
}

impl FileOutput {
    pub fn from_config(
        config: &FileConfig,
        format: FormatOptions,
    ) -> Result<Option<Self>, OutputError> {
        config
            .enabled
            .then(|| Self::new(&config.filename, config.keep_alive, format))
            .transpose()
    }

    pub fn new(
        path: impl AsRef<Path>,
        keep_alive: bool,
        format: FormatOptions,
    ) -> Result<Self, OutputError> {
        let path = path.as_ref().to_owned();
        let file = keep_alive
            .then(|| open_append(&path).map(Mutex::new))
            .transpose()?;
        Ok(Self { path, file, format })
    }

    fn write_line(&self, line: &str) -> Result<(), OutputError> {
        if let Some(file) = &self.file {
            let mut file = file
                .lock()
                .map_err(|_| OutputError::Channel("file lock poisoned".into()))?;
            writeln!(file, "{line}")?;
            file.flush()?;
        } else {
            let mut file = open_append(&self.path)?;
            writeln!(file, "{line}")?;
            file.flush()?;
        }
        Ok(())
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[async_trait]
impl Output for FileOutput {
    async fn deliver(&self, alert: &Alert) -> Result<(), OutputError> {
        self.write_line(&alert.format(&self.format)?)
    }
}
