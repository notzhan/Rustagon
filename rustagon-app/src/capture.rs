use serde::Deserialize;

const MIB: u64 = 1024 * 1024;
const MAX_FILE_SIZE_MB: u64 = 1024 * 1024;

pub fn generate_scap_file_path(prefix: &str, timestamp: u64, event_number: u64) -> String {
    format!("{prefix}_{timestamp:020}_{event_number:020}.scap")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    Rules,
    AllRules,
}

impl Default for CaptureMode {
    fn default() -> Self {
        Self::Rules
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub enabled: bool,
    pub path_prefix: String,
    pub mode: CaptureMode,
    pub default_duration_ns: u64,
    pub max_file_size_mb: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path_prefix: "/tmp/falco".to_string(),
            mode: CaptureMode::Rules,
            default_duration_ns: 5_000_000_000,
            max_file_size_mb: 0,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Root {
    capture: Option<RawCaptureConfig>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawCaptureConfig {
    enabled: bool,
    path_prefix: Option<String>,
    mode: CaptureMode,
    default_duration: Option<u64>,
    max_file_size_mb: u64,
}

impl CaptureConfig {
    pub fn from_yaml(content: &str) -> Result<Self, String> {
        let raw = serde_yaml::from_str::<Root>(content)
            .map_err(|error| error.to_string())?
            .capture
            .unwrap_or_default();
        if raw.max_file_size_mb > MAX_FILE_SIZE_MB {
            return Err(format!(
                "capture.max_file_size_mb must not exceed {MAX_FILE_SIZE_MB}"
            ));
        }
        let duration_ms = raw.default_duration.unwrap_or(5_000);
        let default_duration_ns = duration_ms
            .checked_mul(1_000_000)
            .ok_or_else(|| "capture.default_duration is too large".to_string())?;
        Ok(Self {
            enabled: raw.enabled,
            path_prefix: raw.path_prefix.unwrap_or_else(|| "/tmp/falco".to_string()),
            mode: raw.mode,
            default_duration_ns,
            max_file_size_mb: raw.max_file_size_mb,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStopReason {
    None,
    TimeDeadline,
    SizeLimit,
}

pub fn check_capture_stop(
    now: u64,
    deadline: u64,
    written_bytes: u64,
    max_file_size_mb: u64,
) -> CaptureStopReason {
    if now >= deadline {
        CaptureStopReason::TimeDeadline
    } else if max_file_size_mb != 0 && written_bytes >= max_file_size_mb.saturating_mul(MIB) {
        CaptureStopReason::SizeLimit
    } else {
        CaptureStopReason::None
    }
}
