use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use rustagon_app::outputs::{
    file::FileOutput, http::HttpOutput, program::ProgramOutput, stdout::StdoutOutput,
    syslog::SyslogOutput, Alert, Dispatcher, FormatOptions, Output, OutputError,
};
use rustagon_config::{
    FalcoConfig, FileOutput as FileConfig, HttpOutput as HttpConfig,
    ProgramOutput as ProgramConfig, ToggleOutput,
};
use serde_json::{json, Value};

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl SharedWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn alert() -> Alert {
    Alert {
        time: "2026-09-10T01:02:03.000000004Z".into(),
        rule: "Terminal shell".into(),
        priority: "Warning".into(),
        source: "syscall".into(),
        hostname: "test-host".into(),
        message: "A shell was spawned".into(),
        output_fields: BTreeMap::from([
            ("proc.name".into(), Value::String("bash".into())),
            ("proc.pid".into(), json!(42)),
        ]),
        tags: vec!["container".into(), "shell".into()],
    }
}

#[tokio::test]
async fn stdout_delivers_one_falco_text_line() {
    let writer = SharedWriter::default();
    let output = StdoutOutput::new(writer.clone(), FormatOptions::default());

    output.deliver(&alert()).await.unwrap();

    assert_eq!(
        writer.contents(),
        "2026-09-10T01:02:03.000000004Z: Warning A shell was spawned\n"
    );
}

#[tokio::test]
async fn file_appends_one_line_per_alert() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.log");
    let output = FileOutput::new(&path, false, FormatOptions::default()).unwrap();

    output.deliver(&alert()).await.unwrap();
    output.deliver(&alert()).await.unwrap();

    let line = "2026-09-10T01:02:03.000000004Z: Warning A shell was spawned\n";
    assert_eq!(std::fs::read_to_string(path).unwrap(), line.repeat(2));
}

#[test]
fn json_uses_falco_field_names_and_honors_optional_properties() {
    let options = FormatOptions {
        json_output: true,
        json_include_output_property: true,
        json_include_message_property: true,
        json_include_output_fields_property: true,
        json_include_tags_property: true,
    };

    let value: Value = serde_json::from_str(&alert().format(&options).unwrap()).unwrap();

    assert_eq!(
        value,
        json!({
            "time": "2026-09-10T01:02:03.000000004Z",
            "rule": "Terminal shell",
            "priority": "Warning",
            "source": "syscall",
            "hostname": "test-host",
            "output": "2026-09-10T01:02:03.000000004Z: Warning A shell was spawned",
            "message": "A shell was spawned",
            "output_fields": {"proc.name": "bash", "proc.pid": 42},
            "tags": ["container", "shell"]
        })
    );
}

#[test]
fn json_omits_disabled_optional_properties() {
    let options = FormatOptions {
        json_output: true,
        ..FormatOptions::default()
    };

    let value: Value = serde_json::from_str(&alert().format(&options).unwrap()).unwrap();

    assert_eq!(
        value,
        json!({
            "time": "2026-09-10T01:02:03.000000004Z",
            "rule": "Terminal shell",
            "priority": "Warning",
            "source": "syscall",
            "hostname": "test-host"
        })
    );
}

#[test]
fn format_options_are_derived_from_falco_config_flags() {
    let config = FalcoConfig::load_from_str(
        "json_output: true\n\
         json_include_output_property: true\n\
         json_include_message_property: true\n\
         json_include_output_fields_property: true\n\
         json_include_tags_property: true\n",
    )
    .unwrap();

    assert_eq!(
        FormatOptions::from(&config),
        FormatOptions {
            json_output: true,
            json_include_output_property: true,
            json_include_message_property: true,
            json_include_output_fields_property: true,
            json_include_tags_property: true,
        }
    );
}

struct CountingOutput(Arc<AtomicUsize>);

#[async_trait]
impl Output for CountingOutput {
    async fn deliver(&self, _alert: &Alert) -> Result<(), OutputError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[tokio::test]
async fn dispatcher_fans_each_alert_out_to_every_channel() {
    let first = Arc::new(AtomicUsize::new(0));
    let second = Arc::new(AtomicUsize::new(0));
    let dispatcher = Dispatcher::spawn(
        vec![
            Box::new(CountingOutput(first.clone())),
            Box::new(CountingOutput(second.clone())),
        ],
        4,
    );

    dispatcher.dispatch(alert()).await.unwrap();
    dispatcher.shutdown().await.unwrap();

    assert_eq!(first.load(Ordering::Relaxed), 1);
    assert_eq!(second.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn http_posts_the_formatted_alert() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let count = stream.read(&mut buf).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buf[..count]);
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = header_end + 4;
                let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + content_length {
                    break;
                }
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8(request).unwrap()
    });
    let config = HttpConfig {
        enabled: true,
        url: format!("http://{address}/alerts"),
        user_agent: "rustagon-test".into(),
        ..HttpConfig::default()
    };
    let output = HttpOutput::from_config(&config, FormatOptions::default())
        .unwrap()
        .unwrap();

    output.deliver(&alert()).await.unwrap();
    let request = server.await.unwrap();

    assert!(request.starts_with("POST /alerts HTTP/1.1\r\n"));
    assert!(request.contains("user-agent: rustagon-test\r\n"));
    assert!(request.ends_with("2026-09-10T01:02:03.000000004Z: Warning A shell was spawned"));
}

#[tokio::test]
async fn syslog_sends_the_formatted_alert_to_a_unix_socket() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("dev-log");
    let receiver = tokio::net::UnixDatagram::bind(&socket_path).unwrap();
    let output = SyslogOutput::new(&socket_path, FormatOptions::default());

    output.deliver(&alert()).await.unwrap();
    let mut message = vec![0; 1024];
    let count = receiver.recv(&mut message).await.unwrap();

    assert_eq!(
        String::from_utf8(message[..count].to_vec()).unwrap(),
        "<12>2026-09-10T01:02:03.000000004Z: Warning A shell was spawned"
    );
}

#[tokio::test]
async fn program_pipes_the_formatted_alert_to_the_command() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program.log");
    let config = ProgramConfig {
        enabled: true,
        keep_alive: false,
        program: format!("cat >> {}", path.display()),
    };
    let output = ProgramOutput::from_config(&config, FormatOptions::default())
        .unwrap()
        .unwrap();

    output.deliver(&alert()).await.unwrap();

    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        "2026-09-10T01:02:03.000000004Z: Warning A shell was spawned\n"
    );
}

#[test]
fn disabled_configs_do_not_create_channels() {
    assert!(
        StdoutOutput::from_config(&ToggleOutput::default(), FormatOptions::default()).is_none()
    );
    assert!(
        SyslogOutput::from_config(&ToggleOutput::default(), FormatOptions::default()).is_none()
    );
    assert!(
        FileOutput::from_config(&FileConfig::default(), FormatOptions::default())
            .unwrap()
            .is_none()
    );
    assert!(
        HttpOutput::from_config(&HttpConfig::default(), FormatOptions::default())
            .unwrap()
            .is_none()
    );
    assert!(
        ProgramOutput::from_config(&ProgramConfig::default(), FormatOptions::default())
            .unwrap()
            .is_none()
    );
}
