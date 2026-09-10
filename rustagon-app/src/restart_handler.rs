use crate::atomic_signal_handler::AtomicSignalHandler;
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

type FileSignature = Option<(SystemTime, u64)>;

pub struct RestartHandler {
    check: Arc<dyn Fn() -> bool + Send + Sync>,
    watched_files: Vec<PathBuf>,
    forced: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    wake: Arc<(Mutex<()>, Condvar)>,
    restart_signal: Arc<AtomicSignalHandler>,
    thread: Option<JoinHandle<()>>,
}

impl RestartHandler {
    pub fn new(
        check: impl Fn() -> bool + Send + Sync + 'static,
        watched_files: Vec<PathBuf>,
    ) -> Self {
        Self {
            check: Arc::new(check),
            watched_files,
            forced: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            wake: Arc::new((Mutex::new(()), Condvar::new())),
            restart_signal: Arc::new(AtomicSignalHandler::new()),
            thread: None,
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        if self.thread.is_some() {
            return Err("restart handler is already running".to_string());
        }
        self.stopping.store(false, Ordering::Release);
        let check = Arc::clone(&self.check);
        let paths = self.watched_files.clone();
        let forced = Arc::clone(&self.forced);
        let stopping = Arc::clone(&self.stopping);
        let wake = Arc::clone(&self.wake);
        let restart_signal = Arc::clone(&self.restart_signal);
        let mut previous_signatures = signatures(&paths);

        self.thread = Some(
            thread::Builder::new()
                .name("rustagon-restart".to_string())
                .spawn(move || {
                    while !stopping.load(Ordering::Acquire) {
                        let (lock, condvar) = &*wake;
                        let guard = lock.lock().unwrap_or_else(|error| error.into_inner());
                        let _ = condvar
                            .wait_timeout(guard, Duration::from_millis(100))
                            .unwrap_or_else(|error| error.into_inner());
                        if stopping.load(Ordering::Acquire) {
                            break;
                        }

                        let next = signatures(&paths);
                        let changed = next != previous_signatures;
                        previous_signatures = next;
                        let requested = forced.swap(false, Ordering::AcqRel);
                        if (requested || changed) && check() {
                            restart_signal.trigger();
                        }
                    }
                })
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    pub fn trigger(&self) {
        self.forced.store(true, Ordering::Release);
        self.wake.1.notify_one();
    }

    pub fn restart_signal(&self) -> Arc<AtomicSignalHandler> {
        Arc::clone(&self.restart_signal)
    }

    pub fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.wake.1.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for RestartHandler {
    fn drop(&mut self) {
        self.stop();
    }
}

fn signatures(paths: &[PathBuf]) -> Vec<FileSignature> {
    paths
        .iter()
        .map(|path| {
            fs::metadata(path)
                .ok()
                .and_then(|metadata| Some((metadata.modified().ok()?, metadata.len())))
        })
        .collect()
}
