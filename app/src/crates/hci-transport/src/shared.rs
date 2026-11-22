//! The shared radio (experimental): H4 to the shared-radio worker over its
//! stdin / stdout.
//!
//! The worker (`shared-radio/worker.py` beside the executable, run by its
//! bundled Python) owns the WinUSB adapter. It passes this host's HCI
//! through and gives Windows a virtual controller over USB/IP that may reach
//! one selected LE peripheral on the same radio. Its log lines (stderr) go to
//! this log; lines "bluecaster-status <state> [detail]" among them tell its
//! state ([`SharedRadioStatus`], for the Adapter screen).
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use btstack_sys::{HciBackend, Upstream};

/// The worker's folder, beside the executable
const WORKER_DIR: &str = "shared-radio";
/// How long the worker has to exit after its stdin closes
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// The start of the worker's state lines on stderr (worker.py)
const STATUS_PREFIX: &str = "bluecaster-status ";

/// Where the shared radio is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedRadioState {
    /// The worker started; it opens the adapter
    Starting,
    /// The adapter runs; Windows has not attached the virtual controller
    /// (yet)
    Waiting,
    /// Windows uses the virtual controller: the peripheral can connect
    Attached,
    /// The peripheral is connected to Windows
    Connected,
    /// The worker ended (the stack stopped, or it failed: `error`)
    Stopped,
}

impl SharedRadioState {
    /// As the IPC names it
    pub fn key(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Waiting => "waiting",
            Self::Attached => "attached",
            Self::Connected => "connected",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRadioStatus {
    pub state: SharedRadioState,
    /// Why the worker failed (its own words), kept until it starts again
    pub error: Option<String>,
}

/// Called (on the worker's stderr thread) when the shared radio's state changes
pub type SharedRadioHook = Arc<dyn Fn(&SharedRadioStatus) + Send + Sync>;

/// A state line of the worker's, or None for a log line
fn parse_status(line: &str) -> Option<(SharedRadioState, Option<String>)> {
    let rest = line.strip_prefix(STATUS_PREFIX)?;
    let (word, detail) = rest.split_once(' ').unwrap_or((rest, ""));
    Some(match word {
        "waiting" => (SharedRadioState::Waiting, None),
        "attached" => (SharedRadioState::Attached, None),
        "connected" => (SharedRadioState::Connected, None),
        "error" => (SharedRadioState::Stopped, Some(detail.trim().to_owned()).filter(|d| !d.is_empty())),
        _ => return None,
    })
}

pub struct SharedRadio {
    /// The adapter, "VID:PID"
    adapter: String,
    /// The LE peripheral Windows may connect to, "XX:XX:XX:XX:XX:XX"
    peer: String,
    worker: Option<Child>,
    reader: Option<JoinHandle<()>>,
    /// The H4 frame being sent (reused)
    packet: Vec<u8>,
    on_status: Option<SharedRadioHook>,
}

impl SharedRadio {
    pub fn new(adapter: &str, peer: &str, on_status: Option<SharedRadioHook>) -> Self {
        Self { adapter: adapter.into(), peer: peer.into(), worker: None, reader: None, packet: Vec::new(), on_status }
    }

    fn tell(&self, state: SharedRadioState, error: Option<String>) {
        if let Some(hook) = &self.on_status {
            hook(&SharedRadioStatus { state, error });
        }
    }
}

fn worker_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("shared radio: no executable path: {e}"))?;
    Ok(exe.with_file_name(WORKER_DIR))
}

impl HciBackend for SharedRadio {
    fn is_async(&self) -> bool {
        false
    }

    fn open(&mut self, upstream: Upstream) -> Result<(), String> {
        self.close();
        self.tell(SharedRadioState::Starting, None);
        let started = self.start(upstream);
        if let Err(e) = &started {
            self.tell(SharedRadioState::Stopped, Some(e.clone()));
        }
        started
    }

    fn send(&mut self, kind: u8, bytes: &[u8]) -> bool {
        self.packet.clear();
        self.packet.push(kind);
        self.packet.extend_from_slice(bytes);
        self.worker.as_mut().and_then(|c| c.stdin.as_mut()).is_some_and(|s| s.write_all(&self.packet).is_ok())
    }

    /// Closes the worker's stdin (it releases the adapter and exits), and
    /// kills it if it is still running after [`EXIT_TIMEOUT`]
    fn close(&mut self) {
        if let Some(mut child) = self.worker.take() {
            drop(child.stdin.take());
            let deadline = Instant::now() + EXIT_TIMEOUT;
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl SharedRadio {
    /// Starts the worker, its stderr thread (log and state lines) and the
    /// H4 reader
    fn start(&mut self, upstream: Upstream) -> Result<(), String> {
        let dir = worker_dir()?;
        let mut command = Command::new(dir.join("runtime").join("python.exe"));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        // -E -s: no PYTHON* variables, no user site; -B: no .pyc files
        let mut child = command
            .args(["-E", "-s", "-B"])
            .arg(dir.join("worker.py"))
            .arg(&self.adapter)
            .arg(&self.peer)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("shared radio: the worker did not start: {e}"))?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            return Err("shared radio: the worker has no pipes".into());
        };
        self.worker = Some(child);
        let on_status = self.on_status.clone();
        thread::spawn(move || {
            let tell = |state, error| {
                if let Some(hook) = &on_status {
                    hook(&SharedRadioStatus { state, error });
                }
            };
            let mut error = None;
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                tracing::info!(target: "shared_radio", "{line}");
                if let Some((state, e)) = parse_status(&line) {
                    if state == SharedRadioState::Stopped {
                        // Told with the worker's end, below
                        error = e;
                    } else {
                        tell(state, None);
                    }
                }
            }
            // stderr closes when the worker exits
            tell(SharedRadioState::Stopped, error);
        });
        self.reader = Some(thread::spawn(move || super::tcp::read_loop(stdout, upstream)));
        Ok(())
    }
}

impl Drop for SharedRadio {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_lines() {
        assert_eq!(parse_status("bluecaster-status waiting"), Some((SharedRadioState::Waiting, None)));
        assert_eq!(parse_status("bluecaster-status connected"), Some((SharedRadioState::Connected, None)));
        assert_eq!(
            parse_status("bluecaster-status error USB/IP attach failed: no driver"),
            Some((SharedRadioState::Stopped, Some("USB/IP attach failed: no driver".into())))
        );
        assert_eq!(parse_status("bluecaster-status error"), Some((SharedRadioState::Stopped, None)));
        assert_eq!(parse_status("INFO:usb-radio:Windows imported the virtual controller"), None);
        assert_eq!(parse_status("bluecaster-status something-new"), None);
    }
}
