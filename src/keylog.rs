use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::io::{self, BufWriter};
use std::path::Path;
use std::sync::Mutex;

/// This trait represents the ability to do something useful
/// with key material, such as logging it to a file for debugging.
///
/// Naturally, secrets passed over the interface are *extremely*
/// sensitive and can break the security of past, present and
/// future sessions.
///
/// You'll likely want some interior mutability in your
/// implementation to make this useful.
///
/// See `KeyLogFile` that implements the standard `SSLKEYLOGFILE`
/// environment variable behaviour.
pub trait KeyLog: Send + Sync {
    /// Log the given `secret`.  `client_random` is provided for
    /// session identification.  `label` describes precisely what
    /// `secret` means:
    ///
    /// - `CLIENT_RANDOM`: `secret` is the master secret for a TLSv1.2 session.
    /// - `CLIENT_EARLY_TRAFFIC_SECRET`: `secret` encrypts early data
    ///   transmitted by a client
    /// - `SERVER_HANDSHAKE_TRAFFIC_SECRET`: `secret` encrypts
    ///   handshake messages from the server during a TLSv1.3 handshake.
    /// - `CLIENT_HANDSHAKE_TRAFFIC_SECRET`: `secret` encrypts
    ///   handshake messages from the client during a TLSv1.3 handshake.
    /// - `SERVER_TRAFFIC_SECRET_0`: `secret` encrypts post-handshake data
    ///   from the server in a TLSv1.3 session.
    /// - `CLIENT_TRAFFIC_SECRET_0`: `secret` encrypts post-handshake data
    ///   from the client in a TLSv1.3 session.
    /// - `EXPORTER_SECRET`: `secret` is the post-handshake exporter secret
    ///   in a TLSv1.3 session.
    ///
    /// These strings are selected to match the NSS key log format:
    /// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
}

/// `KeyLog` implementation that opens a file whose name is
/// given by the `SSLKEYLOGFILE` environment variable, and writes
/// keys into it.
///
/// If `SSLKEYLOGFILE` is not set, this does nothing.
///
/// If such a file cannot be opened, or cannot be written then
/// this does nothing but logs errors at warning-level.
pub struct KeyLogFile(Mutex<KeyLogFileInner>);

impl KeyLogFile {
    /// Makes a new `KeyLogFile`.  The environment variable is
    /// inspected and the named file is opened during this call.
    pub fn new() -> Self {
        let var = env::var_os("SSLKEYLOGFILE");
        KeyLogFile(Mutex::new(KeyLogFileInner::new(var)))
    }
}

impl Default for KeyLogFile {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match self
            .0
            .lock()
            .unwrap()
            .try_write(label, client_random, secret)
        {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!("error writing to key log file: {}", e);
            }
        }
    }
}

// Internal mutable state for KeyLogFile
struct KeyLogFileInner {
    file: Option<BufWriter<File>>,
}

impl KeyLogFileInner {
    fn new(var: Option<OsString>) -> Self {
        let Some(path) = var else {
            return KeyLogFileInner { file: None };
        };
        let path = Path::new(&path);

        let file = match OpenOptions::new().append(true).create(true).open(path) {
            Ok(f) => Some(BufWriter::new(f)),
            Err(e) => {
                tracing::warn!("unable to create key log file {:?}: {}", path, e);
                None
            }
        };

        KeyLogFileInner { file }
    }

    fn try_write(&mut self, label: &str, client_random: &[u8], secret: &[u8]) -> io::Result<()> {
        let Some(ref mut file) = self.file else {
            return Ok(());
        };

        write!(file, "{label} ")?;
        for b in client_random.iter() {
            write!(file, "{:02x}", b)?;
        }
        write!(file, " ")?;
        for b in secret.iter() {
            write!(file, "{:02x}", b)?;
        }
        writeln!(file)
    }
}

#[cfg(all(test, target_family = "unix"))]
mod test {
    use super::*;

    #[test]
    fn test_env_var_is_not_set() {
        let mut inner = KeyLogFileInner::new(None);
        assert!(inner.try_write("label", b"random", b"secret").is_ok());
    }

    #[test]
    fn test_env_var_cannot_be_opened() {
        let mut inner = KeyLogFileInner::new(Some("/dev/does-not-exist".into()));
        assert!(inner.try_write("label", b"random", b"secret").is_ok());
    }

    // doesn't seem to fail on macos
    #[cfg(target_os = "linux")]
    #[test]
    fn test_env_var_cannot_be_written() {
        let mut inner = KeyLogFileInner::new(Some("/dev/full".into()));
        assert!(inner.try_write("label", b"random", b"secret").is_err());
    }
}
