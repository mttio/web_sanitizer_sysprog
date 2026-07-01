use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};

use chrono::Local;
use colored::Colorize;
use itertools::Itertools;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::errors::SanitizerMessage;
use crate::policy::Policy;

#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Returns `Err` if `self == Error`, otherwise returns `Ok` and logs the message
    pub fn handle<T: Into<SanitizerMessage>>(self, logger: &impl Log, message: T) -> Result<(), T> {
        if self == LogLevel::Error {
            Err(message)
        } else {
            logger.log(self, message);
            Ok(())
        }
    }
}

/// A trait for logging messages
pub trait Log: Sync {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T);

    #[inline]
    fn trace<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Trace, message);
    }

    #[inline]
    fn debug<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Debug, message);
    }

    #[inline]
    fn info<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Info, message);
    }

    #[inline]
    fn warn<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Warn, message);
    }

    #[inline]
    fn error<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Error, message);
    }
}

#[derive(Clone)]
pub struct ChannelLogger {
    pub index: usize,
    pub channel: Sender<LoggerMessage>,
}

impl Log for ChannelLogger {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T) {
        self.channel
            .send(LoggerMessage {
                source: self.index,
                level,
                message: message.into(),
            })
            .unwrap();
    }
}

impl Log for (usize, &Sender<LoggerMessage>) {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T) {
        self.1
            .send(LoggerMessage {
                source: self.0,
                level,
                message: message.into(),
            })
            .unwrap();
    }
}

pub struct LoggerMessage {
    source: usize,
    level: LogLevel,
    message: SanitizerMessage,
}

/// A logger that stores messages in a `Vec`, with interior mutability
#[derive(Default)]
pub struct VecLogger(Mutex<Vec<(LogLevel, SanitizerMessage)>>);

impl VecLogger {
    pub fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }
}

impl Log for VecLogger {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T) {
        self.0.lock().push((level, message.into()));
    }
}

/// A logger that discards all messages
#[derive(Default)]
pub struct NullLogger;

impl Log for NullLogger {
    fn log<T: Into<SanitizerMessage>>(&self, _: LogLevel, _: T) {}
}

pub fn logging_thread(
    output: &Path,
    policy: &Policy,
    max_size: usize,
    channel: Receiver<LoggerMessage>,
) -> bool {
    let mut files = (0..max_size)
        .map(|i| File::create(output.join(format!("{i}.log"))).ok())
        .collect_vec();

    let width = (max_size as f64).log10().ceil() as usize;
    let mut has_errors = false;

    for msg in channel {
        if msg.level == LogLevel::Error {
            has_errors = true;
        }
        let error = msg.message.to_string();

        if msg.level >= policy.logging.console {
            println!(
                "[{}] {}: {}",
                format!("{:width$}", msg.source).bold().bright_blue(),
                match msg.level {
                    LogLevel::Trace => "TRACE".bright_black(),
                    LogLevel::Debug => "DEBUG".bright_blue(),
                    LogLevel::Info => " INFO".bright_green(),
                    LogLevel::Warn => " WARN".bright_yellow(),
                    LogLevel::Error => "ERROR".bright_red(),
                }
                .bold(),
                error.italic(),
            );
        }

        if msg.level >= policy.logging.files
            && let Some(Some(file)) = files.get_mut(msg.source)
        {
            let now = Local::now().naive_local();
            let _ = writeln!(
                file,
                "[{}] ({:width$}) {}: {}",
                now.format("%Y-%m-%d %H:%M:%S%.3f"),
                msg.source,
                match msg.level {
                    LogLevel::Trace => "TRACE",
                    LogLevel::Debug => "DEBUG",
                    LogLevel::Info => " INFO",
                    LogLevel::Warn => " WARN",
                    LogLevel::Error => "ERROR",
                },
                strip_ansi_escapes::strip_str(&error),
            );
        }
    }
    has_errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawl_session::CrawlSession;
    use crate::http_client::SanitizerHttpClient;
    use crate::policy::Policy;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Arc;

    #[test]
    fn test_xml_bomb_rejection() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("temp_xml_bomb.html");
        fs::write(
            &file_path,
            b"<!DOCTYPE xmlbomb [ <!ENTITY lol 'lol'> ]><html></html>",
        )
        .unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let logger = ChannelLogger {
            index: 0,
            channel: tx,
        };

        let policy = Arc::new(Policy::default());
        let url_map = Arc::new(Mutex::new(HashMap::new()));
        let client = Arc::new(
            SanitizerHttpClient::new(policy.clone(), logger.channel.clone(), url_map.clone())
                .unwrap(),
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();

        let session = Arc::new(CrawlSession::new(
            client,
            policy,
            logger,
            runtime.handle().clone(),
            Arc::new(temp_dir.clone()),
            url_map,
        ));

        session.process_file(file_path.clone());

        // Clean up temp file
        let _ = fs::remove_file(file_path);

        // Retrieve the logged error
        let msg = rx.try_recv().expect("Expected a log message");
        let err_str = msg.message.to_string();
        assert!(err_str.contains("custom XML entity declaration detected"));
    }
}
