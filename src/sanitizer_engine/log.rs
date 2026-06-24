use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::{error::Error, fs::File};

use chrono::Local;
use colored::Colorize;
use itertools::Itertools;
use serde::Deserialize;

use crate::sanitizer_engine::errors::LoggerError;
use crate::sanitizer_engine::policy::Policy;

pub trait LoggerTrait {
    fn log<E: Into<LoggerError>>(&self, level: LogLevel, error: E);

    #[inline]
    fn trace<E: Into<LoggerError>>(&self, error: E) {
        self.log(LogLevel::Trace, error);
    }

    #[inline]
    fn debug<E: Into<LoggerError>>(&self, error: E) {
        self.log(LogLevel::Debug, error);
    }

    #[inline]
    fn info<E: Into<LoggerError>>(&self, error: E) {
        self.log(LogLevel::Info, error);
    }

    #[inline]
    fn warn<E: Into<LoggerError>>(&self, error: E) {
        self.log(LogLevel::Warn, error);
    }

    #[inline]
    fn error<E: Into<LoggerError>>(&self, error: E) {
        self.log(LogLevel::Error, error);
    }
}

pub struct Logger {
    pub index: usize,
    pub channel: Sender<LoggerMessage>,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Returns `Err` if `self == Error`, otherwise returns `Ok` and logs the error message
    pub fn handle<E: Into<LoggerError>>(
        self,
        logger: &impl LoggerTrait,
        error: E,
    ) -> Result<(), E> {
        if self == LogLevel::Error {
            Err(error)
        } else {
            logger.log(self, error);
            Ok(())
        }
    }
}

impl LoggerTrait for Logger {
    fn log<E: Into<LoggerError>>(&self, level: LogLevel, error: E) {
        self.channel
            .send(LoggerMessage {
                source: self.index,
                level,
                error: error.into(),
            })
            .unwrap();
    }
}

impl LoggerTrait for (usize, &Sender<LoggerMessage>) {
    fn log<E: Into<LoggerError>>(&self, level: LogLevel, error: E) {
        self.1
            .send(LoggerMessage {
                source: self.0,
                level,
                error: error.into(),
            })
            .unwrap();
    }
}

pub struct LoggerMessage {
    source: usize,
    level: LogLevel,
    error: Box<dyn Error + Send>,
}

pub fn logging_thread(
    output: &Path,
    policy: &Policy,
    max_size: usize,
    channel: Receiver<LoggerMessage>,
) {
    let mut files = (0..max_size)
        .map(|i| File::create(output.join(format!("{i}.log"))).ok())
        .collect_vec();

    let width = (max_size as f64).log10().ceil() as usize;

    for msg in channel {
        let error = msg.error.to_string();

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
}
