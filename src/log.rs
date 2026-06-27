use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};

use chrono::Local;
use colored::Colorize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::errors::SanitizerMessage;
use crate::policy::Policy;

pub trait LoggerTrait {
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

pub struct Logger {
    pub index: usize,
    pub channel: Sender<LoggerMessage>,
}

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
    pub fn handle<T: Into<SanitizerMessage>>(
        self,
        logger: &impl LoggerTrait,
        message: T,
    ) -> Result<(), T> {
        if self == LogLevel::Error {
            Err(message)
        } else {
            logger.log(self, message);
            Ok(())
        }
    }
}

impl LoggerTrait for Logger {
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

impl LoggerTrait for (usize, &Sender<LoggerMessage>) {
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
}
