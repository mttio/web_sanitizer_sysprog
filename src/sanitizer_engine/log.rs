use std::{error::Error, path::PathBuf, sync::Arc};

use colored::Colorize;

pub struct Logger {
    pub path: Arc<PathBuf>,
    pub index: usize,
    pub max_size: usize,
}

pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Logger {
    pub fn log<E: Into<Box<dyn Error>>>(&self, level: LogLevel, error: E) {
        println!(
            "[{:width$}] {}: {}",
            self.index,
            match level {
                LogLevel::Trace => "TRACE".bright_black(),
                LogLevel::Debug => "DEBUG".bright_blue(),
                LogLevel::Info => " INFO".bright_green(),
                LogLevel::Warn => " WARN".bright_yellow(),
                LogLevel::Error => "ERROR".bright_red(),
            }
            .bold(),
            error.into().to_string().italic(),
            width = self.max_size,
        );
    }

    #[inline]
    pub fn trace<E: Into<Box<dyn Error>>>(&self, error: E) {
        self.log(LogLevel::Trace, error);
    }

    #[inline]
    pub fn debug<E: Into<Box<dyn Error>>>(&self, error: E) {
        self.log(LogLevel::Debug, error);
    }

    #[inline]
    pub fn info<E: Into<Box<dyn Error>>>(&self, error: E) {
        self.log(LogLevel::Info, error);
    }

    #[inline]
    pub fn warn<E: Into<Box<dyn Error>>>(&self, error: E) {
        self.log(LogLevel::Warn, error);
    }

    #[inline]
    pub fn error<E: Into<Box<dyn Error>>>(&self, error: E) {
        self.log(LogLevel::Error, error);
    }
}
