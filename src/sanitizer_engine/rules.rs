use serde::Deserialize;

use crate::sanitizer_engine::{
    errors::LoggerError,
    log::{LogLevel, LoggerTrait},
};

/// A rule that can replace undesired values
///
/// Can be specified in the config in different ways:
/// ```toml
/// rule = "level" # only log level, uses default value as replacement
/// rule = [value, "level"] # both replacement value and log level
/// rule = { value = ..., level = ... } # both replacement value and log level
/// ```
#[derive(Clone, Debug)]
pub struct RuleWithReplace<R: Default> {
    replace: R,
    level: LogLevel,
}

impl<R: Default> RuleWithReplace<R> {
    pub fn new(replace: R, level: LogLevel) -> Self {
        Self { replace, level }
    }

    pub fn handle<T, F: FnOnce(&R) -> T, E: Into<LoggerError>>(
        &self,
        logger: &impl LoggerTrait,
        replace: F,
        error: E,
    ) -> Result<T, E> {
        self.level
            .handle(logger, error)
            .map(|_| replace(&self.replace))
    }
}

impl<'de, R: Default + Deserialize<'de>> Deserialize<'de> for RuleWithReplace<R> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<R> {
            Simple(LogLevel),
            OnlyReplace { replace: R },
            WithLevel { replace: R, level: LogLevel },
        }

        Ok(match Inner::deserialize(deserializer)? {
            Inner::Simple(level) => Self {
                replace: R::default(),
                level,
            },
            Inner::OnlyReplace { replace } => Self {
                replace,
                level: LogLevel::Warn,
            },
            Inner::WithLevel { replace, level } => Self { replace, level },
        })
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RuleWithValue<T: 'static> {
    pub value: T,
    pub level: LogLevel,
}

impl<T> RuleWithValue<T> {
    pub fn new(value: T, level: LogLevel) -> Self {
        Self { value, level }
    }

    pub fn handle<E: Into<LoggerError>>(
        &self,
        logger: &impl LoggerTrait,
        error: E,
    ) -> Result<(), E> {
        self.level.handle(logger, error)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for RuleWithValue<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<T> {
            Value(T),
            Tuple(T, LogLevel),
            Table { value: T, level: LogLevel },
        }

        Ok(match Inner::deserialize(deserializer)? {
            Inner::Value(value) => Self {
                value,
                level: LogLevel::Error,
            },
            Inner::Tuple(value, level) => Self { value, level },
            Inner::Table { value, level } => Self { value, level },
        })
    }
}
