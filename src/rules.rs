use serde::{Deserialize, Serialize};

use crate::{
    errors::SanitizerError,
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
#[derive(Clone, Debug, Serialize)]
pub struct RuleWithReplace<R: Default> {
    replace: R,
    level: LogLevel,
}

impl<R: Default> RuleWithReplace<R> {
    pub fn new(replace: R, level: LogLevel) -> Self {
        Self { replace, level }
    }

    pub fn is_ignore(&self) -> bool {
        self.level.is_ignore()
    }

    pub fn handle<T, F: FnOnce(&R) -> T, M: Into<SanitizerError>>(
        &self,
        logger: &impl LoggerTrait,
        replace: F,
        message: M,
    ) -> Result<T, M> {
        self.level
            .handle(logger, message)
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

#[derive(Copy, Clone, Debug, Serialize)]
pub struct RuleWithValue<T: 'static> {
    pub value: T,
    pub level: LogLevel,
}

impl<T> RuleWithValue<T> {
    pub fn new(value: T, level: LogLevel) -> Self {
        Self { value, level }
    }

    pub fn handle<M: Into<SanitizerError>>(
        &self,
        logger: &impl LoggerTrait,
        message: M,
    ) -> Result<(), M> {
        self.level.handle(logger, message)
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
