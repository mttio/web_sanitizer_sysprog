use nutype::nutype;
use serde::{Deserialize, Serialize};

use crate::{
    errors::SanitizerError,
    log::{Log, LogLevel},
};

#[nutype(
    derive(Debug, Deref, Serialize, Deserialize, Default),
    default = "/* Blocked by Web Sanitizer: dangerous keywords found */"
)]
pub struct JsReplace(String);

/// A rule that can replace undesired values
///
/// Can be specified in the config in different ways:
/// ```toml
/// rule = "level"                          # only log level, replaces with default value
/// rule = true                             # same as "warn"
/// rule = false                            # doesn't replace, log level is "warn"
/// rule = value                            # replacement value, log level is "warn"
/// rule = { replace = ..., level = ... }   # both replacement value and log level
/// rule = { replace = true, level = ... }  # replaces with default value
/// rule = { replace = false, level = ... } # doesn't replace
/// ```
#[derive(Clone, Debug, Serialize)]
pub struct RuleWithReplace<R: Default> {
    /// What to replace the undesired value with. If `None`, it is not replaced
    replace: Option<R>,
    /// The log level associated with this rule. If `Error`, the sanitization should stop
    level: LogLevel,
}

impl<R: Default> RuleWithReplace<R> {
    pub fn new(replace: impl Into<R>, level: LogLevel) -> Self {
        Self {
            replace: Some(replace.into()),
            level,
        }
    }

    pub fn keep(level: LogLevel) -> Self {
        Self {
            replace: None,
            level,
        }
    }

    pub fn with_default(level: LogLevel) -> Self {
        Self::new(R::default(), level)
    }

    /// Returns `Err` if `self.level == Error`
    /// Otherwise logs the message, calls `replace` with the contained value and returns `Ok` with the mapped value
    pub fn handle_with<T, F: FnOnce(&R) -> T, M: Into<SanitizerError>>(
        &self,
        logger: &impl Log,
        replace: F,
        message: M,
    ) -> Result<Option<T>, M> {
        self.level
            .handle(logger, message)
            .map(|_| self.replace.as_ref().map(replace))
    }

    /// Returns `Err` if `self.level == Error`
    /// Otherwise logs the message and returns `Ok` with the replace value
    pub fn handle<M: Into<SanitizerError>>(
        &self,
        logger: &impl Log,
        message: M,
    ) -> Result<Option<&R>, M> {
        self.level
            .handle(logger, message)
            .map(|_| self.replace.as_ref())
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
            Level(LogLevel),
            Bool(bool),
            Value { replace: R },
            ValueLevel { replace: R, level: LogLevel },
            BoolLevel { replace: bool, level: LogLevel },
        }

        Ok(match Inner::deserialize(deserializer)? {
            Inner::Level(level) => Self {
                replace: Some(R::default()),
                level,
            },
            Inner::Bool(replace) => Self {
                replace: replace.then(R::default),
                level: LogLevel::Warn,
            },
            Inner::Value { replace } => Self {
                replace,
                level: LogLevel::Warn,
            },
            Inner::ValueLevel { replace, level } => Self { replace, level },
            Inner::BoolLevel { replace, level } => Self {
                replace: replace.then(R::default),
                level,
            },
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

    pub fn handle<M: Into<SanitizerError>>(&self, logger: &impl Log, message: M) -> Result<(), M> {
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
