use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Serialize};
use url::Host;

use crate::{
    log::LogLevel,
    rules::{RuleWithReplace, RuleWithValue},
};

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyHost(pub Host);

impl<'de> Deserialize<'de> for PolicyHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Host::parse(&string)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for PolicyHost {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Logging {
    /// Minimum log level to write on log files
    pub files: LogLevel,
    /// Minimum log level to write on the console
    pub console: LogLevel,
}

impl Default for Logging {
    fn default() -> Self {
        Self {
            files: LogLevel::Trace,
            console: LogLevel::Warn,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Policy {
    pub logging: Logging,
    pub html: HtmlPolicy,
    pub urls: UrlsPolicy,
    pub resources: ResourcesPolicy,
    pub connections: ConnectionsPolicy,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct HtmlPolicy {
    pub allow_scripts: Vec<String>,
    pub allow_origins: Vec<PolicyHost>,
    /// Action to perform when an event handler is encountered
    pub event_handlers: RuleWithReplace<String>,
    /// Action to perform when a dangerous domain is encountered
    pub dangerous_domain: RuleWithReplace<String>,
    /// Action to perform when a dangerous URI (javascript:, data:) is encountered
    pub dangerous_uris: RuleWithReplace<String>,
}

impl Default for HtmlPolicy {
    fn default() -> Self {
        Self {
            allow_scripts: vec![],
            allow_origins: ["trusted.com"]
                .into_iter()
                .flat_map(Host::parse)
                .map(PolicyHost)
                .collect(),
            event_handlers: RuleWithReplace::new("".to_owned(), LogLevel::Info),
            dangerous_domain: RuleWithReplace::new("#".to_owned(), LogLevel::Error),
            dangerous_uris: RuleWithReplace::new("#".to_owned(), LogLevel::Info),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct UrlsPolicy {
    /// List of domains considered dangerous
    /// Ignores prefix labels (e.g. `youtube.com` matches `www.youtube.com`)
    pub dangerous_domains: Vec<PolicyHost>,
    /// Action to perform when a non-latin url is encountered
    pub idn: LogLevel,
}

impl Default for UrlsPolicy {
    fn default() -> Self {
        Self {
            dangerous_domains: ["malicious-domain.com", "evil.com"]
                .into_iter()
                .flat_map(Host::parse)
                .map(PolicyHost)
                .collect(),
            idn: LogLevel::Warn,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ResourcesPolicy {
    pub fetch_sub_resources: bool,
    pub max_depth: RuleWithValue<usize>,
    pub max_bytes: RuleWithValue<usize>,
    pub max_requests: RuleWithValue<usize>,
    pub mismatched_mime: LogLevel,
    pub unknown_resource: LogLevel,
    pub pdf_active_content: LogLevel,
}

impl Default for ResourcesPolicy {
    fn default() -> Self {
        Self {
            fetch_sub_resources: true,
            max_depth: RuleWithValue::new(1, LogLevel::Error),
            max_bytes: RuleWithValue::new(1024 * 1024, LogLevel::Error),
            max_requests: RuleWithValue::new(5, LogLevel::Error),
            mismatched_mime: LogLevel::Error,
            unknown_resource: LogLevel::Error,
            pdf_active_content: LogLevel::Error,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ConnectionsPolicy {
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub overall_timeout: Duration,
    /// Maximum number of redirects for a single connection
    pub max_redirects: RuleWithValue<usize>,
    /// User agent to include in every request
    pub user_agent: String,
    /// Action to perform when connecting to a dangerous domain
    pub dangerous_domain: LogLevel,
}

impl Default for ConnectionsPolicy {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(3),
            overall_timeout: Duration::from_secs(15),
            max_redirects: RuleWithValue::new(2, LogLevel::Error),
            user_agent: "CoolBot/0.0 (https://example.org/coolbot/; coolbot@example.org) generic-library/0.0".to_owned(),
            dangerous_domain: LogLevel::Error,
        }
    }
}
