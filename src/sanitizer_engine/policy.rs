use std::{error::Error, time::Duration};

use serde::Deserialize;
use url::Host;

use crate::sanitizer_engine::log::Logger;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Warn,
    Deny,
}

impl PolicyAction {
    pub fn handle_error<E: Into<Box<dyn Error>>>(self, logger: &Logger, error: E) -> Result<(), E> {
        match self {
            Self::Allow => {
                logger.info(error);
                Ok(())
            }
            Self::Warn => {
                logger.warn(error);
                Ok(())
            }
            Self::Deny => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActionReplace {
    Allow,
    Replace,
    Warn,
    WarnAndReplace,
    Deny,
}

impl PolicyActionReplace {
    pub fn handle_error<T, F: FnOnce() -> T, E: Into<Box<dyn Error>>>(
        self,
        logger: &Logger,
        rewrite: F,
        error: E,
    ) -> Result<Option<T>, E> {
        match self {
            Self::Allow => {
                logger.info(error);
                Ok(None)
            }
            Self::Replace => {
                logger.info(error);
                Ok(Some(rewrite()))
            }
            Self::Warn => {
                logger.warn(error);
                Ok(None)
            }
            Self::WarnAndReplace => {
                logger.error(error);
                Ok(Some(rewrite()))
            }
            Self::Deny => Err(error),
        }
    }
}

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

#[derive(Debug, Default, Deserialize)]
pub struct Policy {
    pub html: HtmlPolicy,
    pub urls: UrlsPolicy,
    pub resources: ResourcesPolicy,
    pub connections: ConnectionsPolicy,
}

#[derive(Debug, Deserialize)]
pub struct HtmlPolicy {
    pub allow_scripts: Vec<String>,
    pub allow_origins: Vec<PolicyHost>,
    pub strip_event_handlers: bool,
    pub rewrite_dangerous_uris: bool,
    /// Action to perform when a dangerous domain is encountered
    pub dangerous_domain_action: PolicyActionReplace,
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
            strip_event_handlers: true,
            rewrite_dangerous_uris: true,
            dangerous_domain_action: PolicyActionReplace::WarnAndReplace,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UrlsPolicy {
    /// List of domains considered dangerous
    /// Ignores prefix labels (e.g. `youtube.com` matches `www.youtube.com`)
    pub dangerous_domains: Vec<PolicyHost>,
    /// Action to perform when a non-latin url is encountered
    pub idn_action: PolicyAction,
}

impl Default for UrlsPolicy {
    fn default() -> Self {
        Self {
            dangerous_domains: ["malicious-domain.com", "evil.com"]
                .into_iter()
                .flat_map(Host::parse)
                .map(PolicyHost)
                .collect(),
            idn_action: PolicyAction::Deny,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResourcesPolicy {
    pub fetch_sub_resources: bool,
    pub max_depth: usize,
    pub max_bytes: usize,
    pub max_bytes_action: PolicyAction,
    pub max_requests: usize,
}

impl Default for ResourcesPolicy {
    fn default() -> Self {
        Self {
            fetch_sub_resources: true,
            max_depth: 1,
            max_bytes: 1024 * 1024,
            max_bytes_action: PolicyAction::Deny,
            max_requests: 5,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ConnectionsPolicy {
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub overall_timeout: Duration,
    /// Maximum number of redirects for a single connection
    pub max_redirects: Option<usize>,
    /// Action to perform when a connection exceeds `max_redirects`
    pub max_redirects_action: PolicyAction,
    /// User agent to include in every request
    pub user_agent: String,
    /// Action to perform when connecting to a dangerous domain
    pub dangerous_domain_action: PolicyAction,
}

impl Default for ConnectionsPolicy {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(3),
            overall_timeout: Duration::from_secs(15),
            max_redirects: Some(2),
            max_redirects_action: PolicyAction::Deny,
            user_agent: "CoolBot/0.0 (https://example.org/coolbot/; coolbot@example.org) generic-library/0.0".to_owned(),
            dangerous_domain_action: PolicyAction::Deny,
        }
    }
}
