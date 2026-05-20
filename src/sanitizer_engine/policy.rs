use serde::Deserialize;
use url::Host;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Replace,
    Warn,
    WarnAndReplace,
    Deny,
}

#[derive(Debug)]
pub struct PolicyHost(Host);

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
}

#[derive(Debug, Deserialize)]
pub struct HtmlPolicy {
    pub allow_scripts: Vec<String>,
    pub allow_origins: Vec<PolicyHost>,
    pub strip_event_handlers: bool,
    pub rewrite_dangerous_uris: bool,
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
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UrlsPolicy {
    pub dangerous_domains: Vec<PolicyHost>,
    pub dangerous_domain_action: PolicyAction,
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
            dangerous_domain_action: PolicyAction::WarnAndReplace,
            idn_action: PolicyAction::Deny,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResourcesPolicy {
    pub fetch_sub_resources: bool,
    pub max_depth: usize,
    pub max_bytes: usize,
    pub max_requests: usize,
}

impl Default for ResourcesPolicy {
    fn default() -> Self {
        Self {
            fetch_sub_resources: true,
            max_depth: 1,
            max_bytes: 1024 * 1024,
            max_requests: 5,
        }
    }
}
