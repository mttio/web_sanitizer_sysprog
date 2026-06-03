use crate::sanitizer_engine::engine_structs::{FetchedContent, InputSource};
use crate::sanitizer_engine::errors::{ContentTooLong, DangerousDomain, IDN, TooManyRedirects};
use crate::sanitizer_engine::html::create_rewriter;
use crate::sanitizer_engine::log::Logger;
use crate::sanitizer_engine::policy::Policy;
use crate::sanitizer_engine::url::{RuleMatch, check_domain};
use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use hickory_resolver::TokioResolver;
use itertools::Itertools;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, header, redirect};
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/*================== HELPERS ===================*/

/// Validates if an Ip address is safe (blocks all SSRF-relevant ranges)
fn is_safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !is_v4_cgnat(v4)
                && !is_v4_reserved(v4)
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback() && !is_v6_private(v6) && !v6.is_multicast() && !v6.is_unspecified()
        }
    }
}

/// 100.64.0.0/10 – CGNAT (carrier grade NAT).
/// Commonly used internally by cloud providers; known SSRF vector.
fn is_v4_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// TEST-NET developers ranges and the reserved-for-future-use 240.0.0.0/4 block.
fn is_v4_reserved(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    (o[0] == 192 && o[1] == 0   && o[2] == 2)   ||   // 192.0.2.0/24    TEST-NET-1
    (o[0] == 198 && o[1] == 51  && o[2] == 100)  ||  // 198.51.100.0/24 TEST-NET-2
    (o[0] == 203 && o[1] == 0   && o[2] == 113)  ||  // 203.0.113.0/24  TEST-NET-3
    o[0] >= 240 // 240.0.0.0/4     Reserved
}

/// Returns true if the IPv6 address is in a private/local range
fn is_v6_private(v6: Ipv6Addr) -> bool {
    // Unique Local Address (fc00::/7)
    (v6.segments()[0] & 0xfe00) == 0xfc00
        // Link-local (fe80::/10)
        || (v6.segments()[0] & 0xffc0) == 0xfe80
        // IPv4-mapped ::ffff:0:0/96 – re-uses v4 checks
        || v6
            .to_ipv4_mapped()
            .map(|v4| !is_safe_ip(IpAddr::V4(v4)))
            .unwrap_or(false)
}

/*================== SSRF-SAFE DNS RESOLVER ===================*/

// We use reqwest's DNS layer for controlling which IPs are actually used.
// The original hostname stays in the request URL, so TLS SNI and certificate validation work correctly.
// We provide DNS resolution itself an independent timeout.
struct SsrfSafeDnsResolver {
    inner: Arc<TokioResolver>,
    timeout: Duration,
}

impl Resolve for SsrfSafeDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = self.inner.clone();
        let timeout = self.timeout;
        let host = name.as_str().to_owned();

        Box::pin(async move {
            // setting independent timeout on DNS resolution
            let lookup = tokio::time::timeout(timeout, inner.lookup_ip(host.as_str()))
                .await
                .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("DNS resolution timed out for host: {}", host).into()
                })?
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("DNS lookup failed for host {}: {}", host, e).into()
                })?;

            // Filter to safe IPs only;
            // reqwest automatically replaces port 0 with the Url's actual port when connecting
            let safe_addrs: Vec<SocketAddr> = lookup
                .iter()
                .filter(|ip| is_safe_ip(*ip))
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();

            if safe_addrs.is_empty() {
                return Err(format!("No safe IP addresses found for host: {}", host).into());
            }

            Ok(Box::new(safe_addrs.into_iter()) as Addrs)
        })
    }
}

/*================== STRUCTS ===================*/

/// A reusable HTTP client implementing Anti-SSRF and security controls
pub struct SanitizerHttpClient {
    client: reqwest::Client,
}

impl SanitizerHttpClient {
    /// Creates a new SanitizerHttpClient instance
    pub async fn new(policy: &Policy) -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .context("Failed to create DNS resolver builder")?
            .build()
            .context("Failed to build DNS resolver")?;

        let ssrf_safe_resolver = SsrfSafeDnsResolver {
            inner: Arc::new(resolver),
            // Reuse the connection timeout for DNS. This avoids an extra policy field
            timeout: policy.connections.connection_timeout,
        };

        let max_redirects = policy.connections.max_redirects;
        let max_redirects_action = policy.connections.max_redirects_action;
        let dangerous_hosts = policy
            .urls
            .dangerous_domains
            .iter()
            .map(|x| x.0.clone())
            .collect_vec();
        let dangerous_domain_action = policy.connections.dangerous_domain_action;
        let idn_action = policy.urls.idn_action;

        let logger = Logger {
            path: Arc::new(PathBuf::new()),
            index: 0,
            max_size: 1,
        };

        let client = Client::builder()
            // Set custom Ip resolver
            .dns_resolver(Arc::new(ssrf_safe_resolver))
            .connect_timeout(policy.connections.connection_timeout)
            .timeout(policy.connections.overall_timeout)
            .user_agent(&policy.connections.user_agent)
            // Disable redirects
            .redirect(redirect::Policy::custom(move |attempt| {
                let check = || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    if let Some(original) = check_domain(attempt.url()) {
                        idn_action.handle_error(&logger, IDN(original))?;
                    }

                    if let Some(max_redirects) = max_redirects
                        && attempt.previous().len() == max_redirects + 1
                    {
                        max_redirects_action.handle_error(&logger, TooManyRedirects)?;
                    }

                    if let Some(host) = attempt.url().host().map(|x| x.to_owned())
                        && dangerous_hosts.iter().any(|x| host.matches(x))
                    {
                        dangerous_domain_action
                            .handle_error(&logger, DangerousDomain(host.to_owned()))?;
                    }

                    Ok(())
                };

                match check() {
                    Ok(_) => attempt.follow(),
                    Err(e) => attempt.error(e),
                }
            }))
            // Enforce TLS 1.2+
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .context("Failed to build reqwest client")?;

        Ok(Self { client })
    }

    /// Fetch a single URL with security controls
    pub async fn fetch_one_url(
        &self,
        url: &Url,
        logger: &Logger,
        output: File,
        policy: &Policy,
    ) -> Result<FetchedContent> {
        if url.scheme() != "https" {
            return Err(anyhow!("Only HTTPS URLs are permitted"));
        }

        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("Request failed for URL: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Server returned error status: {}",
                response.status()
            ));
        }

        let max_bytes = policy.resources.max_bytes;

        // Fast-fail for `Content-Length` header
        if let Some(length) = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|x| x.to_str().ok())
            .and_then(|x| x.parse::<usize>().ok())
            && length > max_bytes
        {
            return Err(ContentTooLong(max_bytes).into());
        }

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        // Stream body with byte limit to prevent memory exhaustion
        let mut stream = response.bytes_stream();
        let mut length = 0;

        let mut rewriter = create_rewriter(logger, policy, output);

        while let Some(item) = stream.next().await {
            let chunk = item.context("Error while streaming body")?;

            length += chunk.len();
            if length > max_bytes {
                return Err(ContentTooLong(max_bytes).into());
            }

            rewriter.write(&chunk)?;
        }

        rewriter.end()?;

        Ok(FetchedContent {
            source: InputSource::Url(url.clone()),
            data: Vec::new(),
            content_type,
        })
    }
}

/*================== MAIN FUNCTIONS ===================*/

/// Fetch multiple URLs and return their content
pub async fn fetch_multiple_urls(
    sources: Vec<InputSource>,
    policy: &Policy,
) -> Result<(Vec<FetchedContent>, Vec<anyhow::Error>)> {
    let mut results_vec = Vec::new();
    let mut errors_vec = Vec::<anyhow::Error>::new();

    let client = SanitizerHttpClient::new(policy).await?;

    for input_source in sources {
        // if let InputSource::Url(url) = input_source {
        //     match client.fetch_one_url(&url, policy).await {
        //         Ok(res) => results_vec.push(res),
        //         Err(e) => errors_vec.push(anyhow!(
        //             "Could not fetch url {}: {}",
        //             url,
        //             e.source().unwrap().source().unwrap()
        //         )),
        //     }
        // }
    }
    Ok((results_vec, errors_vec))
}

/*================== TESTS ===================*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_safe_ip_v4() {
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))); // loopback
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))); // private
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))); // private
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)))); // private
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)))); // link-local
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))); // CGNAT start
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255)))); // CGNAT end
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))); // TEST-NET-1
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))); // TEST-NET-2
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))); // TEST-NET-3
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)))); // Reserved
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)))); // Broadcast
        assert!(is_safe_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_safe_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_safe_ip_v6() {
        assert!(!is_safe_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1
        )))); // ::1 loopback
        assert!(!is_safe_ip(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )))); // ULA
        assert!(!is_safe_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )))); // link-local
        assert!(is_safe_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        )))); // Google DNS
    }

    #[test]
    fn test_is_v4_cgnat() {
        assert!(is_v4_cgnat(Ipv4Addr::new(100, 64, 0, 1))); // start of range
        assert!(is_v4_cgnat(Ipv4Addr::new(100, 127, 255, 255))); // end of range
        assert!(is_v4_cgnat(Ipv4Addr::new(100, 100, 1, 1))); // middle of range
        assert!(!is_v4_cgnat(Ipv4Addr::new(100, 63, 255, 255))); // just below range
        assert!(!is_v4_cgnat(Ipv4Addr::new(100, 128, 0, 0))); // just above range
        assert!(!is_v4_cgnat(Ipv4Addr::new(8, 8, 8, 8))); // public
    }

    #[test]
    fn test_is_v4_reserved() {
        assert!(is_v4_reserved(Ipv4Addr::new(192, 0, 2, 1))); // TEST-NET-1
        assert!(is_v4_reserved(Ipv4Addr::new(198, 51, 100, 1))); // TEST-NET-2
        assert!(is_v4_reserved(Ipv4Addr::new(203, 0, 113, 1))); // TEST-NET-3
        assert!(is_v4_reserved(Ipv4Addr::new(240, 0, 0, 1))); // Reserved
        assert!(is_v4_reserved(Ipv4Addr::new(255, 255, 255, 255))); // Broadcast
        assert!(!is_v4_reserved(Ipv4Addr::new(8, 8, 8, 8))); // public
        assert!(!is_v4_reserved(Ipv4Addr::new(1, 1, 1, 1))); // public
    }
}
