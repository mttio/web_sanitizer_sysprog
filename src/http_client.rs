use crate::engine_structs::{FetchedContent, InputSource};
use crate::errors::SanitizerError;
use crate::html::{CrawlerState, create_rewriter};
use crate::log::{Logger, LoggerMessage};
use crate::policy::Policy;
use crate::url::{RuleMatch, check_domain};
use std::path::Path;

use futures_util::StreamExt;
use hickory_resolver::TokioResolver;
use parking_lot::Mutex;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, header, redirect};
use std::collections::HashMap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Duration;
use url::Url;

/*================== HELPERS ===================*/

/// Validates if an IP address is safe (blocks all SSRF-relevant private/loopback/multicast ranges).
///
/// # Inputs
/// * `ip` - The IP address to validate.
///
/// # Returns
/// * `bool` - `true` if the IP is a safe public address, otherwise `false`.
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

/// Determines if an IPv4 address falls within the CGNAT range (100.64.0.0/10).
///
/// # Inputs
/// * `v4` - The IPv4 address to check.
///
/// # Returns
/// * `bool` - `true` if within the CGNAT range, otherwise `false`.
fn is_v4_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// Checks if an IPv4 address is in a reserved/test network range (e.g. TEST-NET, 240.0.0.0/4).
///
/// # Inputs
/// * `v4` - The IPv4 address to check.
///
/// # Returns
/// * `bool` - `true` if in a reserved range, otherwise `false`.
fn is_v4_reserved(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    (o[0] == 192 && o[1] == 0   && o[2] == 2)   ||   // 192.0.2.0/24    TEST-NET-1
    (o[0] == 198 && o[1] == 51  && o[2] == 100)  ||  // 198.51.100.0/24 TEST-NET-2
    (o[0] == 203 && o[1] == 0   && o[2] == 113)  ||  // 203.0.113.0/24  TEST-NET-3
    o[0] >= 240 // 240.0.0.0/4     Reserved
}

/// Returns true if the IPv6 address is in a private/local range (ULA, link-local, or mapped IPv4 private).
///
/// # Inputs
/// * `v6` - The IPv6 address to check.
///
/// # Returns
/// * `bool` - `true` if in a private/local IPv6 range, otherwise `false`.
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
    /// Performs DNS resolution for a hostname while applying SSRF-safe checks and timeouts.
    ///
    /// # Inputs
    /// * `name` - The domain name to resolve.
    ///
    /// # Returns
    /// * `Resolving` - A pinned future resolving to an iterator of safe `SocketAddr`s, or a box error if resolution fails or returns only unsafe IPs.
    fn resolve(&self, name: Name) -> Resolving {
        let inner = self.inner.clone();
        let timeout = self.timeout;
        let host = name.as_str().to_owned();

        Box::pin(async move {
            // setting independent timeout on DNS resolution
            let lookup = tokio::time::timeout(timeout, inner.lookup_ip(&host))
                .await
                .map_err(|_| SanitizerError::Timeout(host.clone()))?
                .map_err(|e| SanitizerError::DnsLookup(host.clone(), e))?;

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
    /// Creates a new `SanitizerHttpClient` instance configured with safe DNS resolver, redirects policy, and timeout limits.
    ///
    /// # Inputs
    /// * `policy` - The security policy configuration.
    ///
    /// # Returns
    /// * `Result<Self>` - The configured sanitizer client, or an error if DNS resolver construction fails.
    pub fn new(
        policy: Arc<Policy>,
        channel: Sender<LoggerMessage>,
        url_map: Arc<Mutex<HashMap<Url, usize>>>,
    ) -> Result<Self, SanitizerError> {
        let resolver = TokioResolver::builder_tokio()
            .and_then(|x| x.build())
            .map_err(|e| SanitizerError::CreateHttpClient(Box::new(e)))?;

        let ssrf_safe_resolver = SsrfSafeDnsResolver {
            inner: Arc::new(resolver),
            // Reuse the connection timeout for DNS. This avoids an extra policy field
            timeout: policy.connections.connection_timeout,
        };

        let dangerous_domain_action = policy.connections.dangerous_domain;
        let client = Client::builder()
            // Set custom Ip resolver
            .dns_resolver(Arc::new(ssrf_safe_resolver))
            .connect_timeout(policy.connections.connection_timeout)
            .timeout(policy.connections.overall_timeout)
            .user_agent(&policy.connections.user_agent)
            // Disable redirects
            .redirect(redirect::Policy::custom(move |attempt| {
                let index = url_map.lock();
                let index = *index
                    .get(attempt.previous().first().unwrap_or(attempt.url()))
                    .unwrap();

                let logger = (index, &channel);

                let check = || -> Result<(), SanitizerError> {
                    if let Some(original) = check_domain(attempt.url()) {
                        policy
                            .urls
                            .idn
                            .handle(&logger, |_| {}, SanitizerError::Idn(original))?;
                    }

                    let max_redirects = policy.connections.max_redirects;
                    if attempt.previous().len() == max_redirects.value + 1 {
                        max_redirects.handle(
                            &logger,
                            SanitizerError::TooManyRedirects(max_redirects.value),
                        )?;
                    }

                    if let Some(host) = attempt.url().host().map(|x| x.to_owned())
                        && policy
                            .urls
                            .dangerous_domains
                            .iter()
                            .any(|x| host.matches(&x.0))
                    {
                        dangerous_domain_action
                            .handle(&logger, SanitizerError::DangerousDomain(host.to_owned()))?;
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
            .map_err(|e| SanitizerError::CreateHttpClient(Box::new(e)))?;

        Ok(Self { client })
    }

    /// Fetch raw bytes of a URL with security controls, enforcing max_bytes limit on the current request.
    ///
    /// # Inputs
    /// * `url` - The remote URL to fetch.
    /// * `_logger` - The logging interface (unused).
    /// * `_policy` - The security policy configuration (unused).
    /// * `remaining_bytes` - The max bytes remaining in the budget for this fetch.
    ///
    /// # Returns
    /// * `Result<FetchedContent>` - A `FetchedContent` struct containing the sniffed content-type and downloaded byte vector.
    pub async fn fetch_raw(
        &self,
        url: &Url,
        _logger: &Logger,
        _policy: &Policy,
        remaining_bytes: usize,
    ) -> Result<FetchedContent, SanitizerError> {
        if url.scheme() != "https" {
            return Err(SanitizerError::NonHttpsUrl);
        }

        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| SanitizerError::Request(url.clone(), e))?;

        if !response.status().is_success() {
            return Err(SanitizerError::ServerStatus(response.status()));
        }

        // Fast-fail for `Content-Length` header
        if let Some(length) = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|x| x.to_str().ok())
            .and_then(|x| x.parse::<usize>().ok())
            && length > remaining_bytes
        {
            return Err(SanitizerError::ContentTooLong(remaining_bytes));
        }

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let is_xml_html_svg = if let Some(ref ct) = content_type {
            let clean = crate::resources::mime::clean(ct);
            clean.contains("html") || clean.contains("xml") || clean.contains("svg")
        } else {
            false
        } || {
            let path = url.path().to_lowercase();
            path.ends_with(".html")
                || path.ends_with(".htm")
                || path.ends_with(".xml")
                || path.ends_with(".svg")
                || path.ends_with(".xhtml")
        };

        let mut stream = response.bytes_stream();
        let mut data = Vec::new();
        let mut length = 0;
        let mut entity_scanner = crate::resources::EntityScanner::new();

        while let Some(item) = stream.next().await {
            let chunk = item.map_err(SanitizerError::Streaming)?;
            length += chunk.len();
            if length > remaining_bytes {
                return Err(SanitizerError::ContentTooLong(remaining_bytes));
            }
            if is_xml_html_svg && entity_scanner.feed_chunk(&chunk) {
                return Err(SanitizerError::XmlEntityDeclaration);
            }
            data.extend_from_slice(&chunk);
        }

        Ok(FetchedContent {
            source: InputSource::Url(url.clone()),
            data,
            content_type,
        })
    }

    /// Fetch a single HTML URL, sanitize/rewrite it, and collect discovered subresources.
    ///
    /// # Inputs
    /// * `url` - The remote URL to fetch.
    /// * `logger` - The logging interface.
    /// * `output` - The file handle to stream the rewritten HTML bytes into.
    /// * `policy` - The security policy configuration.
    pub async fn fetch_and_sanitize_html(
        &self,
        url: &Url,
        logger: &Logger,
        output_path: &Path,
        policy: &Policy,
    ) -> Result<CrawlerState, SanitizerError> {
        if url.scheme() != "https" {
            return Err(SanitizerError::NonHttpsUrl);
        }

        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| SanitizerError::Request(url.clone(), e))?;

        if !response.status().is_success() {
            return Err(SanitizerError::ServerStatus(response.status()));
        }

        let max_bytes = policy.resources.max_bytes;

        // Fast-fail for `Content-Length` header
        if let Some(length) = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|x| x.to_str().ok())
            .and_then(|x| x.parse::<usize>().ok())
            && length > max_bytes.value
        {
            let _ = max_bytes.handle(logger, SanitizerError::ContentTooLong(max_bytes.value));
            return Err(SanitizerError::ContentTooLong(max_bytes.value));
        }

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        if let Some(content_type) = content_type
            && !content_type.contains("text/html")
        {
            return Err(SanitizerError::MimeMismatch(
                Some("text/html".to_owned()),
                Some(content_type),
            ));
        }

        let mut stream = response.bytes_stream();
        let mut total_bytes = 0;

        let mut crawler_state = CrawlerState {
            base: url.clone(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(
            logger,
            policy,
            &mut crawler_state,
            File::create(output_path)
                .map_err(|e| SanitizerError::CreateFile(output_path.to_owned(), e))?,
        );

        let mut entity_scanner = crate::resources::EntityScanner::new();
        while let Some(item) = stream.next().await {
            let chunk = item.map_err(SanitizerError::Streaming)?;

            total_bytes += chunk.len();
            if total_bytes > max_bytes.value {
                drop(rewriter);
                let _ = std::fs::remove_file(output_path);
                let _ = max_bytes.handle(logger, SanitizerError::ContentTooLong(max_bytes.value));
                return Err(SanitizerError::ContentTooLong(max_bytes.value));
            }

            if entity_scanner.feed_chunk(&chunk) {
                drop(rewriter);
                let _ = std::fs::remove_file(output_path);
                return Err(SanitizerError::XmlEntityDeclaration);
            }

            rewriter.write(&chunk)?;
        }

        rewriter.end()?;

        Ok(crawler_state)
    }
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

    #[tokio::test]
    async fn test_ssrf_safe_dns_resolver_local() {
        use std::str::FromStr;
        let inner = TokioResolver::builder_tokio().unwrap().build().unwrap();
        let resolver = SsrfSafeDnsResolver {
            inner: Arc::new(inner),
            timeout: Duration::from_secs(2),
        };

        let name = Name::from_str("localhost").unwrap();
        let res = resolver.resolve(name).await;
        if let Ok(addrs) = res {
            let list: Vec<std::net::SocketAddr> = addrs.collect();
            assert!(
                list.is_empty(),
                "localhost resolved to IPs but all should be filtered out: {:?}",
                list
            );
        }
    }
}
