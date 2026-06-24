use crate::cli_application::http_client::SanitizerHttpClient;
use crate::sanitizer_engine::errors::ContentTooLong;
use crate::sanitizer_engine::errors::DangerousDomain;
use crate::sanitizer_engine::errors::IDN;
use crate::sanitizer_engine::html::CrawlerState;
use crate::sanitizer_engine::html::create_rewriter;
use crate::sanitizer_engine::log::LogLevel;
use crate::sanitizer_engine::log::Logger;
use crate::sanitizer_engine::log::LoggerTrait;
use crate::sanitizer_engine::policy::Policy;
use crate::sanitizer_engine::resource_sanitizer::clean_mime;
use crate::sanitizer_engine::resource_sanitizer::sanitize_css;
use crate::sanitizer_engine::resource_sanitizer::sanitize_javascript;
use crate::sanitizer_engine::resource_sanitizer::sniff_mime;
use crate::sanitizer_engine::resource_sanitizer::strip_jpeg_metadata;
use crate::sanitizer_engine::resource_sanitizer::strip_png_metadata;
use crate::sanitizer_engine::resource_sanitizer::validate_mime;
use crate::sanitizer_engine::url::RuleMatch;
use crate::sanitizer_engine::url::check_domain;
use anyhow::{Context, Result, anyhow};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use url::Url;

/// Context tracking session progress, limits, and state for a single crawl/sanitization workflow.
pub struct CrawlSession {
    pub client: Arc<SanitizerHttpClient>,
    pub policy: Arc<Policy>,
    pub logger: Logger,
    pub rt_handle: tokio::runtime::Handle,
    pub output_dir: Arc<PathBuf>,
    pub url_map: Arc<Mutex<HashMap<Url, usize>>>,
    pub total_requests: Mutex<usize>,
    pub total_bytes: Mutex<usize>,
}

impl CrawlSession {
    pub fn new(
        client: Arc<SanitizerHttpClient>,
        policy: Arc<Policy>,
        logger: Logger,
        rt_handle: tokio::runtime::Handle,
        output_dir: Arc<PathBuf>,
        url_map: Arc<Mutex<HashMap<Url, usize>>>,
    ) -> Self {
        Self {
            client,
            policy,
            logger,
            rt_handle,
            output_dir,
            url_map,
            total_requests: Mutex::new(0),
            total_bytes: Mutex::new(0),
        }
    }

    fn index(&self) -> usize {
        self.logger.index
    }

    /// Worker task fetching and sanitizing a single sub-resource URL. Recursively enqueues nested resources (like inside CSS).
    async fn crawl_subresource(self: Arc<Self>, url: Url, local_name: String, depth: usize) {
        let max_depth = self.policy.resources.max_depth;
        if depth > max_depth {
            return;
        }

        let remaining_bytes = {
            let max_bytes = self.policy.resources.max_bytes;
            max_bytes.value.saturating_sub(*self.total_bytes.lock())
        };

        if remaining_bytes == 0 {
            let err = ContentTooLong(self.policy.resources.max_bytes.value);
            let _ = self.policy.resources.max_bytes.handle(&self.logger, err);
            return;
        }

        self.logger
            .info(anyhow!("Crawling sub-resource (depth {}): {}", depth, url));

        let fetch_res = self
            .client
            .fetch_raw(&url, &self.logger, &self.policy, remaining_bytes)
            .await;

        let fetched = match fetch_res {
            Ok(f) => f,
            Err(e) => {
                self.logger
                    .warn(anyhow!("Failed to fetch sub-resource {}: {}", url, e));
                let total_bytes_val = *self.total_bytes.lock();
                if total_bytes_val + remaining_bytes >= self.policy.resources.max_bytes.value {
                    let err = ContentTooLong(self.policy.resources.max_bytes.value);
                    let _ = self.policy.resources.max_bytes.handle(&self.logger, err);
                }
                return;
            }
        };

        {
            let mut total_bytes = self.total_bytes.lock();
            *total_bytes += fetched.data.len();
        }

        let decl_type = fetched.content_type.as_deref();
        let declared = decl_type.map(clean_mime);
        let sniffed = sniff_mime(&fetched.data);
        if let Err(mime_err) = validate_mime(decl_type, sniffed) {
            self.logger
                .warn(anyhow!("MIME validation failed for {}: {}", url, mime_err));
            return;
        }

        let sniffed = sniffed.or(declared.as_deref()).unwrap_or_default();
        let is_jpeg = sniffed == "image/jpeg"
            || url.path().ends_with(".jpg")
            || url.path().ends_with(".jpeg");
        let is_png = sniffed == "image/png" || url.path().ends_with(".png");
        let is_css = sniffed == "text/css" || url.path().ends_with(".css");
        let is_js = sniffed == "text/javascript"
            || sniffed == "application/javascript"
            || url.path().ends_with(".js");

        let sanitized_data = if is_jpeg {
            strip_jpeg_metadata(&fetched.data)
        } else if is_png {
            strip_png_metadata(&fetched.data)
        } else if is_css {
            let css_str = String::from_utf8_lossy(&fetched.data);
            let (sanitized_css, nested_urls) = sanitize_css(&css_str, &url);
            if depth < max_depth {
                for (n_url, n_local) in nested_urls {
                    self.try_enqueue_subresource(n_url, n_local, depth + 1);
                }
            }
            sanitized_css.into_bytes()
        } else if is_js {
            let js_str = String::from_utf8_lossy(&fetched.data);
            match sanitize_javascript(&js_str) {
                Ok(clean_js) => clean_js.into_bytes(),
                Err(js_err) => {
                    self.logger
                        .warn(anyhow!("JS validation failed for {}: {}", url, js_err));
                    b"/* Blocked by Web Sanitizer: dangerous keywords found */".to_vec()
                }
            }
        } else {
            fetched.data.clone()
        };

        let sub_path = self.output_dir.join(&local_name);
        if let Err(e) = fs::write(&sub_path, &sanitized_data) {
            self.logger.error(anyhow!(
                "Failed to write sub-resource to {:?}: {}",
                sub_path,
                e
            ));
        }
    }

    /// Checks limits and registers a sub-resource URL, then enqueues it if valid and not visited.
    fn try_enqueue_subresource(self: &Arc<Self>, url: Url, local_name: String, depth: usize) {
        let max_requests = self.policy.resources.max_requests;

        {
            let mut visited = self.url_map.lock();
            if visited.contains_key(&url) {
                return;
            }

            let mut total_requests = self.total_requests.lock();
            *total_requests += 1;
            if *total_requests > max_requests.value {
                // Log only the first time we hit the limit
                if *total_requests == max_requests.value + 1 {
                    self.logger.log(
                        max_requests.level,
                        anyhow!(
                            "Sub-resource crawl limit reached: max_requests = {}",
                            max_requests.value
                        ),
                    );
                }

                return;
            }

            visited.insert(url.clone(), self.index());
        }

        let clone = Arc::clone(self);
        self.rt_handle
            .spawn(async move { clone.crawl_subresource(url, local_name, depth).await });
    }

    /// Worker task processing a local HTML file. Parses HTML, rewrites links, and enqueues referenced sub-resources.
    pub fn process_file(self: Arc<Self>, path: PathBuf) {
        let output_path = self.output_dir.join(format!("{}.html", self.index()));

        let file_result = || -> Result<_> {
            let input_file = File::open(&path)
                .with_context(|| format!("Failed to open local file {:?}", path))?;
            let mut reader = BufReader::new(input_file);
            let output_file = File::create(&output_path)
                .with_context(|| format!("Failed to create output file {:?}", output_path))?;

            let mut crawler_state = {
                CrawlerState {
                    base: Url::parse("https://localhost").unwrap(),
                    subresources: Vec::new(),
                }
            };

            let mut rewriter =
                create_rewriter(&self.logger, &self.policy, &mut crawler_state, output_file);
            let mut buffer = [0; 8192];
            loop {
                let n = reader
                    .read(&mut buffer)
                    .with_context(|| format!("Failed to read chunk from file {:?}", path))?;
                if n == 0 {
                    break;
                }
                rewriter
                    .write(&buffer[..n])
                    .map_err(|e| anyhow!("Rewriter write error: {:?}", e))?;
            }
            rewriter
                .end()
                .map_err(|e| anyhow!("Rewriter end error: {:?}", e))?;

            Ok(crawler_state.subresources)
        }();

        match file_result {
            Err(error) => self.logger.log(LogLevel::Error, error),
            Ok(sub_resources) => {
                for (sub_url, local_name) in sub_resources {
                    self.try_enqueue_subresource(sub_url, local_name, 1);
                }
            }
        }
    }

    /// Worker task fetching a remote HTML document, sanitizing it, and enqueuing referenced sub-resources.
    pub async fn process_url(self: Arc<Self>, url: Url) {
        if let Some(original) = check_domain(&url)
            && let Err(e) = self.policy.urls.idn.handle(&self.logger, IDN(original))
        {
            self.logger.error(e);
            return;
        }

        if let Some(host) = url.host().map(|x| x.to_owned())
            && self
                .policy
                .urls
                .dangerous_domains
                .iter()
                .any(|x| host.matches(&x.0))
            && let Err(e) = self
                .policy
                .connections
                .dangerous_domain
                .handle(&self.logger, DangerousDomain(host.to_owned()))
        {
            self.logger.error(e);
            return;
        }

        let index = self.index();
        let output_path = self.output_dir.join(format!("{index}.html"));
        let fetch_result = self
            .client
            .fetch_and_sanitize_html(&url, &self.logger, &output_path, &self.policy)
            .await;

        let CrawlerState {
            base: final_base,
            subresources: discovered,
        } = match fetch_result {
            Ok(res) => res,
            Err(error) => {
                self.logger
                    .error(anyhow!("Could not fetch url {}: {}", url, error));
                return;
            }
        };

        // Record the main HTML page request and visit
        {
            let mut visited = self.url_map.lock();
            visited.insert(url.clone(), index);
            visited.insert(final_base.clone(), index);

            let mut total_requests = self.total_requests.lock();
            *total_requests += 1;
        }

        for (sub_url, local_name) in discovered {
            self.try_enqueue_subresource(sub_url, local_name, 1);
        }
    }
}
