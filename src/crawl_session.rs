use crate::errors::SanitizerError;
use crate::errors::SanitizerMessage;
use crate::html::CrawlerState;
use crate::html::create_rewriter;
use crate::http_client::SanitizerHttpClient;
use crate::log::ChannelLogger;
use crate::log::Log;
use crate::policy::Policy;
use crate::resources::mime;
use crate::resources::strip_jpeg_metadata;
use crate::resources::strip_png_metadata;
use crate::url::RuleMatch;
use crate::url::check_domain;
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
    pub logger: ChannelLogger,
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
        logger: ChannelLogger,
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
    async fn crawl_subresource(
        self: &Arc<Self>,
        url: Url,
        local_name: String,
        depth: usize,
    ) -> Result<(), SanitizerError> {
        let max_depth = self.policy.resources.max_depth;
        let max_bytes = self.policy.resources.max_bytes;

        let remaining_bytes = max_bytes.value.saturating_sub(*self.total_bytes.lock());
        if remaining_bytes == 0 {
            max_bytes.handle(
                &self.logger,
                SanitizerError::ContentTooLong(max_bytes.value),
            )?;
        }

        self.logger.info(SanitizerMessage::CrawlingSubresource {
            depth,
            url: url.clone(),
        });

        let fetched = self
            .client
            .fetch_raw(&url, &self.logger, &self.policy, remaining_bytes)
            .await
            .map_err(|e| SanitizerError::UrlFetch(url.clone(), Box::new(e), false))?;

        {
            let mut total_bytes = self.total_bytes.lock();
            *total_bytes += fetched.data.len();
        }

        let declared = fetched.content_type.as_deref().map(mime::clean);
        let sniffed = mime::sniff(&fetched.data);
        if !mime::validate(declared.as_deref(), sniffed) {
            let err =
                SanitizerError::MimeMismatch(declared.clone(), sniffed.map(|x| x.to_string()));
            self.policy
                .resources
                .mismatched_mime
                .handle(&self.logger, err)?;
        }

        let sniffed = sniffed
            .map(|x| x.to_string())
            .or(declared)
            .unwrap_or_default();
        let is_jpeg = sniffed == "image/jpeg"
            || url.path().ends_with(".jpg")
            || url.path().ends_with(".jpeg");
        let is_png = sniffed == "image/png" || url.path().ends_with(".png");
        let is_css = sniffed == "text/css" || url.path().ends_with(".css");
        let is_pdf = sniffed == "application/pdf" || url.path().ends_with(".pdf");
        let is_js = sniffed == "text/javascript"
            || sniffed == "application/javascript"
            || url.path().ends_with(".js");

        let sanitized_data = if is_jpeg {
            strip_jpeg_metadata(&fetched.data)
        } else if is_png {
            strip_png_metadata(&fetched.data)
        } else if is_css {
            let css_str = String::from_utf8_lossy(&fetched.data);
            let (sanitized_css, nested_urls) = crate::resources::css::sanitize(
                &css_str,
                &url,
                &self.logger,
                &self.policy.resources.dangerous_css,
            )?;
            if depth < max_depth.value {
                for (n_url, n_local) in nested_urls {
                    self.try_enqueue_subresource(n_url, n_local, depth + 1);
                }
            }
            sanitized_css.into_bytes()
        } else if is_js {
            let js_str = String::from_utf8_lossy(&fetched.data);
            crate::resources::javascript::sanitize(&js_str)
                .map(|_| None)
                .or_else(|e| {
                    self.policy.resources.dangerous_js.handle_with(
                        &self.logger,
                        |x| x.as_bytes().to_vec(),
                        e,
                    )
                })?
                .unwrap_or(fetched.data)
        } else if is_pdf {
            if let Err(e) = crate::resources::scan_pdf_for_active_content(&fetched.data) {
                self.policy
                    .resources
                    .pdf_active_content
                    .handle(&self.logger, e)?;
            }

            fetched.data
        } else {
            self.policy
                .resources
                .unknown_resource
                .handle(&self.logger, SanitizerError::UnknownResourceType)?;

            fetched.data
        };

        let sub_path = self.output_dir.join(&local_name);
        fs::write(&sub_path, &sanitized_data).map_err(|e| SanitizerError::WriteFile(sub_path, e))
    }

    /// Checks limits and registers a sub-resource URL, then enqueues it if valid and not visited.
    fn try_enqueue_subresource(self: &Arc<Self>, url: Url, local_name: String, depth: usize) {
        let max_requests = self.policy.resources.max_requests;
        let max_depth = self.policy.resources.max_depth;

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
                        SanitizerError::MaxSubresources(max_requests.value),
                    );
                }

                return;
            }

            visited.insert(url.clone(), self.index());
        }

        if depth > max_depth.value {
            if let Err(e) = max_depth.handle(
                &self.logger,
                SanitizerError::MaxSubresourceDepth(max_depth.value),
            ) {
                self.logger.error(e);
                return;
            }
        }

        let clone = Arc::clone(self);
        self.rt_handle.spawn(async move {
            if let Err(e) = clone.crawl_subresource(url, local_name, depth).await {
                clone.logger.error(e);
            }
        });
    }

    /// Worker task processing a local file (HTML, PDF, etc.). Parses HTML, rewrites links, scans PDFs, and enqueues referenced sub-resources.
    pub fn process_file(self: Arc<Self>, path: PathBuf) {
        let extension = path
            .extension()
            .map(|ext| ext.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let result = match extension.as_str() {
            "pdf" => self.process_pdf_file(path),
            "css" => self.process_css_file(path),
            "js" => self.process_js_file(path),
            _ => self.process_html_file(path),
        };

        if let Err(e) = result {
            self.logger.error(e);
        }
    }

    fn process_pdf_file(&self, path: PathBuf) -> Result<(), SanitizerError> {
        let output_path = self.output_dir.join(format!("{}.pdf", self.index()));
        let data = fs::read(&path).map_err(|e| SanitizerError::ReadFile(path, e))?;

        if let Err(e) = crate::resources::scan_pdf_for_active_content(&data) {
            self.policy
                .resources
                .pdf_active_content
                .handle(&self.logger, e)?;
        }

        fs::write(&output_path, &data).map_err(|e| SanitizerError::WriteFile(output_path, e))?;

        Ok(())
    }

    fn process_css_file(&self, path: PathBuf) -> Result<(), SanitizerError> {
        let output_path = self.output_dir.join(format!("{}.css", self.index()));
        let data = fs::read(&path).map_err(|e| SanitizerError::ReadFile(path, e))?;
        let css_str = String::from_utf8_lossy(&data);
        let dummy_url = Url::parse("https://localhost").unwrap();
        let (sanitized_css, _) = crate::resources::css::sanitize(
            &css_str,
            &dummy_url,
            &self.logger,
            &self.policy.resources.dangerous_css,
        )?;
        fs::write(&output_path, sanitized_css.as_bytes())
            .map_err(|e| SanitizerError::WriteFile(output_path, e))?;
        Ok(())
    }

    fn process_js_file(&self, path: PathBuf) -> Result<(), SanitizerError> {
        let output_path = self.output_dir.join(format!("{}.js", self.index()));
        let data = fs::read(&path).map_err(|e| SanitizerError::ReadFile(path, e))?;
        let js_str = String::from_utf8_lossy(&data);

        let to_write = crate::resources::javascript::sanitize(&js_str)
            .map(|_| None)
            .or_else(|e| {
                self.policy.resources.dangerous_js.handle_with(
                    &self.logger,
                    |x| x.as_bytes().to_vec(),
                    e,
                )
            })?
            .unwrap_or(data);

        fs::write(&output_path, to_write).map_err(|e| SanitizerError::WriteFile(output_path, e))?;

        Ok(())
    }

    fn process_html_file(self: &Arc<Self>, path: PathBuf) -> Result<(), SanitizerError> {
        let output_path = self.output_dir.join(format!("{}.html", self.index()));

        let input_file =
            File::open(&path).map_err(|e| SanitizerError::OpenFile(path.clone(), e))?;
        let mut reader = BufReader::new(input_file);
        let output_file = File::create(&output_path)
            .map_err(|e| SanitizerError::CreateFile(output_path.clone(), e))?;

        let mut crawler_state = {
            CrawlerState {
                base: Url::parse("https://localhost").unwrap(),
                subresources: Vec::new(),
            }
        };

        let mut rewriter =
            create_rewriter(&self.logger, &self.policy, &mut crawler_state, output_file);
        let mut buffer = [0; 8192];
        let mut entity_scanner = crate::resources::EntityScanner::new();
        loop {
            let n = reader
                .read(&mut buffer)
                .map_err(|e| SanitizerError::ReadFile(path.clone(), e))?;
            if n == 0 {
                break;
            }
            if entity_scanner.feed_chunk(&buffer[..n]) {
                drop(rewriter);
                let _ = std::fs::remove_file(&output_path);
                return Err(SanitizerError::XmlEntityDeclaration);
            }
            rewriter.write(&buffer[..n])?;
        }
        rewriter.end()?;

        for (sub_url, local_name) in crawler_state.subresources {
            self.try_enqueue_subresource(sub_url, local_name, 1);
        }

        Ok(())
    }

    /// Worker task fetching a remote HTML document, sanitizing it, and enqueuing referenced sub-resources.
    pub async fn process_url(self: Arc<Self>, url: Url) {
        if let Some(original) = check_domain(&url)
            && let Err(e) = self
                .policy
                .urls
                .idn
                .handle(&self.logger, SanitizerError::Idn(original))
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
            && let Err(e) = self.policy.connections.dangerous_domain.handle(
                &self.logger,
                SanitizerError::DangerousDomain(host.to_owned()),
            )
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
                    .error(SanitizerError::UrlFetch(url, Box::new(error), false));
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
