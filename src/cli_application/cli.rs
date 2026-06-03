/*
The tool must accept one or more inputs
local HTML/asset files, a directory tree, or a list of URLs to fetch
*/

use crate::cli_application::http_client::SanitizerHttpClient;
use crate::sanitizer_engine::concurrency::ThreadPool;
use crate::sanitizer_engine::engine_structs::InputSource;
use crate::sanitizer_engine::errors::{DangerousDomain, IDN, ContentTooLong};
use crate::sanitizer_engine::html::create_rewriter;
use crate::sanitizer_engine::log::{LogLevel, Logger};
use crate::sanitizer_engine::policy::Policy;
use crate::sanitizer_engine::url::{RuleMatch, check_domain};
use crate::sanitizer_engine::resource_sanitizer::{
    validate_mime, sniff_mime, strip_jpeg_metadata, strip_png_metadata, sanitize_css, sanitize_javascript,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, Condvar};
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde_json;
use std::fs;
use std::io::{Read, BufReader};
use std::fs::File;

use std::path::PathBuf;
use url::Url;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Input files, directories or URLs
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<String>,

    /// Policy configuration file (JSON)
    #[arg(short, long)]
    pub policy: Option<PathBuf>,

    /// Output directory for sanitised content and reports
    #[arg(short, long, default_value = "output")]
    pub output_dir: PathBuf,

    /// Number of concurrent workers
    #[arg(short, long, default_value_t = 4)]
    pub workers: usize,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Helper to load the sanitization policy from a JSON file.
///
/// # Inputs
/// * `path` - Optional path reference to the JSON policy file.
///
/// # Returns
/// * `Result<Policy>` - The parsed `Policy` struct, or the default Policy if no path is given. Returns an error if reading or parsing fails.
fn load_policy(path: Option<&PathBuf>) -> Result<Policy> {
    let policy = match path {
        Some(path) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read policy file: {path:?}"))?;
            serde_json::from_str(&content).context("Failed to parse policy file")?
        }
        None => Policy::default(),
    };
    Ok(policy)
}

/// Helper to parse input patterns (URLs, directory paths, or files) into concrete InputSources.
///
/// # Inputs
/// * `inputs` - A vector of input strings.
///
/// # Returns
/// * `Result<Vec<InputSource>>` - A list of successfully parsed input sources (files and URLs).
fn parse_inputs(inputs: Vec<String>) -> Result<Vec<InputSource>> {
    let mut sources = Vec::new();
    for input in inputs {
        // Try to parse as URL first
        if let Ok(url) = Url::parse(&input)
            && (url.scheme() == "http" || url.scheme() == "https")
        {
            println!("Input '{}' recognized as URL", input);
            sources.push(InputSource::Url(url.clone()));
        } else {
            let path = PathBuf::from(&input);
            if path.is_dir() {
                println!("Input '{}' recognized as Directory", input);
                // Explore directory recursively
                for entry in WalkDir::new(&path) {
                    let entry = entry
                        .with_context(|| format!("Failed to read directory entry in {:?}", path))?;
                    if entry.file_type().is_file() {
                        sources.push(InputSource::File(entry.path().to_path_buf()));
                    }
                }
            } else if path.is_file() {
                println!("Input '{}' recognized as File", input);
                sources.push(InputSource::File(path));
            } else {
                println!(
                    "Warning: Input '{}' not found or not a supported URL scheme. Skipping.",
                    input
                );
            }
        }
    }
    Ok(sources)
}

/// Context tracking session progress, limits, and state for a single crawl/sanitization workflow.
pub struct CrawlSession {
    pub client: Arc<SanitizerHttpClient>,
    pub policy: Arc<Policy>,
    pub logger: Logger,
    pub rt_handle: tokio::runtime::Handle,
    pub output_dir: Arc<PathBuf>,
    pub visited: Mutex<HashSet<Url>>,
    pub total_requests: Mutex<usize>,
    pub total_bytes: Mutex<usize>,
    pub active_tasks: Mutex<usize>,
    pub active_cond: Condvar,
    pub pool: Arc<ThreadPool>,
}

impl CrawlSession {
    pub fn new(
        client: Arc<SanitizerHttpClient>,
        policy: Arc<Policy>,
        logger: Logger,
        rt_handle: tokio::runtime::Handle,
        output_dir: Arc<PathBuf>,
        pool: Arc<ThreadPool>,
    ) -> Self {
        Self {
            client,
            policy,
            logger,
            rt_handle,
            output_dir,
            visited: Mutex::new(HashSet::new()),
            total_requests: Mutex::new(0),
            total_bytes: Mutex::new(0),
            active_tasks: Mutex::new(0),
            active_cond: Condvar::new(),
            pool,
        }
    }

    /// Enqueues a task to the ThreadPool under the context of this CrawlSession, incrementing the active task counter.
    /// Decrements the counter and notifies the condvar once the job concludes.
    pub fn enqueue_task<F>(self: &Arc<Self>, f: F)
    where
        F: FnOnce(Arc<Self>) + Send + 'static,
    {
        {
            let mut count = self.active_tasks.lock().unwrap();
            *count += 1;
        }

        let session = Arc::clone(self);
        self.pool.push_job(move || {
            f(Arc::clone(&session));

            let mut count = session.active_tasks.lock().unwrap();
            *count -= 1;
            if *count == 0 {
                session.active_cond.notify_all();
            }
        });
    }

    /// Blocks the current thread until the active task count for this CrawlSession drops to 0.
    pub fn wait_until_done(&self) {
        let mut count = self.active_tasks.lock().unwrap();
        while *count > 0 {
            count = self.active_cond.wait(count).unwrap();
        }
    }
}

/// Worker task processing a local HTML file. Parses HTML, rewrites links, and enqueues referenced sub-resources.
fn process_file_task(
    session: Arc<CrawlSession>,
    path: PathBuf,
    index: usize,
) {
    let output_path = session.output_dir.join(format!("{index}.html"));
    let sub_resources = Arc::new(Mutex::new(Vec::new()));

    let file_result = || -> Result<()> {
        let input_file = File::open(&path)
            .with_context(|| format!("Failed to open local file {:?}", path))?;
        let mut reader = BufReader::new(input_file);
        let output_file = File::create(&output_path)
            .with_context(|| format!("Failed to create output file {:?}", output_path))?;
        
        let crawler_state = if session.policy.resources.fetch_sub_resources {
            let dummy_base = Arc::new(Mutex::new(Url::parse("https://localhost/").unwrap()));
            Some((dummy_base, Arc::clone(&sub_resources)))
        } else {
            None
        };

        let mut rewriter = create_rewriter(&session.logger, &session.policy, crawler_state, output_file);
        let mut buffer = [0; 8192];
        loop {
            let n = reader.read(&mut buffer)
                .with_context(|| format!("Failed to read chunk from file {:?}", path))?;
            if n == 0 {
                break;
            }
            rewriter.write(&buffer[..n])
                .map_err(|e| anyhow!("Rewriter write error: {:?}", e))?;
        }
        rewriter.end()
            .map_err(|e| anyhow!("Rewriter end error: {:?}", e))?;
        Ok(())
    }();

    if let Err(error) = file_result {
        session.logger.log(LogLevel::Error, error);
        return;
    }

    let discovered = {
        let guard = sub_resources.lock().unwrap();
        guard.clone()
    };

    for (sub_url, local_name) in discovered {
        enqueue_subresource_if_allowed(&session, sub_url, local_name, 1);
    }
}

/// Worker task fetching a remote HTML document, sanitizing it, and enqueuing referenced sub-resources.
fn process_url_task(
    session: Arc<CrawlSession>,
    url: Url,
    index: usize,
) {
    if let Some(original) = check_domain(&url)
        && let Err(e) = session.policy.urls.idn_action.handle_error(&session.logger, IDN(original))
    {
        session.logger.error(e);
        return;
    }

    if let Some(host) = url.host().map(|x| x.to_owned())
        && session.policy.urls.dangerous_domains.iter().any(|x| host.matches(&x.0))
        && let Err(e) = session.policy.connections.dangerous_domain_action.handle_error(&session.logger, DangerousDomain(host.to_owned()))
    {
        session.logger.error(e);
        return;
    }

    let output_path = session.output_dir.join(format!("{index}.html"));
    let fetch_result = session.rt_handle.block_on(async {
        session.client.fetch_and_sanitize_html(&url, &session.logger, &output_path, &session.policy).await
    });

    let (final_base, discovered) = match fetch_result {
        Ok(res) => res,
        Err(error) => {
            session.logger.error(anyhow!("Could not fetch url {}: {}", url, error));
            return;
        }
    };

    // Record the main HTML page request and visit
    {
        let mut visited = session.visited.lock().unwrap();
        visited.insert(url.clone());
        if url != final_base {
            visited.insert(final_base.clone());
        }
        let mut total_requests = session.total_requests.lock().unwrap();
        *total_requests += 1;
    }

    for (sub_url, local_name) in discovered {
        enqueue_subresource_if_allowed(&session, sub_url, local_name, 1);
    }
}

/// Worker task fetching and sanitizing a single sub-resource URL. Recursively enqueues nested resources (like inside CSS).
fn crawl_subresource_task(
    session: Arc<CrawlSession>,
    url: Url,
    local_name: String,
    depth: usize,
) {
    let max_depth = session.policy.resources.max_depth;
    if depth > max_depth {
        return;
    }

    let remaining_bytes = {
        let max_bytes = session.policy.resources.max_bytes;
        let total_bytes = session.total_bytes.lock().unwrap();
        max_bytes.saturating_sub(*total_bytes)
    };

    if remaining_bytes == 0 {
        let err = ContentTooLong(session.policy.resources.max_bytes);
        let _ = session.policy.resources.max_bytes_action.handle_error(&session.logger, err);
        return;
    }

    session.logger.info(anyhow!("Crawling sub-resource (depth {}): {}", depth, url));

    let fetch_res = session.rt_handle.block_on(async {
        session.client.fetch_raw(&url, &session.logger, &session.policy, remaining_bytes).await
    });

    let fetched = match fetch_res {
        Ok(f) => f,
        Err(e) => {
            session.logger.warn(anyhow!("Failed to fetch sub-resource {}: {}", url, e));
            let total_bytes_val = *session.total_bytes.lock().unwrap();
            if total_bytes_val + remaining_bytes >= session.policy.resources.max_bytes {
                let err = ContentTooLong(session.policy.resources.max_bytes);
                let _ = session.policy.resources.max_bytes_action.handle_error(&session.logger, err);
            }
            return;
        }
    };

    {
        let mut total_bytes = session.total_bytes.lock().unwrap();
        *total_bytes += fetched.data.len();
    }

    let decl_type = fetched.content_type.as_deref();
    if let Err(mime_err) = validate_mime(decl_type, &fetched.data) {
        session.logger.warn(anyhow!("MIME validation failed for {}: {}", url, mime_err));
        return;
    }

    let sniffed = sniff_mime(&fetched.data).unwrap_or(decl_type.unwrap_or(""));
    let is_jpeg = sniffed == "image/jpeg" || url.path().ends_with(".jpg") || url.path().ends_with(".jpeg");
    let is_png = sniffed == "image/png" || url.path().ends_with(".png");
    let is_css = sniffed == "text/css" || url.path().ends_with(".css");
    let is_js = sniffed == "text/javascript" || sniffed == "application/javascript" || url.path().ends_with(".js");

    let sanitized_data = if is_jpeg {
        strip_jpeg_metadata(&fetched.data)
    } else if is_png {
        strip_png_metadata(&fetched.data)
    } else if is_css {
        let css_str = String::from_utf8_lossy(&fetched.data);
        let (sanitized_css, nested_urls) = sanitize_css(&css_str, &url);
        if depth + 1 <= max_depth {
            for (n_url, n_local) in nested_urls {
                enqueue_subresource_if_allowed(&session, n_url, n_local, depth + 1);
            }
        }
        sanitized_css.into_bytes()
    } else if is_js {
        let js_str = String::from_utf8_lossy(&fetched.data);
        match sanitize_javascript(&js_str) {
            Ok(clean_js) => clean_js.into_bytes(),
            Err(js_err) => {
                session.logger.warn(anyhow!("JS validation failed for {}: {}", url, js_err));
                b"/* Blocked by Web Sanitizer: dangerous keywords found */".to_vec()
            }
        }
    } else {
        fetched.data.clone()
    };

    let sub_path = session.output_dir.join(&local_name);
    if let Err(e) = fs::write(&sub_path, &sanitized_data) {
        session.logger.error(anyhow!("Failed to write sub-resource to {:?}: {}", sub_path, e));
    }
}

/// Helper that checks limits and registers a sub-resource URL, then enqueues it if valid and not visited.
fn enqueue_subresource_if_allowed(
    session: &Arc<CrawlSession>,
    url: Url,
    local_name: String,
    depth: usize,
) {
    let max_requests = session.policy.resources.max_requests;

    let mut visited = session.visited.lock().unwrap();
    if visited.contains(&url) {
        return;
    }

    let mut total_requests = session.total_requests.lock().unwrap();
    if *total_requests >= max_requests {
        session.logger.warn(anyhow!("Sub-resource crawl limit reached: max_requests = {}", max_requests));
        return;
    }

    visited.insert(url.clone());
    *total_requests += 1;

    drop(total_requests);
    drop(visited);

    let url_clone = url.clone();
    let local_name_clone = local_name.clone();
    session.enqueue_task(move |s| {
        crawl_subresource_task(s, url_clone, local_name_clone, depth);
    });
}

/// Runs the main CLI application workflow: parses args, loads policy, submits jobs to the thread pool, and blocks until completion.
///
/// # Inputs
/// * None (inputs are gathered from command line arguments via `Args::parse()`).
///
/// # Returns
/// * `Result<()>` - `Ok(())` on successful completion, or an error if initialization fails.
pub async fn run() -> Result<()> {
    let args = Args::parse();
    println!("Successfully parsed args: {:?}", args);

    let policy = load_policy(args.policy.as_ref())?;
    let sources = parse_inputs(args.inputs)?;

    if sources.is_empty() {
        println!("No valid inputs provided.");
        return Ok(());
    }

    // Ensure output directory exists
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", args.output_dir))?;

    println!("Successfully created output directory: {:?}", args.output_dir);

    let client = Arc::new(SanitizerHttpClient::new(&policy).await?);
    let policy = Arc::new(policy);
    let max_size = (sources.len() as f64).log10().ceil() as usize;

    let pool = Arc::new(ThreadPool::new(args.workers)); 
    let rt_handle = tokio::runtime::Handle::current();
    let output_dir = Arc::new(args.output_dir);

    let mut sessions = Vec::new();

    for (i, source) in sources.into_iter().enumerate() {
        let logger = Logger {
            path: Arc::new(PathBuf::new()),
            index: i,
            max_size,
        };
        
        let session = Arc::new(CrawlSession::new(
            Arc::clone(&client),
            Arc::clone(&policy),
            logger,
            rt_handle.clone(),
            Arc::clone(&output_dir),
            Arc::clone(&pool),
        ));
        sessions.push(Arc::clone(&session));

        match source {
            InputSource::Url(url) => {
                session.enqueue_task(move |s| {
                    process_url_task(s, url, i);
                });
            }
            InputSource::File(path) => {
                session.enqueue_task(move |s| {
                    process_file_task(s, path, i);
                });
            }
        }
    }

    // Wait for all crawl sessions to finish processing their task queues
    for session in &sessions {
        session.wait_until_done();
    }

    drop(pool); // This joins the pool threads

    Ok(())
}










/// Helper to determine if a directory entry starts with a dot (hidden file/folder).
///
/// # Inputs
/// * `entry` - A reference to the walkdir entry.
///
/// # Returns
/// * `bool` - `true` if the entry name starts with a dot, otherwise `false`.
#[allow(dead_code)]
fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}






/*======================== TESTS ============================*/

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_default_args() {
        let args = Args::try_parse_from(["test", "input1.html"]).unwrap();
        assert_eq!(args.inputs, vec!["input1.html"]);
        assert_eq!(args.policy, None);
        assert_eq!(args.output_dir, PathBuf::from("output"));
        assert_eq!(args.workers, 4);
        assert!(!args.verbose);
    }

    #[test]
    fn test_multiple_inputs() {
        let args =
            Args::try_parse_from(["test", "input1.html", "input2.html", "http://example.com"])
                .unwrap();
        assert_eq!(
            args.inputs,
            vec!["input1.html", "input2.html", "http://example.com"]
        );
    }

    #[test]
    fn test_custom_flags() {
        let args = Args::try_parse_from([
            "test",
            "input.html",
            "--policy",
            "custom_policy.json",
            "--output-dir",
            "custom_output",
            "--workers",
            "8",
            "--verbose",
        ])
        .unwrap();
        assert_eq!(args.policy, Some(PathBuf::from("custom_policy.json")));
        assert_eq!(args.output_dir, PathBuf::from("custom_output"));
        assert_eq!(args.workers, 8);
        assert!(args.verbose);
    }

    #[test]
    fn test_missing_input_fails() {
        let result = Args::try_parse_from(["test"]);
        assert!(result.is_err());
    }
}
