use lol_html::{
    element,
    send::{HtmlRewriter, Settings},
    text,
};
use std::io::Write;
use url::Url;

use crate::{
    errors::SanitizerError,
    log::{Logger, LoggerTrait},
    policy::{AttributeUrl, Policy},
    url::RuleMatch,
};

/// Helper function to inspect an element's URL attribute for dangerous domains and rewrite it if necessary.
///
/// # Inputs
/// * `el` - A mutable reference to the HTML element.
/// * `attr_name` - The name of the attribute containing the URL (e.g. `"href"`, `"src"`).
/// * `base_url` - The shared thread-safe base URL of the document.
/// * `policy` - The security policy configuration.
/// * `logger` - The logging interface.
///
/// # Returns
/// * `Result<(), LoggerError>` - `Ok(())` if processing succeeded (or was handled by policies), otherwise an error.
fn handle_dangerous_link(
    el: &mut lol_html::html_content::Element<'_, '_, lol_html::send::SendHandlerTypes>,
    attr_name: &str,
    base_url: &Url,
    policy: &Policy,
    logger: &Logger,
) -> Result<Option<Url>, SanitizerError> {
    if let Some(val) = el.get_attribute(attr_name) {
        use unicode_normalization::UnicodeNormalization;
        let val_normalized = val.nfc().collect::<String>();

        let resolved = base_url.join(&val_normalized);
        if let Ok(mut resolved) = resolved
        // && resolved.scheme() == "https"
        {
            if let Some(host) = resolved.host() {
                // Check IDN
                if let Some(original) = crate::url::check_domain(&resolved) {
                    policy.urls.idn.handle(
                        logger,
                        |x| x.replace_attribute(attr_name, el),
                        SanitizerError::Idn(original),
                    )?;
                }

                let host = host.to_owned();

                let is_dangerous = policy
                    .urls
                    .dangerous_domains
                    .iter()
                    .any(|x| x.0.matches(&host));

                if is_dangerous {
                    let location = el.source_location();

                    policy.html.dangerous_domain.handle(
                        logger,
                        |x| {
                            let new = match resolved.set_host(Some(x.as_ref())) {
                                // If policy value is a valid host, replace the host of the old url
                                Ok(_) => &AttributeUrl::new(resolved.as_ref()),
                                // Otherwise replace the whole url with the policy value
                                Err(_) => x,
                            };

                            new.replace_attribute(attr_name, el);
                        },
                        SanitizerError::DangerousDomainInHtml(host, location.bytes().start),
                    )?;
                }
            }

            return Ok(Some(resolved));
        }
    }

    Ok(None)
}

pub struct CrawlerState {
    /// The base URL of the document
    pub base: Url,
    /// The resources discovered in the document
    pub subresources: Vec<(Url, String)>,
}

/// Creates an `HtmlRewriter` to inspect and rewrite HTML contents.
///
/// If `policy.resources.fetch_sub_resources` is `true` and a `crawler_state` is provided,
/// the rewriter will rewrite relative paths for scripts, styles, and other resources to local paths,
/// and enqueue them to be crawled. Otherwise, it will only inspect and clean standard anchors and links.
///
/// # Inputs
/// * `logger` - The logging interface.
/// * `policy` - The security policy configuration.
/// * `state` - Optional tuple containing the document's thread-safe base URL and discovered resources accumulator.
/// * `output` - The output stream writer to write the rewritten HTML bytes to.
///
/// # Returns
/// * `HtmlRewriter<'a, impl FnMut(&[u8])>` - The configured rewriter instance.
pub fn create_rewriter<'a, W: Write>(
    logger: &'a Logger,
    policy: &'a Policy,
    state: &'a mut CrawlerState,
    mut output: W,
) -> HtmlRewriter<'a, impl FnMut(&[u8])> {
    let mut handlers = Vec::new();

    handlers.push(element!("*", move |el| {
        let event_attrs: Vec<_> = el
            .attributes()
            .iter()
            .map(|attr| attr.name())
            .filter(|name| name.to_lowercase().starts_with("on"))
            .collect();

        for attr_name in event_attrs {
            let location = el.source_location();
            policy.html.event_handlers.handle(
                logger,
                |x| x.replace_attribute(&attr_name, el),
                SanitizerError::EventHandler(attr_name.clone(), Some(location.bytes().start)),
            )?;
        }

        let dangerous_uri_attrs: Vec<_> = el
            .attributes()
            .iter()
            .map(|attr| (attr.name(), attr.value().trim().to_lowercase()))
            .filter(|(_, x)| x.starts_with("javascript:") || x.starts_with("data:"))
            .collect();

        for (attr_name, val) in dangerous_uri_attrs {
            let location = el.source_location();
            policy.html.dangerous_uris.handle(
                logger,
                |x| x.replace_attribute(&attr_name, el),
                SanitizerError::DangerousUri(val, Some(location.bytes().start)),
            )?;
        }

        Ok(())
    }));

    handlers.push(element!(
        "base[href], a[href], link[href], img[src], image[href], source[src], script",
        move |el| {
            match el.tag_name().as_str() {
                "base" => {
                    if let Some(href) = el.get_attribute("href")
                        && let Ok(new_base) = state.base.join(&href)
                    {
                        state.base = new_base;
                    }
                }
                "a" => {
                    handle_dangerous_link(el, "href", &state.base, policy, logger)?;
                }
                "link" => {
                    let rel = el.get_attribute("rel").unwrap_or_default().to_lowercase();
                    if !rel.contains("stylesheet") {
                        handle_dangerous_link(el, "href", &state.base, policy, logger)?;
                        return Ok(());
                    }

                    if let Some(resolved) =
                        handle_dangerous_link(el, "href", &state.base, policy, logger)?
                        && policy.resources.fetch_sub_resources
                    {
                        let local_name =
                            crate::resources::generate_local_filename(&resolved, "css");

                        el.set_attribute("href", &local_name)?;
                        state.subresources.push((resolved, local_name));
                    }
                }
                "img" => {
                    if let Some(resolved) =
                        handle_dangerous_link(el, "src", &state.base, policy, logger)?
                        && policy.resources.fetch_sub_resources
                    {
                        let local_name =
                            crate::resources::generate_local_filename(&resolved, "png");

                        el.set_attribute("src", &local_name)?;
                        state.subresources.push((resolved, local_name));
                    }
                }
                "image" => {
                    if let Some(resolved) =
                        handle_dangerous_link(el, "href", &state.base, policy, logger)?
                        && policy.resources.fetch_sub_resources
                    {
                        let local_name =
                            crate::resources::generate_local_filename(&resolved, "png");

                        el.set_attribute("href", &local_name)?;
                        state.subresources.push((resolved, local_name));
                    }
                }
                "source" => {
                    if let Some(resolved) =
                        handle_dangerous_link(el, "src", &state.base, policy, logger)?
                        && policy.resources.fetch_sub_resources
                    {
                        let local_name = crate::resources::generate_local_filename(&resolved, "js");

                        el.set_attribute("src", &local_name)?;
                        state.subresources.push((resolved, local_name));
                    }
                }
                "script" => {
                    let location = el.source_location();

                    if let Some(resolved) =
                        handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    {
                        let host_matched = if let Some(host) = resolved.host() {
                            let host = host.to_string();
                            policy.html.allow_scripts.iter().any(|allowed| {
                                allowed == &host || resolved.as_str().starts_with(allowed)
                            })
                        } else {
                            false
                        };

                        if !host_matched {
                            logger.error(SanitizerError::BlockedScript(
                                resolved.to_string(),
                                location.bytes(),
                            ));
                            el.remove();
                            return Ok(());
                        }

                        if policy.resources.fetch_sub_resources {
                            let local_name =
                                crate::resources::generate_local_filename(&resolved, "js");

                            el.set_attribute("src", &local_name)?;
                            state.subresources.push((resolved, local_name));
                        }
                    } else {
                        if let Some(src) = el.get_attribute("src") {
                            logger.error(SanitizerError::BlockedScript(
                                src.clone(),
                                location.bytes(),
                            ));
                            el.remove();
                        }
                    }
                }
                _ => {}
            }

            Ok(())
        }
    ));

    let mut inline_script = String::new();
    let mut inline_script_location = None;

    handlers.push(text!("script", move |t| {
        use base64::{Engine, prelude::BASE64_STANDARD};
        use sha2::{Digest, Sha256};

        inline_script.push_str(t.as_str());
        t.remove();

        if inline_script_location.is_none() {
            inline_script_location = Some(t.source_location().bytes().start);
        }

        if t.last_in_text_node() {
            let mut hasher = Sha256::new();
            hasher.update(inline_script.as_bytes());
            let hash_result = hasher.finalize();
            let b64_hash = BASE64_STANDARD.encode(hash_result);
            let csp_hash = format!("sha256-{}", b64_hash);

            let is_allowed = policy
                .html
                .allow_scripts
                .iter()
                .any(|allowed| allowed == &csp_hash);
            if is_allowed {
                t.replace(&inline_script, lol_html::html_content::ContentType::Text);
            } else {
                let start = inline_script_location.unwrap_or(0);
                let end = t.source_location().bytes().end;

                logger.error(SanitizerError::BlockedScript(
                    "<inline>".to_owned(),
                    start..end,
                ));
            }
            inline_script.clear();
            inline_script_location = None;
        }
        Ok(())
    }));

    HtmlRewriter::new(
        Settings {
            element_content_handlers: handlers,
            ..Settings::new_send()
        },
        move |c: &[u8]| {
            output.write_all(c).unwrap();
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        log::{LogLevel, Logger},
        policy::AttributeString,
        rules::RuleWithReplace,
    };
    use std::sync::mpsc::{self, channel};

    #[test]
    fn test_event_handler_stripping() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let policy = Policy::default();

        let input_html = b"<button onclick=\"alert(1)\" class=\"btn\" ONLOAD=\"doSomething()\">Click me</button>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("onclick"));
        assert!(!result.contains("ONLOAD"));
        assert!(result.contains("class=\"btn\""));
        assert!(result.contains("Click me"));
    }

    #[test]
    fn test_event_handler_replacement() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.event_handlers =
            RuleWithReplace::new(AttributeString::new("alert('blocked')"), LogLevel::Info);

        let input_html = b"<button onclick=\"alert(1)\"></button>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("onclick=\"alert('blocked')\""));
    }

    #[test]
    fn test_event_handler_ignore() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.event_handlers = RuleWithReplace::keep(LogLevel::Trace);

        let input_html = b"<button onclick=\"alert(1)\"></button>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("onclick=\"alert(1)\""));
    }

    #[test]
    fn test_script_src_allowed() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.allow_scripts = vec!["trusted.com".to_owned()];

        let input_html = b"<script src=\"https://trusted.com/lib.js\"></script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("<script src=\"sub_"));
    }

    #[test]
    fn test_script_src_blocked() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.allow_scripts = vec!["trusted.com".to_owned()];

        let input_html = b"<script src=\"https://untrusted.com/lib.js\"></script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("untrusted.com"));
        assert!(!result.contains("<script"));
    }

    #[test]
    fn test_script_inline_allowed() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.allow_scripts =
            vec!["sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=".to_owned()];

        let input_html = b"<script>alert(1)</script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("alert(1)"));
    }

    #[test]
    fn test_script_inline_blocked() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let policy = Policy::default();

        let input_html = b"<script>alert(1)</script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("alert(1)"));
    }

    #[test]
    fn test_dangerous_uris_sanitization() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.dangerous_uris = RuleWithReplace::with_default(LogLevel::Info);

        let input_html = b"<a href=\"javascript:alert(1)\" src=\"  data:text/html,malicious  \" data-url=\"other\">link</a>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("href=\"#\""));
        assert!(result.contains("src=\"#\""));
        assert!(result.contains("data-url=\"other\""));
    }

    #[test]
    fn test_dangerous_uris_bypass_whitespace() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.dangerous_uris = RuleWithReplace::new(AttributeUrl::new(""), LogLevel::Info);

        let input_html = b"<a href=\"\n\t javascript:alert(1)\">link</a>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("javascript"));
        assert!(!result.contains("href="));
    }

    #[test]
    fn test_dangerous_uris_ignore() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };
        let mut policy = Policy::default();
        policy.html.dangerous_uris = RuleWithReplace::keep(LogLevel::Trace);

        let input_html = b"<a href=\"javascript:alert(1)\">link</a>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&logger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("href=\"javascript:alert(1)\""));
    }

    #[test]
    fn test_idn_rewriting() {
        let (tx, _rx) = channel();
        let logger = Logger {
            index: 0,
            channel: tx,
        };

        // Case 1: IDN is Warn. It should preserve the link.
        let mut policy = Policy::default();
        policy.urls.idn = RuleWithReplace::keep(LogLevel::Warn);
        policy.resources.fetch_sub_resources = false;

        let mut crawler_state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: vec![],
        };

        let mut output = Vec::new();
        {
            let mut rewriter = create_rewriter(&logger, &policy, &mut crawler_state, &mut output);
            rewriter
                .write(b"<a href=\"http://googl\xC3\xA9.com\">Link</a>")
                .unwrap();
            rewriter.end().unwrap();
        }
        let out_str = String::from_utf8(output).unwrap();
        assert!(
            out_str.contains("http://googl\u{00E9}.com")
                || out_str.contains("http://xn--googl-fsa.com")
        );

        // Case 2: IDN is Warn with rewriting enabled. It should rewrite to "#".
        policy.urls.idn = RuleWithReplace::with_default(LogLevel::Warn);
        let mut output2 = Vec::new();
        {
            let mut rewriter = create_rewriter(&logger, &policy, &mut crawler_state, &mut output2);
            rewriter
                .write(b"<a href=\"http://googl\xC3\xA9.com\">Link</a>")
                .unwrap();
            rewriter.end().unwrap();
        }
        let out_str2 = String::from_utf8(output2).unwrap();
        assert!(out_str2.contains("href=\"#\""));
    }
}
