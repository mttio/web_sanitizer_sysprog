use lol_html::{
    element,
    text,
    send::{HtmlRewriter, Settings},
};
use std::io::Write;
use url::Url;

use crate::{
    errors::{LoggerError, SanitizerError},
    log::{Logger, LoggerTrait},
    policy::Policy,
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
) -> Result<(), LoggerError> {
    if let Some(val) = el.get_attribute(attr_name) {
        let resolved = base_url.join(&val);
        if let Ok(mut resolved_url) = resolved
            && let Some(host) = resolved_url.host()
        {
            let host = host.to_owned();
            let is_dangerous = policy
                .urls
                .dangerous_domains
                .iter()
                .any(|x| x.0.matches(&host));

            let location = el.source_location();

            if is_dangerous {
                return policy.html.dangerous_domain.handle(
                    logger,
                    |x| -> Result<_, LoggerError> {
                        let new = match resolved_url.set_host(Some(x)) {
                            // If policy value is a valid host, replace the host of the old url
                            Ok(_) => resolved_url.as_ref(),
                            // Otherwise replace the whole url with the policy value
                            Err(_) => x,
                        };
                        el.set_attribute(attr_name, new)?;
                        Ok(())
                    },
                    SanitizerError::DangerousDomainInHtml(host.to_owned(), location.bytes().start),
                )?;
            }
        }
    }
    Ok(())
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
    use std::sync::Arc;
    use parking_lot::Mutex;

    let inline_script_location = Arc::new(Mutex::new(None));
    let inline_script_location_el_1 = inline_script_location.clone();
    let inline_script_location_el_2 = inline_script_location.clone();
    let inline_script_location_text_1 = inline_script_location.clone();
    let inline_script_location_text_2 = inline_script_location.clone();

    let inline_script_buffer = Arc::new(Mutex::new(String::new()));
    let inline_script_buffer_text_1 = inline_script_buffer.clone();
    let inline_script_buffer_text_2 = inline_script_buffer.clone();

    let policy_allow_scripts_el_1 = policy.html.allow_scripts.clone();
    let policy_allow_scripts_el_2 = policy.html.allow_scripts.clone();
    let policy_allow_scripts_text_1 = policy.html.allow_scripts.clone();
    let policy_allow_scripts_text_2 = policy.html.allow_scripts.clone();

    let logger_clone_el_1 = logger.clone();
    let logger_clone_el_2 = logger.clone();
    let logger_clone_text_1 = logger.clone();
    let logger_clone_text_2 = logger.clone();

    let element_content_handlers = if policy.resources.fetch_sub_resources {
        vec![
            element!("*", move |el| {
                if !policy.html.event_handlers.is_ignore() {
                    let event_attrs: Vec<String> = el.attributes()
                        .iter()
                        .map(|attr| attr.name())
                        .filter(|name| name.to_lowercase().starts_with("on"))
                        .collect();

                    for attr_name in event_attrs {
                        let location = el.source_location();
                        policy.html.event_handlers.handle(
                            logger,
                            |replacement| -> Result<(), LoggerError> {
                                if replacement.is_empty() {
                                    el.remove_attribute(&attr_name);
                                } else {
                                    el.set_attribute(&attr_name, replacement).map_err(|e| Box::new(e) as LoggerError)?;
                                }
                                Ok(())
                            },
                            SanitizerError::EventHandler(attr_name.clone(), Some(location.bytes().start)),
                        )??;
                    }
                }
                Ok(())
            }),
            element!(
            "base[href], a[href], link[href], script, img[src], image[href], source[src]",
            move |el| {
                match el.tag_name().as_str() {
                    "base" => {
                        if let Some(href) = el.get_attribute("href")
                            && let Ok(new_base) = state.base.join(&href)
                        {
                            state.base = new_base;
                        }
                        Ok(())
                    }
                    "a" => handle_dangerous_link(el, "href", &state.base, policy, logger),
                    "script" => {
                        let location = el.source_location();
                        if let Some(src) = el.get_attribute("src") {
                            if let Ok(resolved_url) = state.base.join(&src) {
                                let host_matched = if let Some(host) = resolved_url.host() {
                                    let host_str = host.to_string();
                                    policy_allow_scripts_el_1.iter().any(|allowed| {
                                        allowed == &host_str || resolved_url.as_str().starts_with(allowed)
                                    })
                                } else {
                                    false
                                };

                                if !host_matched {
                                    logger_clone_el_1.error(SanitizerError::BlockedScript(src.clone(), location.bytes().start));
                                    el.remove();
                                    return Ok(());
                                }

                                if policy.resources.fetch_sub_resources {
                                    let local_name = crate::resources::generate_local_filename(&resolved_url, "js");
                                    el.set_attribute("src", &local_name).map_err(|e| Box::new(e) as LoggerError)?;
                                    state.subresources.push((resolved_url, local_name));
                                }
                            } else {
                                logger_clone_el_1.error(SanitizerError::BlockedScript(src.clone(), location.bytes().start));
                                el.remove();
                            }
                        } else {
                            *inline_script_location_el_1.lock() = Some(location.bytes().start);
                        }
                        Ok(())
                    }
                    tag_name => {
                        let tag_name = tag_name.to_lowercase();
                        let attr_name = if tag_name == "link" || tag_name == "image" {
                            "href"
                        } else {
                            "src"
                        };

                        if tag_name == "link" {
                            let rel = el.get_attribute("rel").unwrap_or_default().to_lowercase();
                            if !rel.contains("stylesheet") {
                                return handle_dangerous_link(
                                    el,
                                    attr_name,
                                    &state.base,
                                    policy,
                                    logger,
                                );
                            }
                        }

                        if let Some(val) = el.get_attribute(attr_name) {
                            let resolved = state.base.join(&val);
                            if let Ok(resolved_url) = resolved
                                && resolved_url.scheme() == "https"
                            {
                                if let Some(host) = resolved_url.host() {
                                    let host_owned = host.to_owned();
                                    let is_dangerous = policy
                                        .urls
                                        .dangerous_domains
                                        .iter()
                                        .any(|x| x.0.matches(&host_owned));
                                    if is_dangerous {
                                        let location = el.source_location();
                                        let _ = policy.html.dangerous_domain.handle(
                                            logger,
                                            |x| el.set_attribute(attr_name, x),
                                            SanitizerError::DangerousDomainInHtml(
                                                host_owned,
                                                location.bytes().start,
                                            ),
                                        )?;
                                        return Ok(());
                                    }
                                }

                                let default_ext = match tag_name.as_str() {
                                    "link" => "css",
                                    "script" => "js",
                                    _ => "png",
                                };
                                let local_name = crate::resources::generate_local_filename(
                                    &resolved_url,
                                    default_ext,
                                );

                                el.set_attribute(attr_name, &local_name)?;
                                state.subresources.push((resolved_url, local_name));
                            }
                        }
                        Ok(())
                    }
                }
            }
            ),
            text!("script", move |t| {
                use sha2::{Sha256, Digest};
                use base64::{prelude::BASE64_STANDARD, Engine};

                let mut accum = inline_script_buffer_text_1.lock();
                accum.push_str(t.as_str());
                t.remove();

                if t.last_in_text_node() {
                    let mut hasher = Sha256::new();
                    hasher.update(accum.as_bytes());
                    let hash_result = hasher.finalize();
                    let b64_hash = BASE64_STANDARD.encode(hash_result);
                    let csp_hash = format!("sha256-{}", b64_hash);

                    let is_allowed = policy_allow_scripts_text_1.iter().any(|allowed| allowed == &csp_hash);
                    if is_allowed {
                        t.replace(&accum, lol_html::html_content::ContentType::Text);
                    } else {
                        let offset = inline_script_location_text_1.lock().unwrap_or(0);
                        logger_clone_text_1.error(SanitizerError::BlockedScript("<inline>".to_owned(), offset));
                    }
                    accum.clear();
                    *inline_script_location_text_1.lock() = None;
                }
                Ok(())
            })
        ]
    } else {
        let base_url = state.base.clone();
        vec![
            element!("*", move |el| {
                if !policy.html.event_handlers.is_ignore() {
                    let event_attrs: Vec<String> = el.attributes()
                        .iter()
                        .map(|attr| attr.name())
                        .filter(|name| name.to_lowercase().starts_with("on"))
                        .collect();

                    for attr_name in event_attrs {
                        let location = el.source_location();
                        policy.html.event_handlers.handle(
                            logger,
                            |replacement| -> Result<(), LoggerError> {
                                if replacement.is_empty() {
                                    el.remove_attribute(&attr_name);
                                } else {
                                    el.set_attribute(&attr_name, replacement).map_err(|e| Box::new(e) as LoggerError)?;
                                }
                                Ok(())
                            },
                            SanitizerError::EventHandler(attr_name.clone(), Some(location.bytes().start)),
                        )??;
                    }
                }
                Ok(())
            }),
            element!("a[href], link[href], script", move |el| {
                if el.tag_name() == "script" {
                    let location = el.source_location();
                    if let Some(src) = el.get_attribute("src") {
                        if let Ok(resolved_url) = base_url.join(&src) {
                            let host_matched = if let Some(host) = resolved_url.host() {
                                let host_str = host.to_string();
                                policy_allow_scripts_el_2.iter().any(|allowed| {
                                    allowed == &host_str || resolved_url.as_str().starts_with(allowed)
                                })
                            } else {
                                false
                            };

                            if !host_matched {
                                logger_clone_el_2.error(SanitizerError::BlockedScript(src.clone(), location.bytes().start));
                                el.remove();
                                return Ok(());
                            }
                        } else {
                            logger_clone_el_2.error(SanitizerError::BlockedScript(src.clone(), location.bytes().start));
                            el.remove();
                        }
                    } else {
                        *inline_script_location_el_2.lock() = Some(location.bytes().start);
                    }
                    return Ok(());
                }
                let href = el.get_attribute("href").expect("href was required");
                if let Ok(href) = Url::parse(&href)
                && let Some(host) = href.host()
            {
                let host = host.to_owned();
                let is_dangerous = policy
                    .urls
                    .dangerous_domains
                    .iter()
                    .any(|x| x.0.matches(&host));

                let location = el.source_location();

                if is_dangerous {
                    let _ = policy.html.dangerous_domain.handle(
                        logger,
                        |x| el.set_attribute("href", x),
                        SanitizerError::DangerousDomainInHtml(
                            host.to_owned(),
                            location.bytes().start,
                        ),
                    )?;
                }
            }

            Ok(())
        }),
            text!("script", move |t| {
                use sha2::{Sha256, Digest};
                use base64::{prelude::BASE64_STANDARD, Engine};

                let mut accum = inline_script_buffer_text_2.lock();
                accum.push_str(t.as_str());
                t.remove();

                if t.last_in_text_node() {
                    let mut hasher = Sha256::new();
                    hasher.update(accum.as_bytes());
                    let hash_result = hasher.finalize();
                    let b64_hash = BASE64_STANDARD.encode(hash_result);
                    let csp_hash = format!("sha256-{}", b64_hash);

                    let is_allowed = policy_allow_scripts_text_2.iter().any(|allowed| allowed == &csp_hash);
                    if is_allowed {
                        t.replace(&accum, lol_html::html_content::ContentType::Text);
                    } else {
                        let offset = inline_script_location_text_2.lock().unwrap_or(0);
                        logger_clone_text_2.error(SanitizerError::BlockedScript("<inline>".to_owned(), offset));
                    }
                    accum.clear();
                    *inline_script_location_text_2.lock() = None;
                }
                Ok(())
            })
        ]
    };

    HtmlRewriter::new(
        Settings {
            element_content_handlers,
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
    use crate::log::Logger;
    use std::sync::mpsc;

    #[test]
    fn test_event_handler_stripping() {
        let (tx, _rx) = mpsc::channel();
        let logger = Logger { index: 0, channel: tx };
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
        let logger = Logger { index: 0, channel: tx };
        let mut policy = Policy::default();
        policy.html.event_handlers = crate::rules::RuleWithReplace::new("alert('blocked')".to_owned(), crate::log::LogLevel::Info);

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
        let logger = Logger { index: 0, channel: tx };
        let mut policy = Policy::default();
        policy.html.event_handlers = crate::rules::RuleWithReplace::new("".to_owned(), crate::log::LogLevel::Ignore);

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
        let logger = Logger { index: 0, channel: tx };
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
        let logger = Logger { index: 0, channel: tx };
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
        let logger = Logger { index: 0, channel: tx };
        let mut policy = Policy::default();
        policy.html.allow_scripts = vec!["sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=".to_owned()];

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
        let logger = Logger { index: 0, channel: tx };
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
}
