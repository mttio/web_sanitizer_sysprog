use lol_html::{
    element,
    send::{HtmlRewriter, Settings},
};
use std::io::Write;
use url::Url;

use crate::{
    errors::{LoggerError, SanitizerError},
    log::Logger,
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
    let element_content_handlers = if policy.resources.fetch_sub_resources {
        vec![
            element!("*", move |el| {
                if policy.html.strip_event_handlers {
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
            "base[href], a[href], link[href], script[src], img[src], image[href], source[src]",
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
        )]
    } else {
        vec![
            element!("*", move |el| {
                if policy.html.strip_event_handlers {
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
            element!("a[href], link[href]", move |el| {
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
        })]
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
        let mut policy = Policy::default();
        policy.html.strip_event_handlers = true;

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
        policy.html.strip_event_handlers = true;
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
}
