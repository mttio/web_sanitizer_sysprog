use std::{error::Error, io::Write, sync::{Arc, Mutex}};

use lol_html::{
    element,
    send::{HtmlRewriter, Settings},
};
use url::Url;

use crate::sanitizer_engine::{
    errors::DangerousDomainInHtml, log::Logger, policy::Policy, url::RuleMatch,
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
/// * `Result<(), Box<dyn std::error::Error + Send + Sync>>` - `Ok(())` if processing succeeded (or was handled by policies), otherwise an error.
fn handle_dangerous_link(
    el: &mut lol_html::html_content::Element<'_, '_, lol_html::send::SendHandlerTypes>,
    attr_name: &str,
    base_url: &Arc<Mutex<Url>>,
    policy: &Policy,
    logger: &Logger,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(val) = el.get_attribute(attr_name) {
        let resolved = {
            let current_base = base_url.lock().unwrap();
            current_base.join(&val)
        };
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
                let result = policy.html.dangerous_domain_action.handle_error(
                    logger,
                    || -> Result<_, Box<dyn Error + Send + Sync>> {
                        resolved_url.set_host(Some("example.com"))?;
                        el.set_attribute(attr_name, resolved_url.as_ref())?;
                        Ok(())
                    },
                    DangerousDomainInHtml(host.to_owned(), location.bytes().start),
                );

                match result {
                    Err(e) => logger.error(e),
                    Ok(Some(Err(e))) => logger.error(e.to_string()),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Creates an `HtmlRewriter` to inspect and rewrite standard anchors and links in a stream of HTML bytes.
///
/// # Inputs
/// * `logger` - The logging interface.
/// * `policy` - The security policy configuration.
/// * `output` - The output stream writer to write the rewritten HTML bytes to.
///
/// # Returns
/// * `HtmlRewriter<'a, impl FnMut(&[u8])>` - The rewriter instance setup with element handlers for `a[href]` and `link[href]`.
pub fn create_rewriter<'a, W: Write>(
    logger: &'a Logger,
    policy: &'a Policy,
    mut output: W,
) -> HtmlRewriter<'a, impl FnMut(&[u8])> {
    HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![element!("a[href], link[href]", move |el| {
                let href = el.get_attribute("href").expect("href was required");
                if let Ok(mut href) = Url::parse(&href)
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
                        let result = policy.html.dangerous_domain_action.handle_error(
                            logger,
                            || -> Result<_, Box<dyn Error + Send + Sync>> {
                                href.set_host(Some("example.com"))?;
                                el.set_attribute("href", href.as_ref())?;
                                Ok(())
                            },
                            DangerousDomainInHtml(host.to_owned(), location.bytes().start),
                        );

                        match result {
                            Err(e) => logger.error(e),
                            Ok(Some(Err(e))) => logger.error(e.to_string()),
                            _ => {}
                        }
                    }
                }

                Ok(())
            })],
            ..Settings::new_send()
        },
        move |c: &[u8]| {
            output.write_all(c).unwrap();
        },
    )
}

/// Creates an `HtmlRewriter` that extracts sub-resources, resolves them relative to the document's base URL,
/// rewrites their HTML reference paths to local names, and registers them for recursive crawling.
///
/// # Inputs
/// * `logger` - The logging interface.
/// * `policy` - The security policy configuration.
/// * `base_url` - The thread-safe container for tracking the dynamic base URL (affected by `<base>`).
/// * `sub_resources` - The thread-safe accumulator vector for storing resolved sub-resource URLs and local paths.
/// * `output` - The output stream writer to write the rewritten HTML bytes to.
///
/// # Returns
/// * `HtmlRewriter<'a, impl FnMut(&[u8])>` - The rewriter instance setup with element handlers for base tags, sub-resources, and anchors.
pub fn create_rewriter_with_crawler<'a, W: Write>(
    logger: &'a Logger,
    policy: &'a Policy,
    base_url: Arc<Mutex<Url>>,
    sub_resources: Arc<Mutex<Vec<(Url, String)>>>,
    mut output: W,
) -> HtmlRewriter<'a, impl FnMut(&[u8])> {
    let base_url_for_links = Arc::clone(&base_url);
    let base_url_for_sub = Arc::clone(&base_url);
    let base_url_for_base = Arc::clone(&base_url);
    
    HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("base[href]", move |el| {
                    if let Some(href) = el.get_attribute("href") {
                        let mut current_base = base_url_for_base.lock().unwrap();
                        if let Ok(new_base) = current_base.join(&href) {
                            *current_base = new_base;
                        }
                    }
                    Ok(())
                }),
                element!("link[href], script[src], img[src], image[href], source[src]", move |el| {
                    let tag_name = el.tag_name().to_lowercase();
                    let attr_name = if tag_name == "link" || tag_name == "image" { "href" } else { "src" };
                    
                    if tag_name == "link" {
                        let rel = el.get_attribute("rel").unwrap_or_default().to_lowercase();
                        if !rel.contains("stylesheet") {
                            return handle_dangerous_link(el, attr_name, &base_url_for_sub, policy, logger);
                        }
                    }
                    
                    if let Some(val) = el.get_attribute(attr_name) {
                        let resolved = {
                            let current_base = base_url_for_sub.lock().unwrap();
                            current_base.join(&val)
                        };
                        if let Ok(resolved_url) = resolved {
                            if resolved_url.scheme() == "https" {
                                if let Some(host) = resolved_url.host() {
                                    let host_owned = host.to_owned();
                                    let is_dangerous = policy.urls.dangerous_domains.iter().any(|x| x.0.matches(&host_owned));
                                    if is_dangerous {
                                        let location = el.source_location();
                                        let result = policy.html.dangerous_domain_action.handle_error(
                                            logger,
                                            || -> Result<_, Box<dyn Error + Send + Sync>> {
                                                el.set_attribute(attr_name, "")?;
                                                Ok(())
                                            },
                                            DangerousDomainInHtml(host_owned, location.bytes().start),
                                        );
                                        match result {
                                            Err(e) => logger.error(e),
                                            Ok(Some(Err(e))) => logger.error(e.to_string()),
                                            _ => {}
                                        }
                                        return Ok(());
                                    }
                                }
                                
                                let default_ext = match tag_name.as_str() {
                                    "link" => "css",
                                    "script" => "js",
                                    _ => "png",
                                };
                                let local_name = crate::sanitizer_engine::resource_sanitizer::generate_local_filename(&resolved_url, default_ext);
                                
                                el.set_attribute(attr_name, &local_name)?;
                                sub_resources.lock().unwrap().push((resolved_url, local_name));
                            }
                        }
                    }
                    Ok(())
                }),
                element!("a[href]", move |el| {
                    handle_dangerous_link(el, "href", &base_url_for_links, policy, logger)
                })
            ],
            ..Settings::new_send()
        },
        move |c: &[u8]| {
            output.write_all(c).unwrap();
        },
    )
}
