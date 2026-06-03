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

/// Creates an `HtmlRewriter` to inspect and rewrite HTML contents.
///
/// If `policy.resources.fetch_sub_resources` is `true` and a `crawler_state` is provided,
/// the rewriter will rewrite relative paths for scripts, styles, and other resources to local paths,
/// and enqueue them to be crawled. Otherwise, it will only inspect and clean standard anchors and links.
///
/// # Inputs
/// * `logger` - The logging interface.
/// * `policy` - The security policy configuration.
/// * `crawler_state` - Optional tuple containing the document's thread-safe base URL and discovered resources accumulator.
/// * `output` - The output stream writer to write the rewritten HTML bytes to.
///
/// # Returns
/// * `HtmlRewriter<'a, impl FnMut(&[u8])>` - The configured rewriter instance.
pub fn create_rewriter<'a, W: Write>(
    logger: &'a Logger,
    policy: &'a Policy,
    crawler_state: Option<(Arc<Mutex<Url>>, Arc<Mutex<Vec<(Url, String)>>>)>,
    mut output: W,
) -> HtmlRewriter<'a, impl FnMut(&[u8])> {
    let element_content_handlers = if policy.resources.fetch_sub_resources
        && let Some((base_url, sub_resources)) = &crawler_state
    {
        let base_url_for_links = Arc::clone(base_url);
        let base_url_for_sub = Arc::clone(base_url);
        let base_url_for_base = Arc::clone(base_url);
        let sub_resources = Arc::clone(sub_resources);

        vec![
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
        ]
    } else {
        vec![
            element!("a[href], link[href]", move |el| {
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
