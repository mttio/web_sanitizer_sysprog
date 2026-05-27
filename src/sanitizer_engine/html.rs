use std::{error::Error, io::Write};

use lol_html::{
    element,
    send::{HtmlRewriter, Settings},
};
use url::Url;

use crate::sanitizer_engine::{
    errors::DangerousDomainInHtml, log::Logger, policy::Policy, url::RuleMatch,
};

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
                            || -> Result<_, Box<dyn Error>> {
                                href.set_host(Some("example.com"))?;
                                el.set_attribute("href", href.as_ref())?;
                                Ok(())
                            },
                            DangerousDomainInHtml(host.to_owned(), location.bytes().start),
                        );

                        match result {
                            Err(e) => logger.error(e),
                            Ok(Some(Err(e))) => logger.error(e),
                            _ => {}
                        }
                    }
                }

                Ok(())
            })],
            ..Settings::new_send()
        },
        move |c: &[u8]| {
            // println!("{}\n", str::from_utf8(c).unwrap());
            output.write_all(c).unwrap();
        },
    )
}
