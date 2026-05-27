use itertools::Itertools;
use url::{Host, Url};

pub fn check_domain(url: &Url) -> Option<String> {
    if let Some(Host::Domain(domain, original)) = url.host()
        && domain != original
    {
        let domain = Iterator::zip(domain.split('.'), original.split('.'))
            .map(|(parsed, original)| {
                if let Some(parsed) = parsed.strip_prefix("xn--") {
                    let mut result = String::new();
                    let mut original = original.chars();

                    'outer: for p in parsed.chars() {
                        for o in original.by_ref() {
                            if o == p {
                                result.push(o);
                                continue 'outer;
                            } else if o.to_ascii_lowercase() == p {
                                result.push_str("\x1b[95;1m");
                                result.push(o);
                                result.push_str("\x1b[0m");
                                continue 'outer;
                            } else {
                                result.push_str("\x1b[91;1m");
                                result.push(o);
                                result.push_str("\x1b[0m");
                            }
                        }
                    }
                    result
                } else {
                    let mut result = String::new();

                    for o in original.chars() {
                        if o.is_ascii_uppercase() {
                            result.push_str("\x1b[95;1m");
                            result.push(o);
                            result.push_str("\x1b[0m");
                        } else {
                            result.push(o);
                        }
                    }
                    result
                }
            })
            .join(".");

        Some(domain)
    } else {
        None
    }
}

pub trait RuleMatch: std::marker::Sized {
    type RuleType;
    fn matches(&self, rule: &Self::RuleType) -> bool;
}

impl RuleMatch for Host {
    type RuleType = Self;

    fn matches(&self, rule: &Self::RuleType) -> bool {
        // TODO: avoid calling `to_string` every time
        let target = self.to_string();
        let Some(prefix) = target.strip_suffix(&rule.to_string()) else {
            return false;
        };

        prefix.is_empty() || prefix.ends_with('.')
    }
}
