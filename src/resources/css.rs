use url::Url;

use crate::{errors::SanitizerError, log::Log, rules::RuleWithReplace};

/// Scans CSS content for @import and url(...) references, validates/rewrites them, and extracts them.
///
/// # Inputs
/// * `css` - A string slice containing the CSS source code.
/// * `base_url` - The base URL of the CSS file used to resolve relative imports/links.
///
/// # Returns
/// * `(String, Vec<(Url, String)>)` - A tuple containing:
///   1. The rewritten CSS string with references updated to local filenames.
///   2. A vector of tuples pairing the fully resolved absolute URLs of discovered sub-resources with their generated local filenames.
pub fn sanitize(
    css: &str,
    base_url: &Url,
    logger: &impl Log,
    rule: &RuleWithReplace<String>,
) -> Result<(String, Vec<(Url, String)>), SanitizerError> {
    let mut output = String::new();
    let mut extracted = Vec::new();
    let chars: Vec<char> = css.chars().collect();
    let mut i = 0;

    fn skip_whitespace(chars: &[char], i: &mut usize) {
        while *i < chars.len() && chars[*i].is_whitespace() {
            *i += 1;
        }
    }

    fn read_url_string(chars: &[char], i: &mut usize, end: char) -> String {
        let mut result = String::new();

        skip_whitespace(chars, i);

        let delimiter = match chars.get(*i) {
            Some('"') => Some('"'),
            Some('\'') => Some('\''),
            _ => None,
        };
        if delimiter.is_some() {
            *i += 1;
        }

        let mut previous_backslash = false;

        while let Some(&c) = chars.get(*i) {
            if delimiter == Some(c) && !previous_backslash {
                *i += 1;
                break;
            }

            if c == end && delimiter.is_none() && !previous_backslash {
                *i += 1;
                break;
            }

            if c == '\\' {
                if previous_backslash {
                    previous_backslash = false;
                    result.push('\\');
                } else {
                    previous_backslash = !previous_backslash;
                }
            } else {
                previous_backslash = false;
                result.push(c);
            }

            *i += 1;
        }

        skip_whitespace(chars, i);

        result
    }

    while i < chars.len() {
        // Match @import
        if i + 7 < chars.len()
            && chars[i..i + 7] == ['@', 'i', 'm', 'p', 'o', 'r', 't']
            && (chars[i + 7].is_whitespace() || chars[i + 7] == '(')
        {
            i += 7;
            skip_whitespace(&chars, &mut i);

            let url = if i + 4 <= chars.len() && chars[i..i + 4] == ['u', 'r', 'l', '('] {
                i += 4;
                let url = read_url_string(&chars, &mut i, ')');

                while let Some(&c) = chars.get(i)
                    && c != ';'
                {
                    i += 1;
                }
                i += 1;

                url
            } else {
                read_url_string(&chars, &mut i, ';')
            };

            let url_clean = url.trim().to_string();
            if !url_clean.is_empty()
                && let Ok(resolved_url) = base_url.join(&url_clean)
            {
                let local_name = super::generate_local_filename(&resolved_url, "css");
                extracted.push((resolved_url, local_name.clone()));
                output.push_str(&format!("@import \"{}\";", local_name));
            }
            continue;
        }

        // Match url(
        if i + 4 <= chars.len() && chars[i..i + 4] == ['u', 'r', 'l', '('] {
            i += 4;

            let url = read_url_string(&chars, &mut i, ')');

            let url_clean = url.trim().to_string();
            if url_clean.starts_with("data:") || url_clean.starts_with("javascript:") {
                if let Some(replace) =
                    rule.handle(logger, SanitizerError::DangerousCssConstruct(url_clean))?
                {
                    output.push_str(&format!("url(\"{replace}\")"));
                } else {
                    output.push_str(&format!("url({url})"));
                }
            } else if let Ok(resolved_url) = base_url.join(&url_clean) {
                let ext = url_clean
                    .rsplit('.')
                    .next()
                    .unwrap_or("bin")
                    .split('?')
                    .next()
                    .unwrap_or("bin");
                let local_name = super::generate_local_filename(&resolved_url, ext);
                output.push_str(&format!("url(\"{}\")", local_name));
                extracted.push((resolved_url, local_name));
            } else {
                output.push_str("url(\"\")");
            }
            continue;
        }

        output.push(chars[i]);
        i += 1;
    }

    Ok((output, extracted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{LogLevel, NullLogger};

    #[test]
    fn test_sanitize() {
        let base_url = Url::parse("https://example.com/dir/style.css").unwrap();
        let css = "body { background: url('img.png'); } @import 'common.css';";
        let (rewritten, extracted) = sanitize(
            css,
            &base_url,
            &NullLogger,
            &RuleWithReplace::with_default(LogLevel::Warn),
        )
        .unwrap();

        assert!(rewritten.contains("url(\"sub_"));
        assert!(rewritten.contains("@import \"sub_"));
        assert_eq!(extracted.len(), 2);
        assert_eq!(
            extracted[0].0,
            Url::parse("https://example.com/dir/img.png").unwrap()
        );
        assert_eq!(
            extracted[1].0,
            Url::parse("https://example.com/dir/common.css").unwrap()
        );
    }

    #[test]
    fn test_sanitize_dangerous_uris() {
        let base_url = Url::parse("https://example.com/style.css").unwrap();
        let css = "body { background: url('data:image/png;base64,1234'); font: url('javascript:alert(1)'); }";
        let (rewritten, extracted) = sanitize(
            css,
            &base_url,
            &NullLogger,
            &RuleWithReplace::with_default(LogLevel::Warn),
        )
        .unwrap();
        assert!(rewritten.contains("url(\"\")"));
        assert_eq!(extracted.len(), 0);
    }
}
