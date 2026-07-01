use itertools::Itertools;

use crate::errors::SanitizerError;

/// Scans JS file for dangerous constructs (eval, document.write).
///
/// # Inputs
/// * `content` - A string slice containing the JavaScript source code.
///
/// # Returns
/// * `Result<(), SanitizationError>` - `Ok` if no dangerous keywords are found, otherwise an `Err` indicating what was found.
pub fn sanitize(content: &str) -> Result<(), SanitizerError> {
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c == 'e' {
            let mut temp = chars.clone();
            if temp.next_array() == Some(['v', 'a', 'l']) {
                while let Some(&next_c) = temp.peek() {
                    if next_c.is_whitespace() {
                        temp.next();
                    } else {
                        break;
                    }
                }
                if temp.peek() == Some(&'(') {
                    return Err(SanitizerError::DangerousJsConstruct("eval(...)".to_owned()));
                }
            }
        }
        if c == 'd' {
            let mut temp = chars.clone();
            if temp.next_array() == Some(['o', 'c', 'u', 'm', 'e', 'n', 't']) {
                let mut temp = temp.skip_while(|c| c.is_whitespace());
                if temp.next() == Some('.') {
                    let mut temp = temp.skip_while(|c| c.is_whitespace());
                    if temp.next_array() == Some(['w', 'r', 'i', 't', 'e']) {
                        return Err(SanitizerError::DangerousJsConstruct(
                            "document.write(...)".to_owned(),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize() {
        assert!(sanitize("console.log('hello');").is_ok());
        assert!(sanitize("eval('1 + 1');").is_err());
        assert!(sanitize("document.write('xss');").is_err());
    }

    #[test]
    fn test_sanitize_spaces() {
        assert!(sanitize("eval    (  '1+1'  )").is_err());
        assert!(sanitize("let evaluator = 1;").is_ok());
        assert!(sanitize("document.write()").is_err());
    }
}
