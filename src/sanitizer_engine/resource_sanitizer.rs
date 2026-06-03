use itertools::Itertools;
use std::error::Error;
use std::fmt::Display;
use url::Url;

#[derive(Debug)]
pub struct SanitizationError(pub String);
impl Error for SanitizationError {}
impl Display for SanitizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub struct MimeError(pub String);
impl Error for MimeError {}
impl Display for MimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MIME confusion: declared {} but content doesn't match signature",
            self.0
        )
    }
}

/// Sniffs the mime type of a byte buffer using [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures).
///
/// # Inputs
/// * `data` - A slice of bytes representing the file content.
///
/// # Returns
/// * `Option<&'static str>` - `Some(...)` if a signature is matched, otherwise `None`.
pub fn sniff_mime(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\x89PNG\x0D\x0A\x1A\x0A") {
        Some("image/png")
    } else if data.starts_with(b"\xFF\xD8") {
        Some("image/jpeg")
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some("image/webp")
    } else if data.starts_with(b"%PDF") {
        Some("application/pdf")
    } else {
        None
    }
}

/// Extracts the MIME type from a `Content-Type` header and normalizes it
pub fn clean_mime(content_type: &str) -> String {
    let clean = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_lowercase();

    // TODO: is this necessary?
    // https://www.iana.org/assignments/media-types/media-types.xhtml <- `image/png` not present
    // https://stackoverflow.com/questions/33692835
    if clean == "image/jpg" {
        "image/jpeg".to_owned()
    } else {
        clean
    }
}

/// Validates that the declared MIME type matches the sniffed MIME type.
///
/// # Returns
/// * `Result<(), SanitizationError>` - `Ok(())` if the content matches or if there is no mismatch, otherwise a `Err(SanitizationError)` detailing the MIME confusion mismatch.
pub fn validate_mime(declared: Option<&str>, sniffed: Option<&str>) -> Result<(), MimeError> {
    if let Some(decl) = declared {
        let clean = clean_mime(decl);

        if matches!(
            clean.as_str(),
            "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "application/pdf"
        ) && sniffed != Some(&clean)
        {
            return Err(MimeError(clean));
        }
    }

    Ok(())
}

/// Helper to generate a unique local filename deterministic for a URL.
///
/// # Inputs
/// * `url` - The URL reference for which to generate the filename.
/// * `default_ext` - The fallback extension string slice if no extension is parsed from the URL.
///
/// # Returns
/// * `String` - A deterministic, unique local filename (e.g. `sub_0123456789abcdef.css`).
pub fn generate_local_filename(url: &Url, default_ext: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    let hash_val = hasher.finish();

    // Try to extract clean extension from path
    let last_segment = url.path().split('/').next_back().unwrap_or("");
    let ext = last_segment
        .rsplit_once('.')
        .map(|(_, x)| x)
        .unwrap_or(default_ext);
    let ext = ext
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>();

    let ext = if ext.is_empty() { default_ext } else { &ext };

    format!("sub_{:016x}.{}", hash_val, ext)
}

/// Strips EXIF/metadata segment (APP1 0xFFE1) from JPEG files.
///
/// # Inputs
/// * `data` - A byte slice containing raw JPEG data.
///
/// # Returns
/// * `Vec<u8>` - A new vector with all APP1 (`0xFFE1`) metadata segments removed.
pub fn strip_jpeg_metadata(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return data.to_vec();
    }
    output.push(0xFF);
    output.push(0xD8);
    let mut i = 2;
    while i < data.len() {
        if data[i] == 0xFF {
            if i + 1 >= data.len() {
                output.push(0xFF);
                break;
            }
            let marker = data[i + 1];
            if marker == 0x00 {
                output.push(0xFF);
                output.push(0x00);
                i += 2;
                continue;
            }
            if marker == 0xD9 {
                output.push(0xFF);
                output.push(0xD9);
                break;
            }
            if (0xD0..=0xD7).contains(&marker) {
                output.push(0xFF);
                output.push(marker);
                i += 2;
                continue;
            }
            if i + 3 >= data.len() {
                output.extend_from_slice(&data[i..]);
                break;
            }
            let len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
            if i + 2 + len > data.len() {
                output.extend_from_slice(&data[i..]);
                break;
            }
            if marker == 0xE1 {
                // Strip APP1 marker which typically contains EXIF metadata
                i += 2 + len;
            } else {
                output.extend_from_slice(&data[i..i + 2 + len]);
                i += 2 + len;
            }
        } else {
            output.push(data[i]);
            i += 1;
        }
    }
    output
}

/// Strips metadata chunks from PNG files.
///
/// # Inputs
/// * `data` - A byte slice containing raw PNG data.
///
/// # Returns
/// * `Vec<u8>` - A new vector with metadata chunks (`tEXt`, `zTXt`, `iTXt`, `eXIf`, `iCCP`, `gAMA`, `sRGB`, `tIME`) removed.
pub fn strip_png_metadata(data: &[u8]) -> Vec<u8> {
    let sig = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || &data[0..8] != sig {
        return data.to_vec();
    }
    let mut output = Vec::with_capacity(data.len());
    output.extend_from_slice(sig);
    let mut i = 8;
    while i + 8 <= data.len() {
        let chunk_len = ((data[i] as u32) << 24
            | (data[i + 1] as u32) << 16
            | (data[i + 2] as u32) << 8
            | (data[i + 3] as u32)) as usize;
        let chunk_type = &data[i + 4..i + 8];

        if i + 12 + chunk_len > data.len() {
            output.extend_from_slice(&data[i..]);
            break;
        }

        let is_metadata = matches!(
            chunk_type,
            b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"iCCP" | b"gAMA" | b"sRGB" | b"tIME"
        );

        if is_metadata {
            i += 12 + chunk_len;
        } else {
            output.extend_from_slice(&data[i..i + 12 + chunk_len]);
            i += 12 + chunk_len;
        }
    }
    output
}

/// Scans JS file for dangerous constructs (eval, document.write).
///
/// # Inputs
/// * `content` - A string slice containing the JavaScript source code.
///
/// # Returns
/// * `Result<String, SanitizationError>` - `Ok(content)` if no dangerous keywords are found, otherwise an `Err(SanitizationError)` indicating what was found.
pub fn sanitize_javascript(content: &str) -> Result<String, SanitizationError> {
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c == 'e' {
            let mut temp = chars.clone();
            if temp.next() == Some('v') && temp.next() == Some('a') && temp.next() == Some('l') {
                while let Some(&next_c) = temp.peek() {
                    if next_c.is_whitespace() {
                        temp.next();
                    } else {
                        break;
                    }
                }
                if temp.peek() == Some(&'(') {
                    return Err(SanitizationError(
                        "Dangerous construct 'eval(...)' detected in JS".into(),
                    ));
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
                        return Err(SanitizationError(
                            "Dangerous construct 'document.write(...)' detected in JS".into(),
                        ));
                    }
                }
            }
        }
    }
    Ok(content.to_string())
}

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
pub fn sanitize_css(css: &str, base_url: &Url) -> (String, Vec<(Url, String)>) {
    let mut output = String::new();
    let mut extracted = Vec::new();
    let chars: Vec<char> = css.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Match @import
        if i + 7 < chars.len()
            && chars[i..i + 7] == ['@', 'i', 'm', 'p', 'o', 'r', 't']
            && (chars[i + 7].is_whitespace() || chars[i + 7] == '(')
        {
            i += 7;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            let mut url_str = String::new();
            if i + 4 <= chars.len() && chars[i..i + 4] == ['u', 'r', 'l', '('] {
                i += 4;
                while i < chars.len() && chars[i] != ')' {
                    url_str.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    i += 1;
                }
            } else if i < chars.len() && (chars[i] == '"' || chars[i] == '\'') {
                let quote = chars[i];
                i += 1;
                while i < chars.len() && chars[i] != quote {
                    url_str.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    i += 1;
                }
            } else {
                while i < chars.len() && chars[i] != ';' {
                    url_str.push(chars[i]);
                    i += 1;
                }
            }

            while i < chars.len() && chars[i] != ';' {
                i += 1;
            }
            if i < chars.len() && chars[i] == ';' {
                i += 1;
            }

            let url_clean = url_str
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim()
                .to_string();
            if !url_clean.is_empty()
                && let Ok(resolved_url) = base_url.join(&url_clean)
            {
                let local_name = generate_local_filename(&resolved_url, "css");
                extracted.push((resolved_url, local_name.clone()));
                output.push_str(&format!("@import \"{}\";", local_name));
            }
            continue;
        }

        // Match url(
        if i + 4 <= chars.len() && chars[i..i + 4] == ['u', 'r', 'l', '('] {
            i += 4;
            let mut url_str = String::new();
            while i < chars.len() && chars[i] != ')' {
                url_str.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                i += 1;
            }

            let url_clean = url_str
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim()
                .to_string();
            if url_clean.starts_with("data:") || url_clean.starts_with("javascript:") {
                output.push_str("url(\"\")");
            } else if let Ok(resolved_url) = base_url.join(&url_clean) {
                let ext = url_clean
                    .rsplit('.')
                    .next()
                    .unwrap_or("bin")
                    .split('?')
                    .next()
                    .unwrap_or("bin");
                let local_name = generate_local_filename(&resolved_url, ext);
                extracted.push((resolved_url, local_name.clone()));
                output.push_str(&format!("url(\"{}\")", local_name));
            } else {
                output.push_str("url(\"\")");
            }
            continue;
        }

        output.push(chars[i]);
        i += 1;
    }

    (output, extracted)
}

//========================= TESTS ==============================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_mime() {
        assert_eq!(
            sniff_mime(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Some("image/png")
        );
        assert_eq!(sniff_mime(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(sniff_mime(b"GIF89a..."), Some("image/gif"));
        assert_eq!(sniff_mime(b"%PDF-1.4"), Some("application/pdf"));
        assert_eq!(sniff_mime(b"body {}"), None);
    }

    #[test]
    fn test_validate_mime() {
        assert!(
            validate_mime(
                Some("image/png"),
                sniff_mime(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            )
            .is_ok()
        );
        assert!(validate_mime(Some("image/jpeg"), sniff_mime(&[0xFF, 0xD8, 00, 00])).is_ok());
        assert!(validate_mime(Some("image/png"), sniff_mime(&[0xFF, 0xD8])).is_err());
    }

    #[test]
    fn test_strip_jpeg_metadata() {
        let jpeg = vec![
            0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9,
        ];
        let stripped = strip_jpeg_metadata(&jpeg);
        assert_eq!(stripped, vec![0xFF, 0xD8, 0xFF, 0xD9]);
    }

    #[test]
    fn test_strip_png_metadata() {
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        // add tEXt chunk
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // length
        png.extend_from_slice(b"tEXt"); // type
        png.extend_from_slice(b"data"); // data
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC

        let stripped = strip_png_metadata(&png);
        assert_eq!(
            stripped,
            vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
    }

    #[test]
    fn test_sanitize_javascript() {
        assert!(sanitize_javascript("console.log('hello');").is_ok());
        assert!(sanitize_javascript("eval('1 + 1');").is_err());
        assert!(sanitize_javascript("document.write('xss');").is_err());
    }

    #[test]
    fn test_sanitize_css() {
        let base_url = Url::parse("https://example.com/dir/style.css").unwrap();
        let css = "body { background: url('img.png'); } @import 'common.css';";
        let (rewritten, extracted) = sanitize_css(css, &base_url);

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
    fn test_generate_local_filename() {
        let url1 = Url::parse("https://example.com/asset.js?v=2").unwrap();
        let name1 = generate_local_filename(&url1, "bin");
        assert!(name1.starts_with("sub_"));
        assert!(name1.ends_with(".js"));

        let url2 = Url::parse("https://example.com/no-ext").unwrap();
        let name2 = generate_local_filename(&url2, "png");
        assert!(name2.ends_with(".png"));
    }

    #[test]
    fn test_sanitize_javascript_spaces() {
        assert!(sanitize_javascript("eval    (  '1+1'  )").is_err());
        assert!(sanitize_javascript("let evaluator = 1;").is_ok());
        assert!(sanitize_javascript("document.write()").is_err());
    }

    #[test]
    fn test_sanitize_css_dangerous_uris() {
        let base_url = Url::parse("https://example.com/style.css").unwrap();
        let css = "body { background: url('data:image/png;base64,1234'); font: url('javascript:alert(1)'); }";
        let (rewritten, extracted) = sanitize_css(css, &base_url);
        assert!(rewritten.contains("url(\"\")"));
        assert_eq!(extracted.len(), 0);
    }
}
