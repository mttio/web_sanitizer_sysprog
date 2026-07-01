pub mod css;
pub mod javascript;
pub mod mime;

use crate::errors::SanitizerError;
use url::Url;

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

pub fn scan_pdf_for_active_content(data: &[u8]) -> Result<(), SanitizerError> {
    let mut i = 0;
    while i < data.len() {
        // Check for stream block start
        if i + 6 <= data.len()
            && &data[i..i + 6] == b"stream"
            && (i == 0 || data[i - 1].is_ascii_whitespace() || data[i - 1] == b'>')
        {
            i += 6;
            // Find "endstream"
            let mut found_end = false;
            while i + 9 <= data.len() {
                if &data[i..i + 9] == b"endstream" {
                    i += 9;
                    found_end = true;
                    break;
                }
                i += 1;
            }
            if !found_end {
                break;
            }
            continue;
        }

        // Check for name keys outside stream blocks
        if data[i] == b'/' {
            if i + 3 <= data.len() && &data[i..i + 3] == b"/JS" {
                let next_char = if i + 3 < data.len() { data[i + 3] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    return Err(SanitizerError::ActiveContent(
                        "JavaScript (/JS)".to_string(),
                    ));
                }
            }
            if i + 11 <= data.len() && &data[i..i + 11] == b"/JavaScript" {
                let next_char = if i + 11 < data.len() { data[i + 11] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    return Err(SanitizerError::ActiveContent("JavaScript".to_string()));
                }
            }
            if i + 3 <= data.len() && &data[i..i + 3] == b"/AA" {
                let next_char = if i + 3 < data.len() { data[i + 3] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    return Err(SanitizerError::ActiveContent(
                        "Additional Action (/AA)".to_string(),
                    ));
                }
            }
            if i + 11 <= data.len() && &data[i..i + 11] == b"/OpenAction" {
                let next_char = if i + 11 < data.len() { data[i + 11] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    return Err(SanitizerError::ActiveContent("OpenAction".to_string()));
                }
            }
        }

        i += 1;
    }
    Ok(())
}

fn is_pdf_delimiter(b: u8) -> bool {
    b == 0
        || b.is_ascii_whitespace()
        || b == b'['
        || b == b']'
        || b == b'<'
        || b == b'>'
        || b == b'('
        || b == b')'
        || b == b'{'
        || b == b'}'
        || b == b'/'
        || b == b'%'
}

#[derive(Debug)]
pub struct EntityScanner {
    match_idx: usize,
}

impl EntityScanner {
    pub fn new() -> Self {
        Self { match_idx: 0 }
    }

    /// Process a byte, returns true if b"<!ENTITY" (case-insensitive) is matched
    pub fn feed(&mut self, b: u8) -> bool {
        let target = b"<!ENTITY";
        let target_char = target[self.match_idx];
        if b.eq_ignore_ascii_case(&target_char) {
            self.match_idx += 1;
            if self.match_idx == target.len() {
                return true;
            }
        } else {
            if b == b'<' {
                self.match_idx = 1;
            } else {
                self.match_idx = 0;
            }
        }
        false
    }

    /// Feeds a chunk of bytes, returns true if b"<!ENTITY" is found
    pub fn feed_chunk(&mut self, chunk: &[u8]) -> bool {
        for &b in chunk {
            if self.feed(b) {
                return true;
            }
        }
        false
    }
}

//========================= TESTS ==============================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        log::{LogLevel, NullLogger},
        rules::RuleWithReplace,
    };

    #[test]
    fn test_entity_scanner() {
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"<html><body>"));
        assert!(!scanner.feed_chunk(b"<!DOCTYPE html>"));
        assert!(scanner.feed_chunk(b"<!ENTITY x 'y'>"));

        // Case insensitivity
        let mut scanner = EntityScanner::new();
        assert!(scanner.feed_chunk(b"<!entity lol 'lol'>"));

        // Boundary split
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"abc<!ENT"));
        assert!(scanner.feed_chunk(b"ITY def"));

        // Overlapping match
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"<!<!ENT"));
        assert!(scanner.feed_chunk(b"ITY"));

        // Another overlap match
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"<!EN<!ENT"));
        assert!(scanner.feed_chunk(b"ITY"));
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
    fn test_generate_local_filename() {
        let url1 = Url::parse("https://example.com/asset.js?v=2").unwrap();
        let name1 = generate_local_filename(&url1, "bin");
        assert!(name1.starts_with("sub_"));
        assert!(name1.ends_with(".js"));

        let url2 = Url::parse("https://example.com/no-ext").unwrap();
        let name2 = generate_local_filename(&url2, "png");
        assert!(name2.ends_with(".png"));

        // Path traversal mitigation check
        let url3 = Url::parse("https://example.com/../../../etc/passwd").unwrap();
        let name3 = generate_local_filename(&url3, "txt");
        assert!(!name3.contains(".."));
        assert!(!name3.contains('/'));
        assert!(!name3.contains('\\'));
    }

    #[test]
    fn test_scan_pdf_for_active_content() {
        // Clean PDF
        let clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
        assert!(scan_pdf_for_active_content(clean_pdf).is_ok());

        // Malicious PDF with /JS key
        let malicious_js = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /JS (app.alert(1)) >>\nendobj\n";
        assert!(scan_pdf_for_active_content(malicious_js).is_err());

        // Malicious PDF with /OpenAction key
        let malicious_open = b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R >>\nendobj\n";
        assert!(scan_pdf_for_active_content(malicious_open).is_err());

        // PDF containing /JS inside a binary stream block (should pass)
        let stream_pdf =
            b"%PDF-1.4\n1 0 obj\n<< /Length 20 >>\nstream\nrandom/JSdata\nendstream\nendobj\n";
        assert!(scan_pdf_for_active_content(stream_pdf).is_ok());

        // Boundary checks and fake stream check
        let fake_stream = b"randomstream/JS";
        assert!(scan_pdf_for_active_content(fake_stream).is_err());

        // Files on disk
        let clean_file_data = std::fs::read("input_test_files/benign/clean_doc.pdf").unwrap();
        assert!(scan_pdf_for_active_content(&clean_file_data).is_ok());

        let malicious_file_data =
            std::fs::read("input_test_files/malicious/pdf_js_bomb.pdf").unwrap();
        assert!(scan_pdf_for_active_content(&malicious_file_data).is_err());

        // CSS and JS disk file validation checks
        let css_file_data =
            std::fs::read_to_string("input_test_files/malicious/dangerous_styles.css").unwrap();
        let (clean_css, _) = crate::resources::css::sanitize(
            &css_file_data,
            &Url::parse("https://localhost").unwrap(),
            &NullLogger,
            &RuleWithReplace::with_default(LogLevel::Warn),
        )
        .unwrap();
        assert!(clean_css.contains("url(\"\")"));

        let js_file_data =
            std::fs::read_to_string("input_test_files/malicious/dangerous_script.js").unwrap();
        assert!(javascript::sanitize(&js_file_data).is_err());
    }
}
