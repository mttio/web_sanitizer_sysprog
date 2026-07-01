use std::fmt::Display;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum KnownMime {
    Png,
    Jpeg,
    Gif,
    Webp,
    Pdf,
}

impl KnownMime {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "image/png" => Self::Png,
            "image/jpeg" => Self::Jpeg,
            "image/gif" => Self::Gif,
            "image/webp" => Self::Webp,
            "application/pdf" => Self::Pdf,
            _ => return None,
        })
    }
}

impl Display for KnownMime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
            Self::Pdf => "application/pdf",
        })
    }
}

/// Sniffs the mime type of a byte buffer using [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures).
///
/// # Inputs
/// * `data` - A slice of bytes representing the file content.
///
/// # Returns
/// * `Option<&'static str>` - `Some(...)` if a signature is matched, otherwise `None`.
pub fn sniff(data: &[u8]) -> Option<KnownMime> {
    if data.starts_with(b"\x89PNG\x0D\x0A\x1A\x0A") {
        Some(KnownMime::Png)
    } else if data.starts_with(b"\xFF\xD8") {
        Some(KnownMime::Jpeg)
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some(KnownMime::Gif)
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some(KnownMime::Webp)
    } else if data.starts_with(b"%PDF") {
        Some(KnownMime::Pdf)
    } else {
        None
    }
}

/// Extracts the MIME type from a `Content-Type` header and normalizes it
pub fn clean(content_type: &str) -> String {
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
/// * `Result<(), MimeError>` - `Ok(())` if the content matches or if there is no mismatch, otherwise a `Err(MimeError)` detailing the MIME confusion mismatch.
pub fn validate(declared: Option<&str>, sniffed: Option<KnownMime>) -> bool {
    if let Some(declared) = declared.and_then(KnownMime::parse) {
        if sniffed != Some(declared) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff() {
        assert_eq!(
            sniff(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Some(KnownMime::Png)
        );
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]), Some(KnownMime::Jpeg));
        assert_eq!(sniff(b"GIF89a..."), Some(KnownMime::Gif));
        assert_eq!(sniff(b"%PDF-1.4"), Some(KnownMime::Pdf));
        assert_eq!(sniff(b"body {}"), None);
    }

    #[test]
    fn test_validate() {
        assert!(validate(
            Some("image/png"),
            sniff(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        ));
        assert!(validate(Some("image/jpeg"), sniff(&[0xFF, 0xD8, 00, 00])));
        assert!(!validate(Some("image/png"), sniff(&[0xFF, 0xD8])));
    }
}
