# Project Workload Division

---



## Lorenzo: HTML Engine & Reporting
*Focuses heavily on the HTML rewriting engine, structural parsing, text manipulation, and compiling the final security reports.*

### 1. HTML Structural Sanitisation (`sanitizer_engine/html.rs`)
- [x] **Strip/Filter Inline Event Handlers**: Strip event attributes (e.g., `onclick`, `onerror`, `onload`, `onmouseover`) from all HTML tags when `strip_event_handlers` is enabled.
- [x] **Validate `<script>` Blocks**:
  - Compare script sources and inline content hashes against the policy `allow_scripts` allow-list.
  - Strip or neutralize any scripts that do not match the allow-list.
- [x] **Sanitize dangerous URIs**: Block or remove `javascript:` and `data:` URIs in element attributes (like `href` or `src`).
- [ ] **Restrict `<iframe>` and `<object>` Origins**:
  - Parse target origins and validate them against the `allow_origins` policy.
  - Strip or rewrite elements pointing to untrusted hosts.
- [ ] **Meta-Refresh Redirects**: Detect and remove `<meta http-equiv="refresh" ...>` tags.

### 2. URL and Link Inspection (`sanitizer_engine/url.rs`)
- [ ] **Broaden Extraction**: Expand URL extraction to cover forms (`<form action="...">`), resource references (`src`), and other embedded tags beyond just anchors (`a[href]`) and links (`link[href]`).
- [ ] **Flexible Action Handling**: Integrate policies (e.g., Warn, Replace, Deny/Remove) for suspicious domains and IDN links during the HTML rewriting loop.

### 5. Reporting Layer
- [ ] **Structured Report Generation**:
  - Implement a structured schema for sanitization action events (rule matched, tag name, offset, original code snippet, replacement).
  - Collect these events thread-safely from the worker threads in the custom thread pool.
  - Emit a machine-readable JSON report for each input in the `output/` directory.

---

## Matteo: Systems, Security, & Network
*Focuses on the recursive sub-resource crawler, low-level security mitigations (SSRF, Bombs, MIME), CLI integration, and memory boundaries.*

### 3. Embedded Resource Handling (Crawler / Fetcher)
- [x] **Recursive Sub-Resource Crawling**:
  - Implement parsing of sub-resources (CSS, JavaScript files, images) from processed HTML documents.
  - Retrieve sub-resources recursively up to `max_depth` (from `policy.resources.max_depth`).
  - Enforce bounds on the total number of sub-resource requests (`max_requests`) and total bytes (`max_bytes`).
- [x] **SSRF & Path Traversal Mitigations**:
  - Validate that fetched sub-resources do not lead to Path Traversal in the local directory tree.
  - Verify that URIs are resolved safely using the SSRF-safe DNS resolver.

### 4. Advanced Security Inspections
- [x] **MIME Sniffing (MIME Confusion)**:
  - Implement magic-number sniffing (content sniffing) on fetched HTTP streams to verify that contents match the declared `Content-Type` header.
- [x] **Active Document Inspection**:
  - Write inspectors to scan downloaded PDFs and other complex documents for embedded executable active content (e.g., Javascript in PDFs).
- [x] **DoS Prevention**:
  - Prevent compression bombs (e.g., gzip/deflate recursion limits) and XML bombs (entity expansion attacks) when sanitizing structured text.
- [x] **Unicode Homograph Attacks**:
  - Complete integration of IDN checks and Unicode normalization controls inside the HTML rewriter.

### 6. CLI & Application Integration (`cli_application`)
- [x] **Non-Zero Exit Codes**:
  - Modify the CLI so it returns a non-zero exit code if the sanitizer blocklist rules result in blocking/denying content outright.
- [x] **Code Cleanup**:
  - Resolve compiler warnings regarding unused variables and functions in `http_client.rs` and `cli.rs`.

---

## Together at the end
### 7. Project Evaluation & Benchmarking
- [ ] **Comprehensive Test Corpus**:
  - *Teammate 1 & 2:* Expand `input_test_files/benign` and `input_test_files/malicious` with extensive sets of real-world HTML snippets, synthetic XSS scripts, obfuscated payloads, and malicious/IDN URLs.
- [ ] **Performance Evaluation Suite**:
  - *Teammate 2 (Lead):* Write test/benchmark scripts to measure throughput (pages/sec), per-input latency, speed-up curves across worker threads, and peak memory footprint.
  - *Teammate 1:* Provide assistance ensuring correctness detection rates and false positive rates are accurately verified against the engine.