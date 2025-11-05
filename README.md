# sensitive_url

[![CI](https://github.com/sigp/sensitive_url/workflows/test-suite/badge.svg)](https://github.com/sigp/sensitive_url/actions)
[![Crates.io](https://img.shields.io/crates/v/sensitive_url.svg)](https://crates.io/crates/sensitive_url)
[![Documentation](https://docs.rs/sensitive_url/badge.svg)](https://docs.rs/sensitive_url)

A Rust library that provides a URL wrapper which automatically redacts sensitive information (credentials, paths, and query parameters) when displaying or debugging URLs.

---

 `SensitiveUrl` stores both the full URL and a redacted version containing only the scheme, host, and port. In order to get the full URL, you must explicitly call `expose_full()`. This helps prevent accidental leakage of credentials in logs.
