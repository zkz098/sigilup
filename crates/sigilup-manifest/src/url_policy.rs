use url::Url;

use crate::error::{Error, Result};

/// Configurable defense-in-depth URL policy for update download locations.
///
/// Even though every manifest is cryptographically signed, validating asset URLs
/// before downloading prevents a compromised or misconfigured manifest from
/// redirecting clients to insecure `http://`, arbitrary hosts, or path-traversal
/// filenames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlPolicy {
    /// Require `https://` scheme (recommended `true` in production).
    pub require_https: bool,
    /// Optional list of allowed URL prefixes (e.g. `https://github.com/org/repo/releases/download/`).
    pub allowed_prefixes: Vec<String>,
    /// Optional list of allowed hostnames (exact match, case-insensitive).
    pub allowed_hosts: Vec<String>,
    /// Maximum allowed length for the final path segment (filename).
    pub max_filename_len: usize,
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self {
            require_https: true,
            allowed_prefixes: Vec::new(),
            allowed_hosts: Vec::new(),
            max_filename_len: 160,
        }
    }
}

impl UrlPolicy {
    /// Build a policy that requires HTTPS and restricts URLs to one or more prefixes.
    #[must_use]
    pub fn with_prefixes(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed_prefixes: prefixes.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Build a permissive HTTPS-only policy (useful when custom CDNs/mirrors are allowed).
    #[must_use]
    pub fn https_only() -> Self {
        Self::default()
    }

    /// Validate an artifact URL against this policy.
    pub fn validate(&self, raw_url: &str) -> Result<()> {
        let parsed = Url::parse(raw_url).map_err(|_| Error::UrlRejected {
            url: raw_url.to_string(),
            reason: "invalid URL syntax",
        })?;

        if self.require_https && parsed.scheme() != "https" {
            return Err(Error::UrlRejected {
                url: raw_url.to_string(),
                reason: "https scheme is required",
            });
        }
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(Error::UrlRejected {
                url: raw_url.to_string(),
                reason: "unsupported URL scheme",
            });
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(Error::UrlRejected {
                url: raw_url.to_string(),
                reason: "userinfo in URL is forbidden",
            });
        }

        if !self.allowed_hosts.is_empty() {
            let host = parsed.host_str().unwrap_or_default();
            let host_ok = self
                .allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host));
            if !host_ok {
                return Err(Error::UrlRejected {
                    url: raw_url.to_string(),
                    reason: "host not in allowlist",
                });
            }
        }

        if !self.allowed_prefixes.is_empty()
            && !self
                .allowed_prefixes
                .iter()
                .any(|prefix| raw_url.starts_with(prefix))
        {
            return Err(Error::UrlRejected {
                url: raw_url.to_string(),
                reason: "URL does not match any allowed prefix",
            });
        }

        let file_name = parsed
            .path_segments()
            .and_then(|mut segs| segs.next_back())
            .unwrap_or_default();
        if file_name.is_empty()
            || file_name.len() > self.max_filename_len
            || file_name == "."
            || file_name == ".."
            || !file_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
        {
            return Err(Error::UrlRejected {
                url: raw_url.to_string(),
                reason: "URL must end in a safe plain filename",
            });
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn enforces_https_prefixes_and_safe_filenames() {
        let policy = UrlPolicy::with_prefixes(["https://github.com/acme/app/releases/download/"]);
        assert!(
            policy
                .validate("https://github.com/acme/app/releases/download/v1.0.0/app-1.0.0.tar.gz")
                .is_ok()
        );
        assert!(
            policy
                .validate("http://github.com/acme/app/releases/download/v1.0.0/app.tar.gz")
                .is_err()
        );
        assert!(
            policy
                .validate("https://evil.example/acme/app/releases/download/v1.0.0/app.tar.gz")
                .is_err()
        );
        assert!(
            policy
                .validate("https://github.com/acme/app/releases/download/v1.0.0/..")
                .is_err()
        );
        assert!(
            policy
                .validate("https://user:pass@github.com/acme/app/releases/download/v1.0.0/a.zip")
                .is_err()
        );
    }
}
