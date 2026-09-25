//! CoRE Resource Discovery [RFC 6690](https://tools.ietf.org/html/rfc6690).
//!
//! Resources are described in the CoRE Link Format and served by a server at
//! the well-known URI `/.well-known/core`. Encoding and decoding of the link
//! format is delegated to [`coap_lite::link_format`].

use coap_lite::link_format::{ErrorLinkFormat, LinkFormatParser, LinkFormatWrite};

pub use coap_lite::link_format::{
    LINK_ATTR_CONTENT_FORMAT, LINK_ATTR_INTERFACE_DESCRIPTION, LINK_ATTR_MAXIMUM_SIZE_ESTIMATE,
    LINK_ATTR_OBSERVABLE, LINK_ATTR_RESOURCE_TYPE, LINK_ATTR_TITLE,
};

/// The well-known URI path used for resource discovery, without a leading slash.
pub const WELL_KNOWN_CORE: &str = ".well-known/core";

/// A single link of a CoRE Link Format document, e.g. `</sensors/temp>;rt="temperature";obs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    /// The target URI of the link (e.g. `/sensors/temp`).
    pub href: String,
    /// The target attributes of the link as (key, value) pairs.
    ///
    /// Attributes without a value (e.g. `obs`) have an empty string as value.
    pub attributes: Vec<(String, String)>,
}

impl Link {
    /// Creates a new link with the given target URI and no attributes.
    pub fn new(href: impl ToString) -> Self {
        Self {
            href: href.to_string(),
            attributes: Vec::new(),
        }
    }

    /// Adds an attribute to this link.
    pub fn attribute(mut self, key: impl ToString, value: impl ToString) -> Self {
        self.attributes.push((key.to_string(), value.to_string()));
        self
    }

    /// Returns the value of the first attribute with the given key, if it exists.
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Checks if this link matches the given query filter as described in
    /// [RFC 6690 Section 4.1](https://tools.ietf.org/html/rfc6690#section-4.1).
    ///
    /// The filter has the form `name=value`, where `name` is either `href` or an
    /// attribute key. A trailing `*` in `value` matches any value with that prefix.
    /// Space-separated attribute values (e.g. `rt="a b"`) match if any of the values match.
    /// A filter without `=` matches if the attribute is present.
    pub fn matches_query(&self, query: &str) -> bool {
        let (name, pattern) = match query.split_once('=') {
            Some((name, pattern)) => (name, pattern),
            None => return self.get_attribute(query).is_some(),
        };

        let value_matches = |value: &str| match pattern.strip_suffix('*') {
            Some(prefix) => value.starts_with(prefix),
            None => value == pattern,
        };

        if name == "href" {
            return value_matches(&self.href);
        }
        self.attributes
            .iter()
            .filter(|(k, _)| k == name)
            .any(|(_, v)| value_matches(v) || v.split_ascii_whitespace().any(value_matches))
    }
}

/// Parses a CoRE Link Format document into a list of links.
pub fn parse_link_format(payload: &str) -> Result<Vec<Link>, ErrorLinkFormat> {
    LinkFormatParser::new(payload)
        .map(|link| {
            let (href, attributes) = link?;
            Ok(Link {
                href: href.to_string(),
                attributes: attributes
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
            })
        })
        .collect()
}

/// Writes a list of links as a CoRE Link Format document.
///
/// Attributes without a value (e.g. `obs`) are written after the attributes with a value.
pub fn write_link_format(links: &[Link]) -> String {
    links
        .iter()
        .map(|link| {
            let mut buffer = String::new();
            let mut write = LinkFormatWrite::new(&mut buffer);
            let mut attrs = write.link(&link.href);
            for (key, value) in link.attributes.iter().filter(|(_, v)| !v.is_empty()) {
                attrs = attrs.attr(key, value);
            }
            // Writing into a `String` cannot fail
            let _ = attrs.finish();
            // `LinkFormatWrite` has no support for attributes without a value
            for (key, _) in link.attributes.iter().filter(|(_, v)| v.is_empty()) {
                buffer.push(';');
                buffer.push_str(key);
            }
            buffer
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_link_format() {
        let payload = r#"</sensors/temp>;rt="temperature-c";if="sensor";obs,</sensors/light>;ct=0"#;
        let links = parse_link_format(payload).unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].href, "/sensors/temp");
        assert_eq!(links[0].get_attribute("rt"), Some("temperature-c"));
        assert_eq!(links[0].get_attribute("if"), Some("sensor"));
        assert_eq!(links[0].get_attribute("obs"), Some(""));
        assert_eq!(links[1].href, "/sensors/light");
        assert_eq!(links[1].get_attribute("ct"), Some("0"));
        assert_eq!(links[1].get_attribute("rt"), None);
    }

    #[test]
    fn test_parse_invalid_link_format() {
        assert!(parse_link_format("sensors/temp").is_err());
    }

    #[test]
    fn test_write_link_format() {
        let links = vec![
            Link::new("/sensors/temp")
                .attribute(LINK_ATTR_RESOURCE_TYPE, "temperature-c")
                .attribute(LINK_ATTR_OBSERVABLE, ""),
            Link::new("/sensors/light").attribute(LINK_ATTR_CONTENT_FORMAT, 0),
        ];
        let payload = write_link_format(&links);
        assert_eq!(
            payload,
            r#"</sensors/temp>;rt="temperature-c";obs,</sensors/light>;ct=0"#
        );
        assert_eq!(parse_link_format(&payload).unwrap(), links);
    }

    #[test]
    fn test_matches_query() {
        let link = Link::new("/sensors/temp")
            .attribute(LINK_ATTR_RESOURCE_TYPE, "temperature-c outdoor")
            .attribute(LINK_ATTR_OBSERVABLE, "");
        assert!(link.matches_query("href=/sensors/temp"));
        assert!(link.matches_query("href=/sensors*"));
        assert!(!link.matches_query("href=/actuators*"));
        assert!(link.matches_query("rt=temperature-c"));
        assert!(link.matches_query("rt=outdoor"));
        assert!(link.matches_query("rt=temp*"));
        assert!(link.matches_query("rt=temperature-c outdoor"));
        assert!(!link.matches_query("rt=light"));
        assert!(!link.matches_query("if=sensor"));
        assert!(link.matches_query("obs"));
        assert!(!link.matches_query("ct"));
    }
}
