// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A string newtype whose value never appears in `Debug` or `Display` output.

pub use crate::mxc_common::models::Redacted;

#[cfg(test)]
mod tests {
    use super::Redacted;

    #[test]
    fn debug_and_display_both_hide_the_value() {
        let s = Redacted::new("SUPER_SECRET_VALUE");
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(format!("{s}"), "<redacted>");
        assert!(!format!("{s:?} {s}").contains("SUPER_SECRET_VALUE"));
    }

    #[test]
    fn expose_returns_the_real_value() {
        assert_eq!(Redacted::new("abc").expose(), "abc");
    }

    #[test]
    fn deserializes_transparently_from_a_json_string() {
        let s: Redacted = serde_json::from_str("\"tok\"").unwrap();
        assert_eq!(s.expose(), "tok");
    }
}
