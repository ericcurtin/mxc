// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The `w365` sandbox id: `w365:{poolId}:{computerId}`, both GUIDs.

use std::fmt;

use crate::mxc_common::id::parse_sandbox_id_prefix;
use crate::mxc_common::mxc_error::MxcError;

/// Backend id prefix. Must equal `W365AgentsRunner::ID_PREFIX`.
pub const ID_PREFIX: &str = "w365";

/// A parsed `w365:{poolId}:{computerId}` sandbox id.
///
/// `computerId == sessionId` on the pooled-VM path, so the single GUID serves
/// both ARI routing and SM's `DELETE /api/sessions/{id}`.
///
/// Fields are private: [`parse`](Self::parse) is the only constructor, so a
/// value of this type always satisfies the GUID invariant that keeps the ARI
/// request line and the `x-ms-computerId` header injection-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W365SandboxId {
    pool_id: String,
    computer_id: String,
}

/// Canonical 8-4-4-4-12 hex GUID check. Restricting both segments to GUIDs
/// makes CRLF, space, `/` and `..` unrepresentable, which is what keeps the
/// ARI request line and the `x-ms-computerId` header injection-free.
///
/// Deliberately hand-rolled rather than delegating to `uuid::Uuid::parse_str`:
/// that parser also accepts the simple (undashed), braced `{...}` and
/// `urn:uuid:` forms. The URN form contains colons, which would split into the
/// wrong number of id segments, and the braced form admits `{`/`}` into a URL
/// path — so the permissive parser would weaken exactly the guard this check
/// exists to provide. `uuid` is also not a dependency of this crate.
pub(crate) fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

impl W365SandboxId {
    /// Mint the wire form after validating both segments.
    ///
    /// This is the only supported way to build an id. It is fallible on purpose:
    /// an infallible formatter let `provision` mint an id that [`parse`](Self::parse)
    /// then rejected, which stranded a checked-out (billing) VM that `stop` and
    /// `deprovision` could no longer release, and allowed a non-GUID pool id to
    /// splice into the control-plane HTTP request line.
    ///
    /// # Errors
    /// Returns `malformed_id` if either segment is not a canonical 8-4-4-4-12 GUID.
    pub fn mint(pool_id: &str, computer_id: &str) -> Result<String, MxcError> {
        if !is_guid(pool_id) || !is_guid(computer_id) {
            return Err(MxcError::malformed_id(format!(
                "cannot mint a w365 sandbox id from non-GUID segments: \
                 pool '{pool_id}', computer '{computer_id}'"
            )));
        }
        Ok(Self::format_unchecked(pool_id, computer_id))
    }

    /// Format without validating. Private: every caller must go through
    /// [`mint`](Self::mint) so the GUID invariant cannot be bypassed.
    fn format_unchecked(pool_id: &str, computer_id: &str) -> String {
        format!("{ID_PREFIX}:{pool_id}:{computer_id}")
    }

    /// Parse and validate. Every non-provision phase starts here.
    ///
    /// # Errors
    /// Returns `malformed_id` if the string is not exactly three `:`-separated
    /// segments, if the prefix is not `w365`, or if either body segment is not
    /// a canonical 8-4-4-4-12 GUID.
    pub fn parse(sandbox_id: &str) -> Result<Self, MxcError> {
        // Reuse the framework's prefix parser so a missing `<prefix>:` reports
        // the same `malformed_id` message the dispatcher itself would produce.
        let prefix = parse_sandbox_id_prefix(sandbox_id)?;
        if prefix != ID_PREFIX {
            return Err(MxcError::malformed_id(format!(
                "not a w365 sandbox id: '{sandbox_id}'"
            )));
        }
        let body = sandbox_id.get(prefix.len() + 1..).unwrap_or_default();
        let (pool_id, computer_id) = body.split_once(':').ok_or_else(|| {
            MxcError::malformed_id(format!(
                "w365 id must have exactly 3 ':' segments: '{sandbox_id}'"
            ))
        })?;
        if computer_id.contains(':') {
            return Err(MxcError::malformed_id(format!(
                "w365 id must have exactly 3 ':' segments: '{sandbox_id}'"
            )));
        }
        if !is_guid(pool_id) || !is_guid(computer_id) {
            return Err(MxcError::malformed_id(format!(
                "w365 id segments must both be GUIDs: '{sandbox_id}'"
            )));
        }
        Ok(Self {
            pool_id: pool_id.to_string(),
            computer_id: computer_id.to_string(),
        })
    }

    /// The pool GUID (first id segment).
    pub fn pool_id(&self) -> &str {
        &self.pool_id
    }

    /// The computer GUID (second id segment); equals `sessionId` on the
    /// pooled-VM path.
    pub fn computer_id(&self) -> &str {
        &self.computer_id
    }

    /// Pool-scoped DataPlane host. The host is never stored in the id — it is
    /// rebuilt from ambient config every time.
    pub fn dp_host(&self, dp_suffix: &str) -> String {
        format!("{}.{}", self.pool_id, dp_suffix)
    }
}

impl fmt::Display for W365SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ID_PREFIX}:{}:{}", self.pool_id, self.computer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::W365SandboxId;

    const POOL: &str = "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9";
    const COMPUTER: &str = "538fdbe2-1f9a-40c7-b8dd-f2391d55a24a";

    #[test]
    fn formats_three_segments_with_colons() {
        // The prefix is asserted as a literal, not derived from `ID_PREFIX`, so
        // renaming the const cannot silently move both sides of the assertion.
        assert_eq!(
            W365SandboxId::mint(POOL, COMPUTER).unwrap(),
            format!("w365:{POOL}:{COMPUTER}")
        );
    }

    #[test]
    fn minting_rejects_a_non_guid_segment() {
        // An infallible formatter previously let `provision` mint an id that
        // `parse` rejects, stranding a checked-out VM that could never be
        // released, and let a non-GUID pool id reach the HTTP request line.
        for (pool, computer) in [
            ("not-a-guid", COMPUTER),
            (POOL, "not-a-guid"),
            ("a\r\nX-Injected: 1", COMPUTER),
            ("../../etc", COMPUTER),
        ] {
            let err = W365SandboxId::mint(pool, computer).unwrap_err();
            assert_eq!(err.code.as_str(), "malformed_id", "pool={pool}");
        }
    }

    #[test]
    fn every_minted_id_is_accepted_by_the_parser() {
        // The invariant the type exists to guarantee: mint and parse agree.
        let minted = W365SandboxId::mint(POOL, COMPUTER).unwrap();
        assert!(W365SandboxId::parse(&minted).is_ok());
    }

    #[test]
    fn parses_a_well_formed_id() {
        let id = W365SandboxId::parse(&format!("w365:{POOL}:{COMPUTER}")).unwrap();
        assert_eq!(id.pool_id(), POOL);
        assert_eq!(id.computer_id(), COMPUTER);
    }

    #[test]
    fn round_trips() {
        let s = W365SandboxId::mint(POOL, COMPUTER).unwrap();
        assert_eq!(W365SandboxId::parse(&s).unwrap().to_string(), s);
    }

    #[test]
    fn rejects_the_legacy_dot_form() {
        // The two-segment dot form is unsupported.
        let err = W365SandboxId::parse(&format!("w365:{POOL}.{COMPUTER}")).unwrap_err();
        assert_eq!(err.code.as_str(), "malformed_id");
    }

    #[test]
    fn rejects_wrong_prefix_segment_count_and_non_guids() {
        for bad in [
            format!("iso:{POOL}:{COMPUTER}"),        // wrong prefix
            format!("w365:{POOL}"),                  // too few segments
            format!("w365:{POOL}:{COMPUTER}:extra"), // too many segments
            format!("w365:{POOL}:not-a-guid"),       // non-GUID
            format!("w365::{COMPUTER}"),             // empty segment
        ] {
            assert_eq!(
                W365SandboxId::parse(&bad).unwrap_err().code.as_str(),
                "malformed_id",
                "expected malformed_id for {bad}"
            );
        }
    }

    #[test]
    fn guid_validation_blocks_injection_payloads() {
        // GUID-only segments make CRLF / space / slash / traversal unrepresentable,
        // which is what protects the ARI request line and the x-ms-computerId header.
        for bad in [
            "w365:a\r\nHost: evil:b",
            "w365:../../etc:b",
            "w365:a b:c",
            "w365:a/b:c",
        ] {
            assert_eq!(
                W365SandboxId::parse(bad).unwrap_err().code.as_str(),
                "malformed_id",
                "expected malformed_id for {bad}"
            );
        }
    }

    #[test]
    fn builds_the_pool_scoped_dataplane_host() {
        let id = W365SandboxId::parse(&format!("w365:{POOL}:{COMPUTER}")).unwrap();
        assert_eq!(
            id.dp_host("westus3.remotinginterface.regional.example.net"),
            format!("{POOL}.westus3.remotinginterface.regional.example.net")
        );
    }
}
