// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use std::sync::OnceLock;
use crate::rgh::weak::all_metadata;

pub const HELP_TEMPLATE: &str = "{before-help}{name} {version}
Written by {author-with-newline}{about-with-newline}
Primary command families:
  rgh digest <mode>   Hash strings/files/stdin (e.g. rgh digest string -a sha256 'text')
  rgh kdf <algorithm> Derive passwords with JSON metadata (e.g. rgh kdf argon2 --password-stdin)
  rgh mac --alg <id>  Generate keyed MACs (e.g. rgh mac --alg hmac-sha256 --key key.bin --input 'text')
{usage-heading} {usage}

{all-args}{after-help}
";

pub static DIGEST_ALGORITHM_HELP: OnceLock<String> = OnceLock::new();

pub fn digest_algorithm_help_text() -> &'static str {
	DIGEST_ALGORITHM_HELP.get_or_init(|| {
		let display_names = all_metadata()
			.iter()
			.map(|meta| meta.display_name)
			.collect::<Vec<_>>()
			.join(", ");
		let identifiers = all_metadata()
			.iter()
			.map(|meta| meta.algorithm_id)
			.collect::<Vec<_>>()
			.join(", ");
		format!(
			"Digest algorithm identifier (e.g., sha256). ⚠ Weak: {display_names} ({identifiers}). See README section \"Weak Digest Algorithms\" for safer alternatives.",
		)
	})
	.as_str()
}

pub const WEAK_PROMPT_OPTIONS: [&str; 2] =
	["Choose safer algorithm", "Continue anyway"];
pub const WEAK_PROMPT_DEFAULT_INDEX: usize = 0;

/// Identifiers accepted by `rgh mac --alg`; `hmac-sha1` remains for legacy
/// compatibility only and is flagged per NIST SP 800-131A Rev. 2 guidance.
pub const MAC_ALGORITHMS: [&str; 12] = [
	"hmac-sha1",
	"hmac-sha256",
	"hmac-sha512",
	"hmac-sha3-256",
	"hmac-sha3-512",
	"kmac128",
	"kmac256",
	"cmac-aes128",
	"cmac-aes192",
	"cmac-aes256",
	"poly1305",
	"blake3-keyed",
];

pub const MAC_ALGORITHM_HELP: &str = "MAC algorithm identifier. ⚠ Legacy: hmac-sha1 (see NIST SP 800-131A Rev.2 §3). AES-CMAC keys must be 16/24/32 bytes respectively; Poly1305 keys must be 32 bytes and warn on reuse. Recommended options: hmac-sha2, hmac-sha3, kmac128/256, cmac-aes*, poly1305, blake3-keyed.";

pub const MAC_ALGORITHM_MATRIX_HELP: &str = "Algorithms:\n  hmac-sha1          ⚠ Legacy – retain only for backward compatibility (NIST SP 800-131A Rev.2 §3)\n  hmac-sha256/512    SHA-2 based HMAC as per RFC 2104\n  hmac-sha3-256/512  SHA-3 based HMAC (FIPS 202)\n  kmac128/256        SP 800-185 KMAC (cSHAKE-based)\n  cmac-aes128/192/256 AES CMAC per NIST SP 800-38B (keys 16/24/32 bytes)\n  poly1305           One-time MAC per RFC 8439 §2.5 (32-byte key; reuse warning)\n  blake3-keyed       BLAKE3 keyed mode (§5)\n\nReferences:\n  https://doi.org/10.6028/NIST.SP.800-131Ar2\n  https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf\n  https://doi.org/10.6028/NIST.SP.800-185\n  https://doi.org/10.6028/NIST.SP.800-38B\n  https://www.rfc-editor.org/rfc/rfc8439\n  https://github.com/BLAKE3-team/BLAKE3-specs";
