// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use rustgenhash::rgh::mac::executor::{consume_bytes, digest_to_hex};
use rustgenhash::rgh::mac::registry;

#[test]
fn hmac_sha256_matches_fixture_vector() {
	let key = b"supersecretkey";
	let (executor, metadata) =
		registry::create_executor("hmac-sha256", key)
			.expect("executor");
	assert!(!metadata.is_legacy());
	let digest = consume_bytes(b"alpha", executor);
	assert_eq!(
		digest_to_hex(&digest),
		"36bb6808df1ed0834db71b4d5c671ce1ef3beed1d90ed57ea5362c8a023c9488"
	);
}

#[test]
fn hmac_sha1_reports_legacy_and_computes_digest() {
	let key = b"supersecretkey";
	let (executor, metadata) =
		registry::create_executor("hmac-sha1", key)
			.expect("executor");
	assert!(metadata.is_legacy());
	let digest = consume_bytes(b"alpha", executor);
	assert_eq!(
		digest_to_hex(&digest),
		"23ea5cec55f20f94385951e634a461e26c2554f3"
	);
}
