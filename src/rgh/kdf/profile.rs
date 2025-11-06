// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: profile.rs
// Author: rustgenhash maintainers

//! Compliance presets for PBKDF2 and scrypt password hashing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pbkdf2Profile {
	pub id: &'static str,
	pub rounds: u32,
	pub salt_len: usize,
	pub output_len: usize,
	pub description: &'static str,
	pub reference: &'static str,
}

pub const PBKDF2_PROFILES: &[Pbkdf2Profile] = &[
	Pbkdf2Profile {
		id: "nist-sp800-132-2023",
		rounds: 310_000,
		salt_len: 16,
		output_len: 32,
		description: "NIST SP 800-132 draft (2023) baseline for general-purpose applications",
		reference: "NIST SP 800-132 (Draft 2023)",
	},
	Pbkdf2Profile {
		id: "pci-dss-2024",
		rounds: 600_000,
		salt_len: 16,
		output_len: 32,
		description: "PCI DSS v4 recommended floor for stored credential verifiers",
		reference: "PCI DSS v4 Password Requirements",
	},
];

pub fn get_pbkdf2_profile(
	id: &str,
) -> Option<&'static Pbkdf2Profile> {
	PBKDF2_PROFILES
		.iter()
		.find(|profile| profile.id.eq_ignore_ascii_case(id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptProfile {
	pub id: &'static str,
	pub log_n: u8,
	pub r: u32,
	pub p: u32,
	pub salt_len: usize,
	pub output_len: usize,
	pub description: &'static str,
	pub reference: &'static str,
}

pub const SCRYPT_PROFILES: &[ScryptProfile] = &[
	ScryptProfile {
		id: "owasp-2024",
		log_n: 18,
		r: 8,
		p: 1,
		salt_len: 16,
		output_len: 32,
		description:
			"OWASP Password Storage Cheat Sheet (2024) recommendation",
		reference: "OWASP Password Storage Cheat Sheet",
	},
	ScryptProfile {
		id: "nist-low",
		log_n: 14,
		r: 8,
		p: 1,
		salt_len: 16,
		output_len: 32,
		description:
			"NIST SP 800-132 lower-bound interactive workload",
		reference: "NIST SP 800-132",
	},
	ScryptProfile {
		id: "nist-high",
		log_n: 20,
		r: 8,
		p: 2,
		salt_len: 16,
		output_len: 32,
		description: "NIST SP 800-132 strong interactive workload",
		reference: "NIST SP 800-132",
	},
];

pub fn get_scrypt_profile(
	id: &str,
) -> Option<&'static ScryptProfile> {
	SCRYPT_PROFILES
		.iter()
		.find(|profile| profile.id.eq_ignore_ascii_case(id))
}

pub fn pbkdf2_profile_ids() -> Vec<&'static str> {
	PBKDF2_PROFILES.iter().map(|p| p.id).collect()
}

pub fn scrypt_profile_ids() -> Vec<&'static str> {
	SCRYPT_PROFILES.iter().map(|p| p.id).collect()
}
