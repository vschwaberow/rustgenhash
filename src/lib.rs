// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: analyze.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

pub mod rgh {
	pub mod analyze;
	pub mod app;
	pub mod benchmark;
	pub mod hash;
	pub mod hhhash;
	pub mod random;
}

#[cfg(test)]
mod tests {
	use crate::rgh::hash::RHash;

	use super::*;
	use password_hash::{PasswordHasher, PasswordVerifier};
	use rgh::analyze::HashAnalyzer;

	#[test]
	fn test_analyze_argon2() {
		let hash = HashAnalyzer::from_string(
			"$argon2id$v=19$m=4096,t=3,p=1$aN8J49cAi1VFS560uw5vsw$wskiYeq9UkHSgzpulEDHauTHOJ9Nz2dOf+0OcfAULU0",
		);
		assert!(hash.is_argon2());
	}

	#[test]
	fn test_analyze_ascon() {
		let hash = HashAnalyzer::from_string(
			"1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43",
		);
		assert!(hash.is_ascon());
	}

	#[test]
	fn test_balloon() {
		let hash = HashAnalyzer::from_string(
			"$balloon$1$m=65536,t=2,p=1$e3b0c44298fc1c149afbf4c8996fb924"
		);
		assert!(hash.is_balloon());
	}

	#[test]
	fn test_analyze_md4() {
		let hash = HashAnalyzer::from_string(
			"31d6cfe0d16ae931b73c59d7e0c089c0",
		);
		assert!(hash.is_md4());
	}

	#[test]
	fn test_analyze_md5() {
		let hash = HashAnalyzer::from_string(
			"d41d8cd98f00b204e9800998ecf8427e",
		);
		assert!(hash.is_md5());
	}

	#[test]
	fn test_analyze_groestl() {
		let hash = HashAnalyzer::from_string(
			"5fc07d8c8d9d54bf2733c8f3d4d2aa8b3f1603970001fc987f1cdecde18f520f",
		);
		assert!(hash.is_groestl());
	}

	#[test]
	fn test_analyze_sha1() {
		let hash = HashAnalyzer::from_string(
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		);
		assert!(hash.is_sha1());
	}

	#[test]
	fn test_analyze_streebog256() {
		let hash = HashAnalyzer::from_string(
			"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		);
		assert!(hash.is_streebog256());
	}

	#[test]
	fn test_analyze_streebog512() {
		let hash = HashAnalyzer::from_string(
			"1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43",
		);
		assert!(hash.is_streebog512());
	}

	#[test]
	fn test_analyze_sha256() {
		let hash = HashAnalyzer::from_string(
			"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		);
		assert!(hash.is_sha256());
	}

	#[test]
	fn test_analyze_sha512() {
		let hash = HashAnalyzer::from_string(
			"1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43",
		);
		assert!(hash.is_sha512());
	}

	#[test]
	fn test_analyze_tiger() {
		let hash = HashAnalyzer::from_string(
			"3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
		);
		assert!(hash.is_tiger());
	}

	#[test]
	fn test_argon2() {
		use argon2::Argon2;
		use password_hash::SaltString;
		use rand::rngs::OsRng;
		let password = "password";
		let salt = SaltString::generate(&mut OsRng);
		let argon2 = Argon2::default();
		let phash = argon2.hash_password(password.as_bytes(), &salt);

		let phash = match phash {
			Ok(p) => p,
			Err(e) => {
				eprintln!("Error: {}", e);
				std::process::exit(1);
			}
		};
		assert!(Argon2::default()
			.verify_password(password.as_bytes(), &phash)
			.is_ok());
	}

	#[test]
	fn test_belthash() {
		use hex_literal::hex;
		let mut hasher = RHash::new("BELTHASH");
		let pass = "hello world".to_string();
		let result = hasher.process_string(pass.as_bytes());
		assert_eq!(result, hex!("afb175816416fbadad4629ecbd78e1887789881f2d2e5b80c22a746b7ac7ba88"));
	}

	#[test]
	fn test_fsb() {
		use hex_literal::hex;
		let mut hasher = RHash::new("FSB160");
		let pass = "volker".to_string();
		let result = hasher.process_string(pass.as_bytes());
		assert_eq!(
			result,
			hex!("6c241935a6599531bfa96826052c7b0675747606")
		);
		let mut hasher = RHash::new("FSB224");
		let pass = "volker".to_string();
		let result = hasher.process_string(pass.as_bytes());
		assert_eq!(result, hex!("4da25700e1c56889418afb4bd32c28b880dd54ede24fd13406f5245d"));
		let mut hasher = RHash::new("FSB256");
		let pass = "volker".to_string();
		let result = hasher.process_string(pass.as_bytes());
		assert_eq!(result, hex!("39fb73727a0471fbdaff2a8124c6a349d3b98f17b93f108c495bcbe3bd85a233"));
		let mut hasher = RHash::new("FSB384");
		let pass = "volker".to_string();
		let result = hasher.process_string(pass.as_bytes());
		assert_eq!(result, hex!("ef05947d168b233e1e76a6db49e7ec324669530af5c473b7fb147a55473ca248ad2cc4d0f4f4cac7c63533cc713b305f"));
		let mut hasher = RHash::new("FSB512");
		let pass = "volker".to_string();
		let result = hasher.process_string(pass.as_bytes());
		assert_eq!(result, hex!("121e785b23b511cbb17c3656579d4794ed6dfc25e5d6274112221220be10a6d19a107e8e3f3c06f9e3fba5f51308a69539f0baf163835b55afcea425e0d059cd"));
	}

	#[test]
	fn test_md2() {
		let mut hasher = RHash::new("MD2");
		let pass = "b".to_string();
		let result = hasher.process_string(pass.as_bytes());
		assert_eq!(
			result,
			vec![
				130, 206, 148, 11, 27, 79, 210, 236, 216, 35, 110,
				129, 166, 248, 181, 203
			]
		);
	}
	#[test]
	fn test_md4() {
		let mut hasher = RHash::new("MD4");
		let result = hasher.process_string(b"");
		assert_eq!(
			result,
			vec![
				0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7,
				0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
			]
		);
	}
	#[test]
	fn test_md5() {
		let mut hasher = RHash::new("MD5");
		let data = b"";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			vec![
				0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9,
				0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
			]
		);
	}

	#[test]
	fn test_sha1() {
		let mut hasher = RHash::new("SHA1");
		let data = b"";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			vec![
				0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32,
				0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8,
				0x07, 0x09
			]
		);
	}

	#[test]
	fn test_sha2() {
		let mut hasher = RHash::new("SHA256");
		let data = b"";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			vec![
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a,
				0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae,
				0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99,
				0x1b, 0x78, 0x52, 0xb8, 0x55
			]
		);

		let mut hasher = RHash::new("SHA384");
		let data = b"";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			vec![
				0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c,
				0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd,
				0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7,
				0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
				0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48,
				0x98, 0xb9, 0x5b
			]
		);

		let mut hasher = RHash::new("SHA512");
		let data = b"";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			vec![
				0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1,
				0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20,
				0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9,
				0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c,
				0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87,
				0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41,
				0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda,
				0x3e
			]
		);
	}

	#[test]
	fn test_sha3() {
		use hex_literal::hex;
		let mut hasher = RHash::new("SHA3_224");
		let data = b"";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			vec![
				0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b,
				0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab, 0xd4, 0x59,
				0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b,
				0xc7
			]
		);

		let mut hasher = RHash::new("SHA3_256");
		let data = b"";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			vec![
				0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51,
				0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80,
				0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a,
				0x4b, 0x80, 0xf8, 0x43, 0x4a
			]
		);

		let mut hasher = RHash::new("SHA3_384");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(result, hex!("292c5d7b7d4a9f04cc88e2b7f1c82506ff006d9415b9c96dd71faadbaf89ff9a747cd7ec0b1ae50e29b321b12b24469e"));

		let mut hasher = RHash::new("SHA3_512");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("2aa84199f3d2c74cd676f8a34d164536c3c71142f90f4b1410495e3147685674fe591b4dd24f4768a8839e1680e8e6e91cc4ccbfeb1fe27577be16756b4bc364")
    );
	}

	#[test]
	fn test_gost94() {
		use hex_literal::hex;
		let mut hasher = RHash::new("GOST94");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("551dadd1e2f993d803a65e0e2eb71635ef9c4729be4ba60069a867416606243c")
    );

		let mut hasher = RHash::new("GOST94UA");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("d8439a5f1e69c451a66c0bd61ec3d2a1d72251b97795cd53b8dd12b438313c08")
    );
	}

	#[test]
	fn test_streebog() {
		use hex_literal::hex;
		let mut hasher = RHash::new("STREEBOG256");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("b26f5746c682b94aae1f379adc543ab57af2705dc00b1c8ce76f339d65ab0bea")
    );

		let mut hasher = RHash::new("STREEBOG512");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("a46f857d0bd23dc679c69d5234e44d58069a3d50c60da5abf56fabed70e3c72b2050763e8a7bd787c76b3c17fffedd65e8e1c14e7a911ef12899da9980efd8e9")
    );
	}

	#[test]
	fn test_shabal() {
		use hex_literal::hex;
		let mut hasher = RHash::new("SHABAL192");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
			result,
			hex!("48ad5122b9d23c402f895587423645c0021f43f9945b5ba3")
		);

		let mut hasher = RHash::new("SHABAL224");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("9a90b332259c0178c4a1ed9cd254eadfc917f88edf7b3dbee8e971da")
    );

		let mut hasher = RHash::new("SHABAL256");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("9779f7a748b7a6087c7e0f149877e87deb42371e2a10df0fbef1a38123029b02")
    );

		let mut hasher = RHash::new("SHABAL384");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("4dc385ce0932123d50330e41d9bdf633e4aeb4caf52200d2f5b3843a2061118fe82188f74a44741fc4278765b2a9c5fc")
    );

		let mut hasher = RHash::new("SHABAL512");
		let data = b"volker";
		let result = hasher.process_string(data);
		assert_eq!(
        result,
        hex!("911dfa9aaed2318d28ae5a04b5584a39be27ef558845f4c8235e7e4e72c63bfaedc02dd89270b367e651dc36d3dea2c471a7de7c9df3e65522dc6e2837e38b99")
    );
	}

	#[test]
	#[should_panic]
	fn test_error_string_hash() {
		let mut _hasher = RHash::new("MICKEYMOUSE");
	}

	#[test]
	fn test_parse_urls() {
		use crate::rgh::hhhash::parse_url;
		let url = "https://www.example.com";
		let parsed_url = parse_url(url).unwrap();
		assert_eq!(parsed_url.scheme(), "https");
		assert_eq!(parsed_url.host_str(), Some("www.example.com"));
	}

	#[test]
	fn test_hhhash_parse_url_with_path() {
		use crate::rgh::hhhash::parse_url;
		let url = "https://www.example.com/foo/bar";
		let parsed_url = parse_url(url).unwrap();
		assert_eq!(parsed_url.scheme(), "https");
		assert_eq!(parsed_url.host_str(), Some("www.example.com"));
		assert_eq!(parsed_url.path(), "/foo/bar");
	}

	#[test]
	fn test_hhhash_generate() {
		use crate::rgh::hhhash::generate_hhhash;
		let url = "https://www.example.com";
		let hash = generate_hhhash(url.to_string()).unwrap();
		assert!(hash.starts_with("hhh:1:"));
	}
	#[test]
	fn test_hhhash_generate_with_error() {
		use crate::rgh::hhhash::generate_hhhash;
		let url = "www2.schwaberow.de";
		let hash = generate_hhhash(url.to_string());
		assert!(hash.is_err());
	}
}
