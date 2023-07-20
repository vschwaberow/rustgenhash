// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hhhash.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use reqwest::blocking::Client;
use sha2::Digest;
use std::error::Error;
use std::time::Duration;

pub fn generate_hhhash(
	url: String,
) -> Result<String, Box<dyn Error>> {
	let client =
		Client::builder().timeout(Duration::from_secs(10)).build()?;
	let resp = client.get(url).send();
	match resp {
		Ok(resp) => {
			let headers = resp.headers();

			let mut header_names = Vec::new();
			for header_name in headers.keys() {
				header_names.push(header_name);
			}

			let header_string = header_names
				.iter()
				.map(|h| h.as_str())
				.collect::<Vec<_>>()
				.join("\n");

			let mut hasher = sha2::Sha256::new();
			hasher.update(header_string.as_bytes());
			let hash = hasher.finalize();
			let hash = format!("hhh:1:{}", hex::encode(hash));
			Ok(hash)
		}
		Err(e) => Err(Box::new(e)),
	}
}
