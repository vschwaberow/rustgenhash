// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hhhash.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::error::Error;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
use reqwest::blocking::Client;
#[cfg(not(target_arch = "wasm32"))]
use sha2::Digest;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

pub fn parse_url(
	url: &str,
) -> Result<Url, Box<dyn std::error::Error>> {
	let parsed_url = match Url::parse(url) {
		Ok(url) => {
			if matches!(url.scheme(), "http" | "https") {
				url
			} else {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidInput,
					format!(
						"URL {} has an invalid scheme. Only http or https are allowed.",
						url
					),
				)
				.into());
			}
		}
		Err(_) => {
			eprintln!("Warning: URL {} is not valid / complete. Assuming https.", url);
			Url::parse(&format!("https://{}", url)).map_err(|e| {
				Box::new(e) as Box<dyn std::error::Error>
			})?
		}
	};
	Ok(parsed_url)
}

#[cfg(target_arch = "wasm32")]
pub fn generate_hhhash(
	_url: String,
) -> Result<String, Box<dyn Error>> {
	Err("HHHash generation is not supported on wasm targets".into())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_hhhash(
	url: String,
) -> Result<String, Box<dyn Error>> {
	let parsed_url = parse_url(&url)?;

	let client =
		Client::builder().timeout(Duration::from_secs(10)).build()?;

	let resp = client.get(parsed_url).send()?;

	let header_names: Vec<_> = resp
		.headers()
		.keys()
		.map(|header| header.as_str())
		.collect();
	let header_string = header_names.join("\n");

	let mut hasher = sha2::Sha256::new();
	hasher.update(header_string.as_bytes());
	let hash = hasher.finalize();
	let hash = format!("hhh:1:{}", hex::encode(hash));

	Ok(hash)
}
