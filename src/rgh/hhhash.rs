// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: hhhash.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use reqwest::blocking::Client;
use sha2::Digest;
use std::error::Error;
use std::time::Duration;
use url::Url;

pub fn parse_url(
	url: &str,
) -> Result<Url, Box<dyn std::error::Error>> {
	let parsed_url = match Url::parse(url) {
		Ok(url) => match url.scheme() {
			"http" | "https" => url,
			_ => {
				eprintln!("Error: URL {} has an invalid scheme. Only http or https are allowed.", url);
				std::process::exit(1);
			}
		},
		Err(_) => {
			eprintln!("Warning: URL {} is not valid / complete. Assuming https.", url);
			Url::parse(&format!("https://{}", url)).map_err(|e| {
				Box::new(e) as Box<dyn std::error::Error>
			})?
		}
	};
	Ok(parsed_url)
}
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
