// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: app/mac.rs

use crate::rgh::mac::commands::{run_mac, MacInput, MacOptions};
use crate::rgh::mac::key::KeySource;
use crate::rgh::mac::registry;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::process;

pub(crate) fn handle_mac_command(
	matches: &clap::ArgMatches,
) -> Result<(), Box<dyn Error>> {
	let algorithm = matches
		.get_one::<String>("algorithm")
		.expect("algorithm must be provided")
		.to_owned();

	let key_source =
		if let Some(path) = matches.get_one::<String>("key") {
			KeySource::File(PathBuf::from(path))
		} else if matches.get_flag("key-stdin") {
			KeySource::Stdin
		} else {
			return Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidInput,
			"exactly one of --key or --key-stdin must be supplied",
		)));
		};

	let input = if let Some(text) = matches.get_one::<String>("input")
	{
		MacInput::Inline(text.clone())
	} else if let Some(path) = matches.get_one::<String>("file") {
		MacInput::File(PathBuf::from(path))
	} else if matches.get_flag("stdin") {
		MacInput::Stdin
	} else {
		return Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidInput,
			"provide one of --input, --file, or --stdin",
		)));
	};

	let hash_only = matches.get_flag("hash-only");
	let json = matches
		.get_one::<String>("format")
		.map(|value| value.eq_ignore_ascii_case("json"))
		.unwrap_or(false);

	let options = MacOptions {
		algorithm,
		key_source,
		input,
		hash_only,
		json,
	};

	match run_mac(options) {
		Ok(_) => Ok(()),
		Err(err) => match err.downcast::<registry::MacError>() {
			Ok(mac_err) => match mac_err.kind() {
				registry::MacErrorKind::InvalidKey
				| registry::MacErrorKind::InvalidKeyLength
				| registry::MacErrorKind::UnsupportedAlgorithm => {
					eprintln!("error: {}", mac_err);
					process::exit(2);
				}
				registry::MacErrorKind::Crypto => {
					Err(mac_err as Box<dyn Error>)
				}
			},
			Err(err) => Err(err),
		},
	}
}


