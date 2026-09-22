// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash

use super::common::select_output_format;
use crate::rgh::benchmark::{
	render_digest_report, run_digest_benchmarks,
};
use crate::rgh::cli::algorithms::Algorithm;
use crate::rgh::hhhash::generate_hhhash;
use crate::rgh::random::{RandomNumberGenerator, RngType};
use dialoguer::{Input, MultiSelect, Select};
use std::error::Error;
use strum::IntoEnumIterator;

pub(crate) fn select_rng_type() -> Result<RngType, Box<dyn Error>> {
	let rng_types: Vec<_> = RngType::iter().collect();
	let selection = Select::new()
		.with_prompt("Select a random number generator type")
		.items(&rng_types)
		.interact()?;

	Ok(rng_types[selection])
}

pub(crate) fn interactive_generate_random() -> Result<(), Box<dyn Error>> {
	let rng_type = select_rng_type()?;
	let length = Input::<u64>::new()
		.with_prompt("Enter the length of the random string")
		.default(32)
		.interact()?;

	let output_option = select_output_format()?;

	let out = RandomNumberGenerator::new(rng_type)
		.generate(length, output_option)?;
	println!("{}", out);

	Ok(())
}

pub(crate) fn interactive_generate_hhhash() -> Result<(), Box<dyn Error>> {
	let url = Input::<String>::new()
		.with_prompt("Enter the URL to fetch")
		.interact_text()?;

	let hash = generate_hhhash(url)?;
	println!("{}", hash);

	Ok(())
}

pub(crate) fn interactive_run_benchmarks() -> Result<(), Box<dyn Error>> {
	let algorithms = MultiSelect::new()
		.with_prompt("Select algorithms to benchmark")
		.items(&Algorithm::iter().collect::<Vec<_>>())
		.interact()?;

	let iterations = Input::<u32>::new()
		.with_prompt("Enter the number of iterations")
		.default(100)
		.interact()?;

	let selected_algorithms: Vec<Algorithm> = algorithms
		.into_iter()
		.map(|i| Algorithm::iter().nth(i).unwrap())
		.collect();

	let summary =
		run_digest_benchmarks(&selected_algorithms, iterations)
			.map_err(|err| Box::new(err) as Box<dyn Error>)?;
	render_digest_report(&summary);

	Ok(())
}

// Helpers

