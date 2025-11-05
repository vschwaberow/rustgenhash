use rustgenhash::rgh::mac::executor::{consume_bytes, digest_to_hex};
use rustgenhash::rgh::mac::registry;
use std::fs::File;

#[test]
fn kmac256_vector_matches() {
	let key = std::fs::read("tests/fixtures/keys/kmac.key").unwrap();
	let (executor, _) =
		registry::create_executor("kmac256", &key).unwrap();
	let digest = consume_bytes(b"Compliance message", executor);
	assert_eq!(
        digest_to_hex(&digest),
        "dbbfeb5afc0ace13d06ac2efc2efed874793bd88f2e03f66ae69274bdeaa9c968a63e0259791e2f596c442719e6069cd49f8add11f2cefae6a0f4a7c9c8bd23c"
    );
}

#[test]
fn blake3_keyed_vector_matches() {
	let key =
		std::fs::read("tests/fixtures/keys/blake3.key").unwrap();
	let (executor, _) =
		registry::create_executor("blake3-keyed", &key).unwrap();
	let digest = consume_bytes(b"alpha", executor);
	assert_eq!(
        digest_to_hex(&digest),
        "e66e5af037fb22dc6d957057b669507d4627de61b43061053cb3782ecb07e41f"
    );
}

#[test]
fn kmac256_file_fixture_matches() {
	let key = std::fs::read("tests/fixtures/keys/kmac.key").unwrap();
	let (executor, _) =
		registry::create_executor("kmac256", &key).unwrap();
	let mut file =
		File::open("tests/fixtures/file/sample.txt").unwrap();
	let digest = rustgenhash::rgh::mac::executor::consume_reader(
		&mut file, executor,
	)
	.unwrap();
	assert_eq!(
        digest_to_hex(&digest),
        "f1da31385c8e9bd97a65f9323c7dfd63417b1e5fd6137a1178257cabe9c6fbb5bdca6442f0f972d158baad542fa384d2aae1bbba0940dd08e47ceee5d29d2a1e"
    );
}

#[test]
fn blake3_keyed_stdio_fixture_matches() {
	let key =
		std::fs::read("tests/fixtures/keys/blake3.key").unwrap();
	let mut results = Vec::new();
	for line in ["alpha", "beta"] {
		let (executor, _) =
			registry::create_executor("blake3-keyed", &key).unwrap();
		let digest = consume_bytes(line.as_bytes(), executor);
		results.push(digest_to_hex(&digest));
	}
	assert_eq!(
        results,
        vec![
            "e66e5af037fb22dc6d957057b669507d4627de61b43061053cb3782ecb07e41f".to_string(),
            "c1a91f69569cc82e93f716d02e7c07b5c5be53a27f2ad5b99af63fcbc6a63518".to_string()
        ]
    );
}
