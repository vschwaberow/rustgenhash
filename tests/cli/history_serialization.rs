use std::fs;
use std::time::{Duration, SystemTime};

use rustgenhash::rgh::console::history::{
	self, HistoryExecutionStatus, HistoryOrigin, HistoryRecord,
	HistoryRetention,
};
use tempfile::tempdir;

#[test]
fn snapshot_round_trip_prunes_and_preserves_metadata() {
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("history.json");

	let mut records = Vec::new();
	let target_len = history::DEFAULT_MAX_PERSISTED + 26;
	for idx in 0..target_len {
		let timestamp =
			SystemTime::UNIX_EPOCH + Duration::from_secs(idx as u64);
		let exit_code = if idx % 2 == 0 { 0 } else { 1 };
		let status =
			HistoryExecutionStatus::from_exit_code(exit_code);
		let replay_of = if idx > 0 && idx % 10 == 0 {
			Some(format!("cmd-{}", idx - 1))
		} else {
			None
		};
		records.push(HistoryRecord {
			timestamp,
			command: format!("cmd-{}", idx),
			exit_code,
			execution_status: status,
			replay_of,
			origin: HistoryOrigin::Live,
		});
	}

	history::save_snapshot(
		&path,
		HistoryRetention::Sanitized,
		&records,
	)
	.expect("save snapshot");
	let snapshot =
		history::load_snapshot(&path).expect("load snapshot");

	assert_eq!(
		snapshot.entries.len(),
		history::DEFAULT_MAX_PERSISTED,
		"persisted snapshot should be pruned to default limit"
	);
	let last = snapshot.entries.last().expect("last entry");
	assert!(last.command.starts_with("cmd-"));
	assert_eq!(last.execution_status, HistoryExecutionStatus::Error);
	assert!(matches!(last.origin, HistoryOrigin::Persisted));
	assert!(
		snapshot.entries.iter().any(|entry| entry
			.replay_of
			.as_deref()
			.unwrap_or_default()
			.starts_with("cmd-")),
		"expected at least one entry to retain replay_of metadata"
	);
}

#[test]
fn legacy_array_files_are_migrated() {
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("legacy.json");
	fs::write(
		&path,
		r#"[{"timestamp":1700,"command":"legacy","exit_code":-1}]"#,
	)
	.expect("write legacy file");

	let snapshot =
		history::load_snapshot(&path).expect("load legacy snapshot");
	assert_eq!(snapshot.entries.len(), 1);
	let entry = &snapshot.entries[0];
	assert_eq!(entry.command, "legacy");
	assert_eq!(
		entry.execution_status,
		HistoryExecutionStatus::Cancelled
	);
	assert!(matches!(entry.origin, HistoryOrigin::Persisted));
}
