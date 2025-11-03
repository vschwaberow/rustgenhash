// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: walker.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use super::{DirectoryHashPlan, WalkOrder};

#[derive(
	Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
pub enum SymlinkPolicy {
	Never,
	Files,
	All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkEntry {
	pub path: PathBuf,
	pub is_symlink: bool,
}

impl WalkEntry {
	fn new(path: PathBuf, is_symlink: bool) -> Self {
		Self { path, is_symlink }
	}
}

pub struct Walker {
	plan: DirectoryHashPlan,
}

impl Walker {
	pub fn new(plan: DirectoryHashPlan) -> Self {
		Self { plan }
	}

	pub fn plan(&self) -> &DirectoryHashPlan {
		&self.plan
	}

	pub fn walk(&self) -> io::Result<Vec<WalkEntry>> {
		let max_depth = if self.plan.requires_recursion() {
			usize::MAX
		} else {
			1
		};
		let mut entries = Vec::new();

		if self.plan.root_path.is_file() {
			let metadata =
				fs::symlink_metadata(&self.plan.root_path)?;
			let file_type = metadata.file_type();
			let is_symlink = file_type.is_symlink();
			if !is_symlink
				|| self
					.include_symlink(is_symlink, file_type.is_dir())
			{
				entries.push(WalkEntry::new(
					self.plan.root_path.clone(),
					is_symlink,
				));
			}
			self.sort(&mut entries);
			return Ok(entries);
		}

		let walker = WalkDir::new(&self.plan.root_path)
			.max_depth(max_depth)
			.follow_links(self.follow_links())
			.sort_by(|a, b| a.file_name().cmp(b.file_name()));

		let mut visited = if self.follow_links() {
			let mut set = HashSet::new();
			if let Ok(root) = fs::canonicalize(&self.plan.root_path) {
				set.insert(root);
			}
			Some(set)
		} else {
			None
		};

		let mut iter = walker.into_iter();
		while let Some(entry) = iter.next() {
			let entry = entry.map_err(to_io_error)?;
			if entry.depth() == 0 {
				if entry.file_type().is_dir() {
					continue;
				}
			}
			let file_type = entry.file_type();
			if file_type.is_dir() {
				if let (true, Some(set)) =
					(self.follow_links(), visited.as_mut())
				{
					if entry.path_is_symlink() {
						if let Ok(real) =
							fs::canonicalize(entry.path())
						{
							if !set.insert(real) {
								iter.skip_current_dir();
								continue;
							}
						}
					}
				}
				continue;
			}
			let is_symlink = file_type.is_symlink();
			if is_symlink
				&& !self
					.include_symlink(is_symlink, file_type.is_dir())
			{
				continue;
			}
			entries
				.push(WalkEntry::new(entry.into_path(), is_symlink));
		}

		self.sort(&mut entries);
		Ok(entries)
	}

	fn include_symlink(
		&self,
		is_symlink: bool,
		is_dir: bool,
	) -> bool {
		if !is_symlink {
			return true;
		}
		match self.plan.follow_symlinks {
			SymlinkPolicy::Never => false,
			SymlinkPolicy::Files => !is_dir,
			SymlinkPolicy::All => true,
		}
	}

	fn follow_links(&self) -> bool {
		matches!(self.plan.follow_symlinks, SymlinkPolicy::All)
	}

	fn sort(&self, entries: &mut Vec<WalkEntry>) {
		match self.plan.order {
			WalkOrder::Lexicographic => {
				entries.sort_by(|a, b| a.path.cmp(&b.path))
			}
		}
	}
}

fn to_io_error(err: walkdir::Error) -> io::Error {
	if let Some(inner) = err.io_error() {
		return io::Error::new(inner.kind(), inner.to_string());
	}
	io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[cfg(test)]
mod tests {
	use super::super::ThreadStrategy;
	use super::*;
	use std::path::{Path, PathBuf};
	use tempfile::tempdir;

	fn write(path: &Path, contents: &str) {
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(path, contents).unwrap();
	}

	fn make_plan(
		root: &Path,
		policy: SymlinkPolicy,
		recursive: bool,
	) -> DirectoryHashPlan {
		DirectoryHashPlan {
			root_path: root.to_path_buf(),
			recursive,
			follow_symlinks: policy,
			order: WalkOrder::Lexicographic,
			threads: ThreadStrategy::Single,
			mmap_threshold: None,
		}
	}

	#[test]
	fn orders_entries_lexicographically() {
		let tmp = tempdir().unwrap();
		let root = tmp.path();
		write(&root.join("b.txt"), "b");
		write(&root.join("a.txt"), "a");
		write(&root.join("nested/c.txt"), "c");

		let plan = make_plan(root, SymlinkPolicy::Never, true);
		let walker = Walker::new(plan);
		let entries = walker.walk().unwrap();
		let names: Vec<_> = entries
			.iter()
			.map(|e| e.path.strip_prefix(root).unwrap().to_path_buf())
			.collect();
		assert_eq!(
			names,
			vec![
				PathBuf::from("a.txt"),
				PathBuf::from("b.txt"),
				PathBuf::from("nested/c.txt")
			]
		);
	}

	#[cfg(unix)]
	#[test]
	fn respects_symlink_policy() {
		use std::os::unix::fs::symlink;
		let tmp = tempdir().unwrap();
		let root = tmp.path();
		write(&root.join("file.txt"), "base");
		write(&root.join("target.txt"), "target");
		symlink(&root.join("target.txt"), &root.join("link.txt"))
			.unwrap();

		let plan_never = make_plan(root, SymlinkPolicy::Never, false);
		let entries_never = Walker::new(plan_never).walk().unwrap();
		assert_eq!(entries_never.len(), 1);

		let plan_files = make_plan(root, SymlinkPolicy::Files, false);
		let entries_files = Walker::new(plan_files).walk().unwrap();
		assert_eq!(entries_files.len(), 2);
	}
}
