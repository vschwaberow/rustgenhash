// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleValueType {
	Generic,
	Digest,
	Path,
	Json,
}

#[derive(Debug, Clone)]
pub struct ConsoleVariable {
	pub name: String,
	pub value: String,
	pub value_type: ConsoleValueType,
	pub sensitive: bool,
}

impl ConsoleVariable {
	pub fn preview(&self) -> String {
		if self.value.len() <= 8 || !self.sensitive {
			return self.value.clone();
		}
		let start = &self.value[..4];
		let end = &self.value[self.value.len() - 4..];
		format!("{start}****{end}")
	}
}

#[derive(Default)]
pub struct ConsoleVariableStore {
	values: HashMap<String, ConsoleVariable>,
}

impl ConsoleVariableStore {
	pub fn set(
		&mut self,
		name: impl Into<String>,
		value: impl Into<String>,
		value_type: ConsoleValueType,
		sensitive: bool,
	) {
		let name = name.into();
		let value = value.into();
		let variable = ConsoleVariable {
			name: name.clone(),
			value,
			value_type,
			sensitive,
		};
		self.values.insert(name, variable);
	}

	pub fn get(&self, name: &str) -> Option<&ConsoleVariable> {
		self.values.get(name)
	}

	pub fn clear(&mut self, name: &str) -> bool {
		self.values.remove(name).is_some()
	}

	pub fn list(&self) -> Vec<&ConsoleVariable> {
		let mut vars: Vec<_> = self.values.values().collect();
		vars.sort_by(|a, b| a.name.cmp(&b.name));
		vars
	}
}
