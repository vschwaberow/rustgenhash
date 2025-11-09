// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: variables.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

use std::collections::HashMap;
use std::time::SystemTime;

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
	pub created_at: SystemTime,
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
	order: Vec<String>,
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
			created_at: SystemTime::now(),
		};
		let is_new = !self.values.contains_key(&name);
		self.values.insert(name.clone(), variable);
		if is_new {
			self.order.push(name);
		}
	}

	pub fn get(&self, name: &str) -> Option<&ConsoleVariable> {
		self.values.get(name)
	}

	pub fn clear(&mut self, name: &str) -> bool {
		if self.values.remove(name).is_some() {
			self.order.retain(|entry| entry != name);
			true
		} else {
			false
		}
	}

	pub fn list(&self) -> Vec<&ConsoleVariable> {
		let mut vars = Vec::new();
		for key in &self.order {
			if let Some(var) = self.values.get(key) {
				vars.push(var);
			}
		}
		vars
	}
}
