// SPDX-License-Identifier: MIT OR Apache-2.0
// Project: rustgenhash
// File: color.rs
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2022 Volker Schwaberow

#[cfg(windows)]
use colored::control;
use colored::{Color, Colorize};
use std::env;
use std::fmt;
use std::io::{self, IsTerminal};

use super::session::ConsoleMode;

/// User-facing color preference selected via CLI/env/builtin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
	#[default]
	Auto,
	Always,
	Never,
	HighContrast,
}

impl fmt::Display for ColorMode {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			ColorMode::Auto => "auto",
			ColorMode::Always => "always",
			ColorMode::Never => "never",
			ColorMode::HighContrast => "high-contrast",
		})
	}
}

impl std::str::FromStr for ColorMode {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"auto" => Ok(ColorMode::Auto),
			"always" | "on" => Ok(ColorMode::Always),
			"never" | "off" => Ok(ColorMode::Never),
			"high-contrast" | "high_contrast" | "contrast" => {
				Ok(ColorMode::HighContrast)
			}
			other => {
				Err(format!("unsupported color mode `{}`", other))
			}
		}
	}
}

/// Identifiers for the built-in color palettes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleColorThemeName {
	Default,
	HighContrast,
}

/// Represents a single palette entry with a truecolor + ANSI fallback.
#[derive(Debug, Clone, Copy)]
pub struct PaletteColor {
	rgb: (u8, u8, u8),
	fallback: Color,
}

impl PaletteColor {
	pub const fn new(rgb: (u8, u8, u8), fallback: Color) -> Self {
		Self { rgb, fallback }
	}

	pub fn resolve(self, supports_truecolor: bool) -> Color {
		if supports_truecolor {
			Color::TrueColor {
				r: self.rgb.0,
				g: self.rgb.1,
				b: self.rgb.2,
			}
		} else {
			self.fallback
		}
	}
}

/// Palette definition for console-owned lines.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleColorTheme {
	pub name: ConsoleColorThemeName,
	pub prompt: PaletteColor,
	pub success: PaletteColor,
	pub warning: PaletteColor,
	pub error: PaletteColor,
	pub info: PaletteColor,
	pub supports_truecolor: bool,
}

pub const DEFAULT_THEME: ConsoleColorTheme = ConsoleColorTheme {
	name: ConsoleColorThemeName::Default,
	prompt: PaletteColor::new((97, 175, 239), Color::BrightCyan),
	success: PaletteColor::new((46, 204, 113), Color::Green),
	warning: PaletteColor::new((242, 201, 76), Color::Yellow),
	error: PaletteColor::new((255, 107, 107), Color::Red),
	info: PaletteColor::new((86, 204, 242), Color::Cyan),
	supports_truecolor: true,
};

pub const HIGH_CONTRAST_THEME: ConsoleColorTheme =
	ConsoleColorTheme {
		name: ConsoleColorThemeName::HighContrast,
		prompt: PaletteColor::new((255, 255, 255), Color::White),
		success: PaletteColor::new((0, 255, 0), Color::BrightGreen),
		warning: PaletteColor::new(
			(255, 215, 0),
			Color::BrightYellow,
		),
		error: PaletteColor::new((255, 51, 51), Color::BrightRed),
		info: PaletteColor::new((173, 216, 230), Color::BrightBlue),
		supports_truecolor: true,
	};

#[cfg_attr(not(windows), allow(dead_code))]
const WINDOWS_LEGACY_NOTICE: &str =
	"windows console lacks ANSI support; falling back to monochrome output (try Windows Terminal or PowerShell)";

/// Describes the environment where the console is running.
#[derive(Debug, Clone, Copy)]
pub struct PlatformCapabilityProfile {
	pub supports_ansi: bool,
	pub supports_truecolor: bool,
	pub is_windows_legacy: bool,
	pub script_mode: bool,
	pub no_color_env: bool,
	pub legacy_notice: Option<&'static str>,
}

impl PlatformCapabilityProfile {
	pub fn detect(mode: ConsoleMode) -> Self {
		let script_mode = matches!(mode, ConsoleMode::Script);
		let stdout_is_tty = io::stdout().is_terminal();
		let term = env::var("TERM").unwrap_or_default();
		let dumb_terminal = term.eq_ignore_ascii_case("dumb");
		#[allow(unused_mut)]
		let mut supports_ansi =
			stdout_is_tty && !script_mode && !dumb_terminal;
		#[allow(unused_mut)]
		let mut supports_truecolor = detect_truecolor_hint();
		#[allow(unused_mut)]
		let mut is_windows_legacy = false;
		#[allow(unused_mut)]
		let mut legacy_notice = None;

		#[cfg(windows)]
		{
			if stdout_is_tty && !script_mode && !dumb_terminal {
				let _ = control::set_virtual_terminal(true);
			}
			let wt_env = env::var("WT_SESSION").is_ok();
			let conemu = env::var("ConEmuANSI")
				.map(|v| v.eq_ignore_ascii_case("ON"))
				.unwrap_or(false);
			let ansicon = env::var("ANSICON").is_ok();
			let term_program =
				env::var("TERM_PROGRAM").unwrap_or_default();
			let windows_terminal = wt_env
				|| term_program
					.to_ascii_lowercase()
					.contains("windows terminal");
			is_windows_legacy =
				!(windows_terminal || conemu || ansicon);
			if is_windows_legacy {
				supports_truecolor = false;
				supports_ansi = false;
				legacy_notice = Some(WINDOWS_LEGACY_NOTICE);
			} else {
				supports_ansi = stdout_is_tty;
				supports_truecolor = true;
			}
		}

		let no_color_env = env::var_os("NO_COLOR").is_some();
		Self {
			supports_ansi,
			supports_truecolor: supports_truecolor && supports_ansi,
			is_windows_legacy,
			script_mode,
			no_color_env,
			legacy_notice,
		}
	}
}

fn detect_truecolor_hint() -> bool {
	if let Ok(value) = env::var("COLORTERM") {
		let lower = value.to_ascii_lowercase();
		if lower.contains("truecolor") || lower.contains("24bit") {
			return true;
		}
	}
	if let Ok(term) = env::var("TERM") {
		let lower = term.to_ascii_lowercase();
		return lower.contains("24bit")
			|| lower.contains("truecolor")
			|| lower.contains("256color");
	}
	false
}

/// Logical buckets for console-owned output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleLineRole {
	Prompt,
	Success,
	Warning,
	Error,
	Info,
	ChildStdout,
	ChildStderr,
}

impl ConsoleLineRole {
	pub fn is_console_owned(self) -> bool {
		matches!(
			self,
			ConsoleLineRole::Prompt
				| ConsoleLineRole::Success
				| ConsoleLineRole::Warning
				| ConsoleLineRole::Error
				| ConsoleLineRole::Info
		)
	}
}

/// Tracks the current palette/mode decision for the session.
#[derive(Debug, Clone)]
pub struct ColorState {
	pub mode: ColorMode,
	palette: &'static ConsoleColorTheme,
	enabled: bool,
	pub reason: String,
	pub capability: PlatformCapabilityProfile,
}

impl ColorState {
	pub fn new(
		mode: ColorMode,
		capability: PlatformCapabilityProfile,
	) -> Self {
		let palette = match mode {
			ColorMode::HighContrast => &HIGH_CONTRAST_THEME,
			_ => &DEFAULT_THEME,
		};
		let enabled;
		let mut reason = String::new();

		if matches!(mode, ColorMode::Never) {
			enabled = false;
			reason.push_str("disabled via --color=never");
		} else if matches!(
			mode,
			ColorMode::Always | ColorMode::HighContrast
		) {
			enabled = true;
			if capability.script_mode {
				reason.push_str(
					"forced color via override (script mode)",
				);
			} else if capability.no_color_env {
				reason.push_str(
					"forced color via override (ignoring NO_COLOR)",
				);
			} else {
				reason.push_str("forced color via override");
			}
		} else if capability.no_color_env {
			enabled = false;
			reason.push_str("disabled via NO_COLOR");
		} else if capability.script_mode {
			enabled = false;
			reason.push_str("script mode defaults to monochrome");
		} else if !capability.supports_ansi {
			enabled = false;
			reason.push_str("terminal lacks ANSI capability");
		} else {
			enabled = true;
			reason.push_str("auto (ANSI capable)");
		}

		Self {
			mode,
			palette,
			enabled,
			reason,
			capability,
		}
	}

	pub fn palette(&self) -> &'static ConsoleColorTheme {
		self.palette
	}

	pub fn should_emit(&self) -> bool {
		self.enabled
	}

	pub fn update_mode(&mut self, mode: ColorMode) {
		*self = Self::new(mode, self.capability);
	}

	pub fn allows_coloring(&self, role: ConsoleLineRole) -> bool {
		self.enabled && role.is_console_owned()
	}

	pub fn color_for(&self, role: ConsoleLineRole) -> PaletteColor {
		match role {
			ConsoleLineRole::Prompt => self.palette.prompt,
			ConsoleLineRole::Success => self.palette.success,
			ConsoleLineRole::Warning => self.palette.warning,
			ConsoleLineRole::Error => self.palette.error,
			ConsoleLineRole::Info => self.palette.info,
			ConsoleLineRole::ChildStdout
			| ConsoleLineRole::ChildStderr => {
				panic!("child streams must not be colorized")
			}
		}
	}

	pub fn format(
		&self,
		role: ConsoleLineRole,
		message: &str,
	) -> String {
		if !self.allows_coloring(role) {
			return message.to_string();
		}
		let color = self
			.color_for(role)
			.resolve(self.capability.supports_truecolor);
		message.color(color).to_string()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use colored::control;

	fn test_profile() -> PlatformCapabilityProfile {
		PlatformCapabilityProfile {
			supports_ansi: true,
			supports_truecolor: true,
			is_windows_legacy: false,
			script_mode: false,
			no_color_env: false,
			legacy_notice: None,
		}
	}

	#[test]
	fn auto_mode_disables_when_script() {
		let mut profile = test_profile();
		profile.script_mode = true;
		let state = ColorState::new(ColorMode::Auto, profile);
		assert!(!state.should_emit());
	}

	#[test]
	fn always_mode_overrides_no_color() {
		let mut profile = test_profile();
		profile.no_color_env = true;
		let state = ColorState::new(ColorMode::Always, profile);
		assert!(state.should_emit());
		assert!(state.allows_coloring(ConsoleLineRole::Prompt));
	}

	#[test]
	fn child_streams_are_never_colorized() {
		let state =
			ColorState::new(ColorMode::Always, test_profile());
		assert!(!state.allows_coloring(ConsoleLineRole::ChildStdout));
		assert!(!state.allows_coloring(ConsoleLineRole::ChildStderr));
	}

	#[test]
	fn legacy_profile_sets_notice_and_disables_color() {
		let profile = PlatformCapabilityProfile {
			supports_ansi: false,
			supports_truecolor: false,
			is_windows_legacy: true,
			script_mode: false,
			no_color_env: false,
			legacy_notice: Some(WINDOWS_LEGACY_NOTICE),
		};
		let state = ColorState::new(ColorMode::Auto, profile);
		assert!(!state.should_emit());
		assert_eq!(state.reason, "terminal lacks ANSI capability");
		assert_eq!(
			profile.legacy_notice,
			Some(WINDOWS_LEGACY_NOTICE)
		);
	}

	#[test]
	fn truecolor_fallback_uses_basic_palette() {
		let mut profile = test_profile();
		profile.supports_truecolor = false;
		let state = ColorState::new(ColorMode::Always, profile);
		control::set_override(true);
		let output = state.format(ConsoleLineRole::Prompt, "demo");
		control::unset_override();
		assert!(
			output.contains("\x1b["),
			"expected ANSI escape even without truecolor support"
		);
		assert!(
			!output.contains("38;2"),
			"expected 8-bit escape instead of truecolor"
		);
	}
}
