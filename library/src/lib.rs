// This is a required file for rust libraries which declares what files are
// part of the library and what interfaces are public from the library.

#[macro_use]
mod logging_macros;

// Declare that the c_api.rs file exists and is a public sub-namespace.
// C doesn't care about the namespaces, but Rust does.
pub mod c_api;

// Declare other .rs file/module exists, but make them private.
mod cache;
mod config;
mod encrypted_patch;
mod events;
mod file_errors;
mod logging;
mod native_boot;
mod native_cache;
mod network;
mod time;
mod updater;
mod updater_lock;
mod vmcode;
mod yaml;

#[cfg(any(target_os = "android", test))]
mod android;

#[cfg(test)]
mod test_utils;

// Take all public items from the updater namespace and make them public.
pub use self::updater::*;

#[cfg(test)]
extern crate tempfile;

mod response_auth;

/// Startup integrity gate: signed build manifest, loaded-module measurement
/// and package identity (hardening P3).
mod integrity;
// File-image parsers are used at run time only on the platforms that measure
// files (Windows); every platform tests all of them.
#[cfg_attr(not(test), allow(dead_code))]
mod module_measurement;
mod package_identity;
/// Release root of trust: root chain and role delegations (hardening P4,
/// contract v2). The device uses the build-manifest role; the
/// artifact-catalog role is verified by the build tools.
#[cfg_attr(not(test), allow(dead_code))]
mod release_trust;

/// Compiled security floor and release admission (hardening contracts v1
/// and v2).
mod security;
// Shared with build.rs; the library itself uses only the identity check.
#[allow(dead_code)]
mod security_inputs;

/// Signed v2 selection verification and durable authorization.
pub mod selection_v2;
