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

/// Compiled security floor and release admission (hardening contract v1).
mod security;
// Shared with build.rs; the library itself uses only the identity check.
#[allow(dead_code)]
mod security_inputs;

/// Signed v2 selection verification and durable authorization.
pub mod selection_v2;
