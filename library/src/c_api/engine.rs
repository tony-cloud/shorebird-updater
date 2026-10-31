//! Engine-internal C API surface.
//!
//! These symbols are consumed by Shorebird's Flutter engine
//! (`flutter::shorebird::Updater` in `shell/common/shorebird/updater.cc`) and
//! by no other public consumer. Both sides ship together as part of the
//! engine, so this surface has no stability guarantee — change freely as the
//! engine integration evolves.
//!
//! cbindgen reads this file directly (see `build.rs`) and emits exactly the
//! `pub extern "C"` items found here plus the types they reference. Adding
//! a function to this file automatically adds it to the engine header — no
//! cbindgen-config update required. Conversely, anything declared in
//! `c_api::dart` cannot leak into this header.
//!
//! For the stable Dart surface consumed by `package:shorebird_code_push`,
//! see `c_api::dart`.
use std::os::raw::c_char;
use std::path::PathBuf;

use super::{allocate_c_string, free_c_string, log_on_error, to_rust};
use crate::c_api::c_file::CFileProvider;
use crate::updater;

/// Application-owned resolver for a 32-byte per-patch AES key. `key_id` and
/// validated UTF-8 `aad` are borrowed NUL-terminated strings. Write exactly
/// 32 bytes and set `written`, or return false. May run on an updater worker;
/// must be thread-safe and remain callable for the process lifetime. Never
/// return the server master secret or derive keys from public device IDs.
pub type PatchDecryptionKeyProvider = unsafe extern "C" fn(
    key_id: *const c_char,
    aad: *const c_char,
    key_out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> bool;

/// Register before shorebird_init; returns false after initialization.
/// A non-null provider requires encrypted patch delivery and strict signed
/// response/boot policies. Null disables delivery encryption before init only.
/// Key provisioning is the application's authenticated service responsibility.
#[no_mangle]
pub extern "C" fn shorebird_set_patch_decryption_key_provider(
    provider: Option<
        unsafe extern "C" fn(
            key_id: *const c_char,
            aad: *const c_char,
            key_out: *mut u8,
            capacity: usize,
            written: *mut usize,
        ) -> bool,
    >,
) -> bool {
    crate::encrypted_patch::set_provider(provider)
}

/// Struct containing configuration parameters for the updater.
/// Passed to `shorebird_init`.
/// NOTE: If this struct is changed all language bindings must be updated.
#[repr(C)]
pub struct AppParameters {
    /// release_version, required.  Named version of the app, off of which
    /// updates are based.  Can be either a version number or a hash.
    pub release_version: *const libc::c_char,

    /// Array of paths to the original aot library, required.  For Flutter apps
    /// these are the paths to the bundled libapp.so.  May be used for
    /// compression downloaded artifacts.
    pub original_libapp_paths: *const *const libc::c_char,

    /// Length of the original_libapp_paths array.
    pub original_libapp_paths_size: libc::c_int,

    /// Path to app storage directory where the updater will store serialized
    /// state and other data that persists between releases.
    pub app_storage_dir: *const libc::c_char,

    /// Path to cache directory where the updater will store downloaded
    /// artifacts and data that can be deleted when a new release is detected.
    pub code_cache_dir: *const libc::c_char,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FileCallbacks {
    /// Opens the "file" (actually an in-memory buffer) and returns a handle.
    pub open: extern "C" fn() -> *mut libc::c_void,

    /// Reads count bytes from the file into buffer.  Returns the number of
    /// bytes read.
    pub read: extern "C" fn(file_handle: *mut libc::c_void, buffer: *mut u8, count: usize) -> usize,

    /// Moves the file pointer to the given offset relative from whence (one of
    /// libc::SEEK_SET, libc::SEEK_CUR, or libc::SEEK_END). Returns the new
    /// offset relative to the start of the file.
    pub seek: extern "C" fn(file_handle: *mut libc::c_void, offset: i64, whence: i32) -> i64,

    /// Closes and frees the file handle.
    pub close: extern "C" fn(file_handle: *mut libc::c_void),
}

fn to_rust_vector(
    c_array: *const *const libc::c_char,
    size: libc::c_int,
) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    for i in 0..size {
        let c_string = unsafe { *c_array.offset(i as isize) };
        result.push(to_rust(c_string)?);
    }
    Ok(result)
}

fn app_config_from_c(c_params: *const AppParameters) -> anyhow::Result<updater::AppConfig> {
    anyhow::ensure!(
        !c_params.is_null(),
        "Null parameters passed to app_config_from_c"
    );
    let c_params_ref = unsafe { &*c_params };

    Ok(updater::AppConfig {
        app_storage_dir: to_rust(c_params_ref.app_storage_dir)?,
        code_cache_dir: to_rust(c_params_ref.code_cache_dir)?,
        release_version: to_rust(c_params_ref.release_version)?,
        original_libapp_paths: to_rust_vector(
            c_params_ref.original_libapp_paths,
            c_params_ref.original_libapp_paths_size,
        )?,
    })
}

fn path_to_c_string(path: Option<PathBuf>) -> anyhow::Result<*mut c_char> {
    Ok(match path {
        Some(v) => allocate_c_string(v.to_str().unwrap())?,
        None => std::ptr::null_mut(),
    })
}

/// Free a string returned by the updater library.
///
/// # Safety
///
/// If this function is called with a non-null pointer, it must be a pointer
/// returned by the updater library.
#[no_mangle]
pub unsafe extern "C" fn shorebird_free_string(c_string: *const c_char) {
    unsafe { free_c_string(c_string) }
}

/// Configures the updater. First parameter is a struct containing
/// configuration from the running app. Second parameter is a YAML string
/// containing configuration compiled into the app. Returns true on success
/// and false on failure. If false is returned, the updater library will not
/// be usable.
#[no_mangle]
pub extern "C" fn shorebird_init(
    c_params: *const AppParameters,
    c_file_callbacks: FileCallbacks,
    c_yaml: *const libc::c_char,
) -> bool {
    log_on_error(
        || {
            let config = app_config_from_c(c_params)?;
            let file_provider = Box::new(CFileProvider {
                file_callbacks: c_file_callbacks,
            });
            let yaml_string = to_rust(c_yaml)?;
            updater::init(config, file_provider, &yaml_string)?;
            Ok(true)
        },
        "initializing updater",
        false,
    )
}

/// Returns if the app should run the updater automatically on launch.
#[no_mangle]
pub extern "C" fn shorebird_should_auto_update() -> bool {
    log_on_error(
        updater::should_auto_update,
        "fetching update behavior",
        true,
    )
}

/// Performs integrity checks on the next boot patch. If the patch fails
/// these checks, the patch will be deleted and the next boot patch will be
/// set to the last successfully booted patch or the base release if there is
/// no last successfully booted patch.
#[no_mangle]
pub extern "C" fn shorebird_validate_next_boot_patch() {
    log_on_error(
        updater::validate_next_boot_patch,
        "validating next_boot_patch",
        (),
    );
}

/// The path to the patch that will boot on the next run of the app, or NULL
/// if there is no next patch. The caller must free the returned string with
/// `shorebird_free_string`.
#[no_mangle]
pub extern "C" fn shorebird_next_boot_patch_path() -> *mut c_char {
    log_on_error(
        || {
            let maybe_path = updater::with_mut_state(|state| {
                Ok(state
                    .next_boot_patch()
                    .filter(|patch| {
                        matches!(
                            state.lifecycle().read_state(patch.number),
                            Some(crate::cache::lifecycle::PatchState::Installed { .. })
                        )
                    })
                    .map(|p| p.path))
            })?;
            path_to_c_string(maybe_path)
        },
        "fetching next_boot_patch_path",
        std::ptr::null_mut(),
    )
}

/// Start a thread to download an update if one is available.
#[no_mangle]
pub extern "C" fn shorebird_start_update_thread() {
    // The thread runs detached; nothing waits for it.
    drop(updater::start_update_thread());
}

/// Tell the updater that we're launching from what it told us was the
/// next patch to boot from. This will copy the next boot patch to be the
/// `current_boot` patch.
///
/// It is required to call this function before calling
/// `shorebird_report_launch_success` or `shorebird_report_launch_failure`.
#[no_mangle]
pub extern "C" fn shorebird_report_launch_start() {
    log_on_error(updater::report_launch_start, "reporting launch start", ());
}

/// Report that the app failed to launch. This will cause the updater to
/// attempt to roll back to the previous version if this version has not been
/// launched successfully before.
#[no_mangle]
pub extern "C" fn shorebird_report_launch_failure() {
    log_on_error(
        updater::report_launch_failure,
        "reporting launch failure",
        (),
    );
}

/// Report that the app launched successfully. The Shell constructor calls
/// this once per process when the VM has finished booting; it pairs with
/// `shorebird_report_launch_start` to mark a patch as having booted cleanly.
#[no_mangle]
pub extern "C" fn shorebird_report_launch_success() {
    log_on_error(
        updater::report_launch_success,
        "reporting launch success",
        (),
    );
}

/// Loader capability; this is independent of application key authorization.
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum ShorebirdNativeSourceCapability {
    SHOREBIRD_NATIVE_SOURCE_LEGACY = 0,
    SHOREBIRD_NATIVE_SOURCE_SEALED_FD_V1 = 1,
    SHOREBIRD_NATIVE_SOURCE_VERIFIED_MEMORY_V1 = 2,
}

/// Additive engine options. Active encrypted mode requires a release-owned,
/// nonzero expanded-image budget. Unsupported capabilities fail explicitly.
#[repr(C)]
pub struct ShorebirdEngineOptions {
    pub struct_size: libc::size_t,
    pub native_source_capability: u32,
    pub max_native_image_bytes: u64,
}

/// Initialize atomically with source capability and cache migration. Identical
/// successful repeated initialization preserves the immutable process selection.
///
/// # Safety
/// Input pointers must reference readable C structs/strings for the call.
#[no_mangle]
pub unsafe extern "C" fn shorebird_init_with_options(
    parameters: *const AppParameters,
    base_callbacks: FileCallbacks,
    compiled_yaml: *const c_char,
    options: *const ShorebirdEngineOptions,
) -> bool {
    log_on_error(
        || {
            anyhow::ensure!(!options.is_null(), "Missing engine options");
            anyhow::ensure!(
                unsafe { (*options).struct_size } >= std::mem::size_of::<ShorebirdEngineOptions>(),
                "Truncated engine options"
            );
            let options = unsafe { &*options };
            crate::native_boot::initialize(
                app_config_from_c(parameters)?,
                base_callbacks,
                to_rust(compiled_yaml)?,
                crate::native_boot::NativeOptions {
                    capability: options.native_source_capability,
                    max_image_bytes: options.max_native_image_bytes,
                },
            )?;
            Ok(true)
        },
        "initializing prepared native updater",
        false,
    )
}

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum ShorebirdBootSourceKind {
    SHOREBIRD_BOOT_BASE = 0,
    SHOREBIRD_BOOT_PATH = 1,
    SHOREBIRD_BOOT_FD = 2,
    SHOREBIRD_BOOT_MEMORY = 3,
}

/// Caller owns fd/path until release or explicit detach (fd = -1/path = NULL).
/// Set struct_size before prepare. Every successful result has a nonzero token.
#[repr(C)]
pub struct ShorebirdBootSource {
    pub struct_size: libc::size_t,
    pub kind: u32,
    pub selection_id: u64,
    pub patch_number: u64,
    pub image_size: u64,
    pub fd: i32,
    pub path: *mut c_char,
}
impl ShorebirdBootSource {
    fn empty() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>(),
            kind: 0,
            selection_id: 0,
            patch_number: 0,
            image_size: 0,
            fd: -1,
            path: std::ptr::null_mut(),
        }
    }
}

/// Prepare exactly one immutable process source. Key/source unavailability
/// selects BASE and retains the authenticated candidate for a fresh process.
/// Do not pass an already-owned output without releasing it first.
///
/// # Safety
/// `out` must be null or reference writable storage of its advertised size.
#[no_mangle]
pub unsafe extern "C" fn shorebird_prepare_boot_source(out: *mut ShorebirdBootSource) -> bool {
    log_on_error(
        || {
            anyhow::ensure!(!out.is_null(), "Missing source output");
            anyhow::ensure!(
                unsafe { (*out).struct_size } >= std::mem::size_of::<ShorebirdBootSource>(),
                "Truncated source output"
            );
            unsafe {
                out.write(ShorebirdBootSource::empty());
            }
            let source = crate::native_boot::prepare()?;
            let path = source
                .path
                .map(|path| {
                    path.into_os_string()
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("Native source path is not UTF-8"))
                })
                .transpose()?;
            let path = path
                .map(|path| allocate_c_string(&path))
                .transpose()?
                .unwrap_or(std::ptr::null_mut());
            #[cfg(unix)]
            let fd = {
                use std::os::fd::IntoRawFd;
                source.file.map(|file| file.into_raw_fd()).unwrap_or(-1)
            };
            #[cfg(not(unix))]
            let fd = {
                anyhow::ensure!(source.file.is_none(), "Native FD export unsupported");
                -1
            };
            unsafe {
                out.write(ShorebirdBootSource {
                    struct_size: std::mem::size_of::<ShorebirdBootSource>(),
                    kind: if source.memory.is_some() {
                        3
                    } else if fd >= 0 {
                        2
                    } else if !path.is_null() {
                        1
                    } else {
                        0
                    },
                    selection_id: source.id,
                    patch_number: source.patch.unwrap_or(0) as u64,
                    image_size: source.size,
                    fd,
                    path,
                });
            }
            Ok(true)
        },
        "preparing native boot source",
        false,
    )
}

/// Release still-owned fields. Does not undo the process selection or report
/// any boot outcome. A detached FD must be set to -1 before calling this.
///
/// # Safety
/// `source` must be null or a valid output whose still-owned fields came from
/// prepare and have not already been freed/closed outside this ownership rule.
#[no_mangle]
pub unsafe extern "C" fn shorebird_release_boot_source(source: *mut ShorebirdBootSource) {
    if source.is_null() {
        return;
    }
    if unsafe { (*source).struct_size } < std::mem::size_of::<ShorebirdBootSource>() {
        return;
    }
    let source = unsafe { &mut *source };
    #[cfg(unix)]
    if source.fd >= 0 {
        unsafe {
            libc::close(source.fd);
        }
    }
    unsafe {
        free_c_string(source.path);
    }
    *source = ShorebirdBootSource::empty();
}

/// Owned lease of immutable anonymous bytes. Set struct_size before acquire.
/// Never copy an owned lease or dereference private_owner. Bytes remain valid
/// until release, including after selection abort; acquisition does not begin boot.
#[repr(C)]
pub struct ShorebirdBootMemory {
    pub struct_size: libc::size_t,
    pub data: *const u8,
    pub length: u64,
    pub private_owner: *mut libc::c_void,
}
impl ShorebirdBootMemory {
    fn empty() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>(),
            data: std::ptr::null(),
            length: 0,
            private_owner: std::ptr::null_mut(),
        }
    }
}

/// Acquire an existing memory selection without reconstructing or copying it.
/// Stale and non-memory tokens fail with an empty output. Release any existing
/// lease before reusing its output storage.
///
/// # Safety
/// `out` must be null or reference writable storage of its advertised size.
#[no_mangle]
pub unsafe extern "C" fn shorebird_acquire_boot_source_memory(
    selection_id: u64,
    out: *mut ShorebirdBootMemory,
) -> bool {
    log_on_error(
        || {
            anyhow::ensure!(!out.is_null(), "Missing memory output");
            anyhow::ensure!(
                unsafe { (*out).struct_size } >= std::mem::size_of::<ShorebirdBootMemory>(),
                "Truncated memory output"
            );
            unsafe { out.write(ShorebirdBootMemory::empty()) };
            let Some(memory) = crate::native_boot::acquire_memory(selection_id) else {
                return Ok(false);
            };
            let lease = ShorebirdBootMemory {
                struct_size: std::mem::size_of::<ShorebirdBootMemory>(),
                data: memory.bytes().as_ptr(),
                length: memory.bytes().len() as u64,
                private_owner: std::sync::Arc::into_raw(memory).cast_mut().cast(),
            };
            unsafe { out.write(lease) };
            Ok(true)
        },
        "acquiring native boot memory",
        false,
    )
}

/// Release a lease; an already emptied result is harmless. Does not change
/// selection or boot state.
///
/// # Safety
/// `memory` must be null or a valid output whose owner came from acquire and
/// has not been copied, freed or otherwise changed outside this ownership rule.
#[no_mangle]
pub unsafe extern "C" fn shorebird_release_boot_source_memory(memory: *mut ShorebirdBootMemory) {
    if memory.is_null() {
        return;
    }
    if unsafe { (*memory).struct_size } < std::mem::size_of::<ShorebirdBootMemory>() {
        return;
    }
    let memory = unsafe { &mut *memory };
    if !memory.private_owner.is_null() {
        unsafe {
            drop(std::sync::Arc::from_raw(
                memory
                    .private_owner
                    .cast::<crate::native_cache::VerifiedMemory>(),
            ));
        }
    }
    *memory = ShorebirdBootMemory::empty();
}

/// Record a breadcrumb immediately before a loader can execute instructions.
/// A stale token returns false and must never be loaded.
#[no_mangle]
pub extern "C" fn shorebird_begin_boot_source(selection_id: u64) -> bool {
    log_on_error(
        || crate::native_boot::begin(selection_id),
        "beginning native boot source",
        false,
    )
}

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum ShorebirdBootSourceFailure {
    SHOREBIRD_BOOT_SOURCE_RETRYABLE = 0,
    SHOREBIRD_BOOT_SOURCE_INVALID_IMAGE = 1,
}

/// Refuse a selected source and freeze BASE. Only concrete invalid-image
/// evidence justifies INVALID_IMAGE; ambiguous platform loader errors retry.
#[no_mangle]
pub extern "C" fn shorebird_abort_boot_source(selection_id: u64, failure: u32) -> bool {
    log_on_error(
        || crate::native_boot::abort(selection_id, failure),
        "aborting native boot source",
        false,
    )
}

#[cfg(test)]
mod native_source_tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn rejects_truncated_options_and_output_without_touching_adjacent_memory() {
        crate::testing_reset_config();
        let size_only = std::mem::size_of::<usize>();
        assert!(!unsafe {
            shorebird_init_with_options(
                std::ptr::null(),
                FileCallbacks::new(),
                std::ptr::null(),
                (&size_only as *const usize).cast(),
            )
        });
        assert!(!unsafe {
            shorebird_prepare_boot_source((&size_only as *const usize).cast_mut().cast())
        });
        assert!(!unsafe {
            shorebird_acquire_boot_source_memory(1, (&size_only as *const usize).cast_mut().cast())
        });
        unsafe {
            shorebird_release_boot_source_memory((&size_only as *const usize).cast_mut().cast());
            shorebird_release_boot_source((&size_only as *const usize).cast_mut().cast());
        }
        assert_eq!(size_only, std::mem::size_of::<usize>());
        assert!(crate::config::with_config(|_| Ok(())).is_err());
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn failed_prepare_resets_valid_outputs_and_release_is_idempotent() {
        crate::testing_reset_config();
        let mut output = ShorebirdBootSource::empty();
        output.kind = 999;
        output.selection_id = 42;
        output.image_size = 30;
        assert!(!unsafe { shorebird_prepare_boot_source(&mut output) });
        assert_eq!(output.kind, 0);
        assert_eq!(output.selection_id, 0);
        assert_eq!(output.fd, -1);
        assert!(output.path.is_null());
        unsafe {
            shorebird_release_boot_source(&mut output);
            shorebird_release_boot_source(&mut output);
        }
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn missing_memory_selection_empties_output_and_null_release_is_harmless() {
        crate::testing_reset_config();
        let mut output = ShorebirdBootMemory::empty();
        output.length = 99;
        output.data = std::ptr::dangling();
        assert!(!unsafe { shorebird_acquire_boot_source_memory(42, &mut output) });
        assert!(output.data.is_null());
        assert!(output.private_owner.is_null());
        assert_eq!(output.length, 0);
        assert!(!unsafe { shorebird_acquire_boot_source_memory(42, std::ptr::null_mut()) });
        unsafe {
            shorebird_release_boot_source_memory(&mut output);
            shorebird_release_boot_source_memory(&mut output);
            shorebird_release_boot_source_memory(std::ptr::null_mut());
        }
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn repeated_base_prepare_reuses_identity_and_release_does_not_begin_boot() {
        crate::testing_reset_config();
        let directory = tempfile::tempdir().unwrap();
        crate::native_boot::initialize(
            crate::AppConfig {
                app_storage_dir: directory.path().to_str().unwrap().to_owned(),
                code_cache_dir: directory.path().to_str().unwrap().to_owned(),
                release_version: "test".to_owned(),
                original_libapp_paths: vec![directory
                    .path()
                    .join("lib/arch/libapp.so")
                    .to_str()
                    .unwrap()
                    .to_owned()],
            },
            FileCallbacks::new(),
            "app_id: test".to_owned(),
            crate::native_boot::NativeOptions::default(),
        )
        .unwrap();
        let mut first = ShorebirdBootSource::empty();
        let mut second = ShorebirdBootSource::empty();
        assert!(unsafe { shorebird_prepare_boot_source(&mut first) });
        assert!(unsafe { shorebird_prepare_boot_source(&mut second) });
        assert_ne!(first.selection_id, 0);
        assert_eq!(first.selection_id, second.selection_id);
        assert_eq!(first.kind, 0);
        assert_eq!(first.patch_number, 0);
        assert_eq!(first.fd, -1);
        unsafe {
            shorebird_release_boot_source(&mut first);
            shorebird_release_boot_source(&mut second);
        }
        assert!(crate::with_state(|s| Ok(s.currently_booting_patch().is_none())).unwrap());
        crate::testing_reset_config();
    }
}
