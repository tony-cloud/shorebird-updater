//! One immutable process selection; never persisted. Lock ordering is updater
//! operation -> selection -> config/state. No selection/config mutex spans a key
//! callback; never acquire operation under config.
use crate::{
    cache::{
        lifecycle::{BadReason, PatchState},
        UpdaterState,
    },
    config::{self, UpdateConfig},
    native_cache,
};
use anyhow::{ensure, Context, Result};
use std::{
    fs::File,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeOptions {
    pub capability: u32,
    pub max_image_bytes: u64,
}
impl NativeOptions {
    pub(crate) fn validate(self) -> Result<()> {
        ensure!(self.capability <= 1, "Unknown native source capability");
        if self.capability == 1 {
            ensure!(
                cfg!(any(target_os = "linux", target_os = "android")),
                "Sealed FD capability unsupported on this platform"
            );
            if crate::encrypted_patch::provider().is_some() {
                ensure!(
                    self.max_image_bytes > 0,
                    "Encrypted native mode requires a nonzero image budget"
                );
            }
        }
        Ok(())
    }
    pub(crate) fn encrypted(self, config: &UpdateConfig) -> bool {
        self.capability == 1 && config.patch_decryption_key_provider.is_some()
    }
}

#[derive(PartialEq, Eq)]
struct Initialization {
    app: crate::AppConfig,
    yaml: String,
    callbacks: [usize; 4],
    provider: Option<usize>,
    options: NativeOptions,
}
static INITIALIZATION: Mutex<Option<Initialization>> = Mutex::new(None);

pub(crate) fn initialize(
    app: crate::AppConfig,
    callbacks: crate::c_api::engine::FileCallbacks,
    yaml: String,
    options: NativeOptions,
) -> Result<()> {
    crate::logging::init_logging();
    options.validate()?;
    let identity = Initialization {
        app: app.clone(),
        yaml: yaml.clone(),
        callbacks: [
            callbacks.open as usize,
            callbacks.read as usize,
            callbacks.seek as usize,
            callbacks.close as usize,
        ],
        provider: crate::encrypted_patch::provider().map(|p| p as usize),
        options,
    };
    let mut initialized = INITIALIZATION.lock().expect("Native init lock poisoned");
    if let Some(prior) = initialized.as_ref() {
        ensure!(
            *prior == identity,
            "Incompatible repeated native initialization"
        );
        return Ok(());
    }
    // Resolve the same immutable base as legacy initialization. In test builds
    // Android's APK resolver is used by the existing updater tests as well.
    #[cfg(any(target_os = "android", test))]
    let path = crate::android::libapp_path_from_settings(&app.original_libapp_paths)?;
    #[cfg(not(any(target_os = "android", test)))]
    let path = crate::updater::libapp_path_from_settings(&app.original_libapp_paths)?;
    let parsed = crate::yaml::YamlConfig::from_yaml(&yaml).map_err(anyhow::Error::msg)?;
    crate::config::set_config_with_native_options(
        app,
        Box::new(crate::c_api::c_file::CFileProvider {
            file_callbacks: callbacks,
        }),
        path,
        &parsed,
        crate::network::NetworkHooks::default(),
        options,
        true,
    )?;
    *initialized = Some(identity);
    Ok(())
}

pub(crate) fn load_state(c: &UpdateConfig) -> UpdaterState {
    UpdaterState::load_or_new_on_error(
        &c.storage_dir,
        &c.download_dir,
        &c.release_version,
        c.patch_public_key.as_deref(),
        c.patch_verification,
    )
}

struct Selection {
    id: u64,
    patch: Option<usize>,
    expected_state: Option<PatchState>,
    path: Option<PathBuf>,
    file: Option<File>,
    size: u64,
    begun: bool,
    completed: bool,
}
static SELECTION: Mutex<Option<Selection>> = Mutex::new(None);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
fn next_id() -> u64 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    assert_ne!(id, 0, "Native selection ID exhausted");
    id
}
impl Selection {
    fn base() -> Self {
        Self {
            id: next_id(),
            patch: None,
            expected_state: None,
            path: None,
            file: None,
            size: 0,
            begun: false,
            completed: false,
        }
    }
    fn owned(&self) -> Result<OwnedSource> {
        Ok(OwnedSource {
            id: self.id,
            patch: self.patch,
            path: self.path.clone(),
            file: self.file.as_ref().map(duplicate).transpose()?,
            size: self.size,
        })
    }
}
pub(crate) struct OwnedSource {
    pub id: u64,
    pub patch: Option<usize>,
    pub path: Option<PathBuf>,
    pub file: Option<File>,
    pub size: u64,
}
fn duplicate(file: &File) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    #[cfg(not(unix))]
    {
        Ok(file.try_clone()?)
    }
}
pub(crate) fn needs_prepared_route(config: &UpdateConfig) -> bool {
    if config.native_options.encrypted(config) {
        return true;
    }
    let state = load_state(config);
    state
        .lifecycle()
        .pointers()
        .next_boot_patch
        .is_some_and(|n| {
            matches!(
                state.lifecycle().read_state(n),
                Some(PatchState::InstalledEncryptedTransportV1 { .. })
            )
        })
}

pub(crate) fn selection_id() -> Option<u64> {
    SELECTION
        .lock()
        .expect("Native selection lock poisoned")
        .as_ref()
        .map(|s| s.id)
}

fn diagnostic(
    config: &UpdateConfig,
    number: usize,
    error: &anyhow::Error,
    category: Option<&str>,
) -> Result<()> {
    let result = config::with_config(|_| {
        let mut state = load_state(config);
        let mut event = crate::updater::update_failure_event(
            config,
            state.client_id(),
            "native_boot",
            number,
            error,
        );
        if let Some(category) = category {
            event.failure_category = Some(category.to_owned());
        }
        state.queue_event(event)
    });
    if let Err(error) = result {
        shorebird_error!("Could not queue native boot diagnostic: {:#}", error);
    }
    Ok(())
}

/// Every recoverable failure freezes BASE with an identity. Never expose an
/// implicit next-boot selection after crypto or allocation has refused it.
pub(crate) fn prepare() -> Result<OwnedSource> {
    // Fast repeat consumers require no update operation and perform no crypto.
    {
        let mut selection = SELECTION.lock().expect("Native selection lock poisoned");
        if selection.is_some() {
            return export_source(&mut selection);
        }
    }
    let config = config::with_config(|c| Ok(c.clone()))?;
    let result = crate::updater_lock::with_updater_thread_lock(|_| {
        {
            let mut selection = SELECTION.lock().expect("Native selection lock poisoned");
            if selection.is_some() {
                return export_source(&mut selection);
            }
        }
        // Do not retain the selection/config mutex across the application key
        // callback. The operation lock serializes expensive materialization;
        // reentrant/concurrent preparation can freeze BASE without blocking.
        // Publication below then respects whichever source froze first.
        let selected = loop {
            let candidate = config::with_config(|_| {
                let mut state = load_state(&config);
                Ok(state.next_boot_patch().map(|p| {
                    let number = p.number;
                    (p, state.lifecycle().read_state(number), state.client_id())
                }))
            })?;
            let Some((patch_info, state, client_id)) = candidate else {
                break Selection::base();
            };
            let number = patch_info.number;
            if matches!(
                state,
                Some(PatchState::InstalledEncryptedTransportV1 { .. })
            ) && !config.native_options.encrypted(&config)
            {
                // An older/provider-free integration cannot consume this format.
                // Retain it for a capable fresh process; never hash it as code.
                break Selection::base();
            }
            let result: Result<Selection> = (|| {
                if config.native_options.encrypted(&config) {
                    let Some(PatchState::InstalledEncryptedTransportV1 {
                        size,
                        ciphertext_size,
                        ..
                    }) = state.as_ref()
                    else {
                        anyhow::bail!("Encrypted native mode refuses legacy executable state");
                    };
                    // Both authenticated metadata and ciphertext are checked
                    // before calling the application-owned resolver.
                    let patch =
                        crate::response_auth::load_authenticated_boot_patch(&config, number)
                            .context(crate::UpdateError::InvalidSignature)?;
                    let path = native_cache::transport_path(&config, number);
                    let actual = crate::encrypted_patch::validate_ciphertext(
                        &config, &patch, &client_id, &path,
                    )?;
                    ensure!(
                        actual == *ciphertext_size,
                        "Installed ciphertext size mismatch"
                    );
                    ensure!(
                        *size <= config.native_options.max_image_bytes,
                        native_cache::ResourceLimit
                    );
                    let file = native_cache::create_source()?;
                    let (mut file, actual_size) =
                        native_cache::reconstruct(&config, &patch, &client_id, &path, file)?;
                    ensure!(actual_size == *size, crate::UpdateError::CorruptPatch);
                    native_cache::seal_and_verify(&mut file, &patch, actual_size, &config)?;
                    Ok(Selection {
                        id: next_id(),
                        patch: Some(number),
                        expected_state: state.clone(),
                        path: None,
                        file: Some(file),
                        size: actual_size,
                        begun: false,
                        completed: false,
                    })
                } else {
                    ensure!(
                        matches!(state, Some(PatchState::Installed { .. })),
                        "Legacy loader refuses encrypted native cache"
                    );
                    config::with_config(|_| {
                        let mut current = load_state(&config);
                        crate::response_auth::verify_boot_patch(&config, &patch_info)?;
                        current.validate_next_boot_patch()
                    })?;
                    Ok(Selection {
                        id: next_id(),
                        patch: Some(number),
                        expected_state: state.clone(),
                        path: Some(patch_info.path),
                        file: None,
                        size: 0,
                        begun: false,
                        completed: false,
                    })
                }
            })();
            match result {
                Ok(source) => break source,
                Err(error)
                    if error.is::<crate::encrypted_patch::KeyResolutionFailed>()
                        || native_cache::is_resource_error(&error)
                        || error.is::<native_cache::ResourceLimit>() =>
                {
                    let category = if error.is::<crate::encrypted_patch::KeyResolutionFailed>() {
                        "key_resolution_failed"
                    } else {
                        "native_source_unavailable"
                    };
                    diagnostic(&config, number, &error, Some(category))?;
                    break Selection::base();
                }
                Err(error) => {
                    config::with_config(|_| {
                        let mut current = load_state(&config);
                        // Rollback/replacement must not condemn another live candidate.
                        if current.lifecycle().pointers().next_boot_patch == Some(number)
                            && current.lifecycle().read_state(number) == state
                        {
                            current
                                .lifecycle_mut()
                                .mark_bad(number, BadReason::ValidationFailed)?;
                            current.lifecycle_mut().recompute_next_boot()?;
                        }
                        Ok(())
                    })?;
                    diagnostic(&config, number, &error, None)?;
                }
            }
        };
        let mut selection = SELECTION.lock().expect("Native selection lock poisoned");
        if selection.is_none() {
            config::with_config(|_| {
                let current = load_state(&config);
                let still_current = selected.patch.is_none_or(|number| {
                    current.lifecycle().pointers().next_boot_patch == Some(number)
                        && current.lifecycle().read_state(number) == selected.expected_state
                });
                // Publish while still holding the state/config serialization,
                // not in a gap after a successful candidate identity check.
                *selection = Some(if still_current {
                    selected
                } else {
                    Selection::base()
                });
                Ok(())
            })?;
        }
        // A concurrent/reentrant consumer may already have frozen BASE. Never
        // overwrite that process decision after the external callback returns.
        export_source(&mut selection)
    });
    match result {
        Err(error)
            if matches!(
                error.downcast_ref::<crate::UpdateError>(),
                Some(crate::UpdateError::UpdateAlreadyInProgress)
            ) =>
        {
            let mut selection = SELECTION.lock().expect("Native selection lock poisoned");
            if selection.is_none() {
                *selection = Some(Selection::base());
            }
            export_source(&mut selection)
        }
        result => result,
    }
}

fn export_source(selection: &mut Option<Selection>) -> Result<OwnedSource> {
    let source = selection.as_ref().context("Missing process selection")?;
    match source.owned() {
        Ok(owned) => Ok(owned),
        Err(error) if !source.begun => {
            shorebird_error!(
                "Could not duplicate native boot source; freezing BASE: {:#}",
                error
            );
            *selection = Some(Selection::base());
            selection.as_ref().unwrap().owned()
        }
        Err(error) => Err(error), // A running process cannot switch code on FD exhaustion.
    }
}

pub(crate) fn begin(id: u64) -> Result<bool> {
    let mut selection = SELECTION.lock().expect("Native selection lock poisoned");
    let source = selection.as_mut().context("No prepared source")?;
    if source.id != id {
        return Ok(false);
    }
    if source.begun {
        return Ok(true);
    }
    let accepted = config::with_config(|config| {
        let mut state = load_state(config);
        if let Some(number) = source.patch {
            if state.lifecycle().pointers().next_boot_patch != Some(number)
                || state.lifecycle().read_state(number) != source.expected_state
            {
                return Ok(false);
            }
            state.record_boot_start_for_patch(number)?;
        }
        state.set_running_patch(source.patch);
        Ok(true)
    })?;
    if !accepted {
        *selection = Some(Selection::base());
        return Ok(false);
    }
    source.begun = true;
    Ok(true)
}

pub(crate) fn abort(id: u64, failure: u32) -> Result<bool> {
    ensure!(failure <= 1, "Unknown prepared-source failure");
    let mut selection = SELECTION.lock().expect("Native selection lock poisoned");
    let source = selection.as_ref().context("No prepared source")?;
    if source.id != id || source.completed {
        return Ok(false);
    }
    let number = source.patch;
    let expected_state = source.expected_state.clone();
    // Freeze first even if bookkeeping fails. Never execute a refused source.
    *selection = Some(Selection::base());
    config::with_config(|config| {
        let mut state = load_state(config);
        state.set_running_patch(None);
        if let Some(number) = number {
            if failure == 0 {
                state.lifecycle_mut().abort_boot_retryable(number)?;
            } else if state.lifecycle().read_state(number) == expected_state {
                state.record_boot_failure_for_patch(number)?;
            } else {
                state.lifecycle_mut().abort_boot_retryable(number)?;
            }
            let error = anyhow::anyhow!(if failure == 0 {
                "Native loader refused authenticated source"
            } else {
                "Native loader proved image invalid"
            });
            let mut event = crate::updater::update_failure_event(
                config,
                state.client_id(),
                "native_loader",
                number,
                &error,
            );
            if failure == 1 {
                event.identifier = crate::events::EventType::PatchInstallFailure;
            }
            event.failure_category = Some(
                if failure == 0 {
                    "native_loader_retryable"
                } else {
                    "corrupt_patch"
                }
                .to_owned(),
            );
            state.queue_event(event)?;
        }
        Ok(true)
    })
}

/// Serialize success bookkeeping against begin/abort. Some(None) is an
/// explicit BASE/unbegun selection and must never consume a stale breadcrumb.
pub(crate) fn with_success_guard<F, T>(f: F) -> Result<T>
where
    F: FnOnce(Option<Option<usize>>) -> Result<T>,
{
    let mut selection = SELECTION.lock().expect("Native selection lock poisoned");
    let expected = selection
        .as_ref()
        .map(|source| if source.begun { source.patch } else { None });
    let result = f(expected);
    if let Some(source) = selection
        .as_mut()
        .filter(|source| source.begun && result.is_ok())
    {
        source.completed = true;
    }
    result
}

#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn reset() {
    *SELECTION.lock().expect("Native selection lock poisoned") = None;
    *INITIALIZATION.lock().expect("Native init lock poisoned") = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;
    fn app(tmp: &TempDir) -> crate::AppConfig {
        crate::AppConfig {
            app_storage_dir: tmp.path().to_str().unwrap().to_owned(),
            code_cache_dir: tmp.path().to_str().unwrap().to_owned(),
            release_version: "1".to_owned(),
            original_libapp_paths: vec![tmp
                .path()
                .join("lib/arch/libapp.so")
                .to_str()
                .unwrap()
                .to_owned()],
        }
    }
    #[test]
    #[serial]
    fn checked_init_is_idempotent_and_rejects_incompatible_identity() {
        crate::testing_reset_config();
        let tmp = TempDir::new().unwrap();
        let callbacks = crate::c_api::engine::FileCallbacks::new();
        initialize(
            app(&tmp),
            callbacks,
            "app_id: test".into(),
            NativeOptions::default(),
        )
        .unwrap();
        let prepared = prepare().unwrap();
        initialize(
            app(&tmp),
            callbacks,
            "app_id: test".into(),
            NativeOptions::default(),
        )
        .unwrap();
        assert_eq!(prepare().unwrap().id, prepared.id);
        assert!(initialize(
            app(&tmp),
            callbacks,
            "app_id: changed".into(),
            NativeOptions::default()
        )
        .is_err());
        crate::testing_reset_config();
    }
    #[test]
    #[serial]
    fn unknown_capability_rejected_without_publishing_configuration() {
        crate::testing_reset_config();
        let tmp = TempDir::new().unwrap();
        assert!(initialize(
            app(&tmp),
            crate::c_api::engine::FileCallbacks::new(),
            "app_id: test".into(),
            NativeOptions {
                capability: 2,
                max_image_bytes: 1
            }
        )
        .is_err());
        assert!(config::with_config(|_| Ok(())).is_err());
        crate::testing_reset_config();
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    #[serial]
    fn unsupported_platform_refuses_sealed_capability_even_without_a_provider() {
        crate::testing_reset_config();
        assert!(NativeOptions {
            capability: 1,
            max_image_bytes: 1
        }
        .validate()
        .is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe extern "C" fn unavailable_key(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut u8,
        _: usize,
        _: *mut usize,
    ) -> bool {
        false
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[serial]
    fn failed_secure_migration_exposes_no_config_and_requires_secure_retry() {
        crate::testing_reset_config();
        let tmp = TempDir::new().unwrap();
        UpdaterState::load_or_new_on_error(
            tmp.path(),
            &tmp.path().join("downloads"),
            "1",
            None,
            crate::yaml::PatchVerificationMode::Strict,
        );
        std::fs::write(tmp.path().join("patches"), b"not a directory").unwrap();
        assert!(crate::encrypted_patch::set_provider(Some(unavailable_key)));
        assert!(NativeOptions {
            capability: 1,
            max_image_bytes: 0
        }
        .validate()
        .is_err());
        let options = NativeOptions {
            capability: 1,
            max_image_bytes: 1024,
        };
        let yaml = format!("app_id: test\npatch_public_key: {}\npatch_verification: strict\npatch_response_verification: required", crate::test_utils::response_test_public_key());
        let callbacks = crate::c_api::engine::FileCallbacks::new();
        assert!(initialize(app(&tmp), callbacks, yaml.clone(), options).is_err());
        assert!(config::with_config(|_| Ok(())).is_err());
        assert!(initialize(app(&tmp), callbacks, yaml.clone(), NativeOptions::default()).is_err());
        assert!(crate::init(
            app(&tmp),
            Box::new(crate::c_api::c_file::CFileProvider {
                file_callbacks: callbacks
            }),
            &yaml
        )
        .is_err());
        assert!(config::with_config(|_| Ok(())).is_err());
        std::fs::remove_file(tmp.path().join("patches")).unwrap();
        initialize(app(&tmp), callbacks, yaml, options).unwrap();
        assert!(config::with_config(|_| Ok(())).is_ok());
        crate::testing_reset_config();
    }
}
