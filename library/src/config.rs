// This file handles the global config for the updater library.
use crate::network::NetworkHooks;

use crate::updater::AppConfig;
use crate::yaml::{PatchResponseVerificationMode, PatchVerificationMode, YamlConfig};
use crate::{ExternalFileProvider, UpdateError};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Mutex,
};

static CHECKED_NATIVE_ONLY: AtomicBool = AtomicBool::new(false);
static SELECTION_V2_ONLY: AtomicBool = AtomicBool::new(false);
pub(crate) fn require_selection_v2_initialization() {
    SELECTION_V2_ONLY.store(true, Ordering::Release);
}
// A key-refused interpreter boot runs BASE for the remainder of this process,
// even if clearing its durable breadcrumb fails. Never promote that breadcrumb
// from a later engine or a direct launch-report call.
#[repr(u8)]
enum LaunchOutcome {
    Pending,
    Completed,
    Deferred,          // Refused source; bookkeeping has not safely cleared the breadcrumb.
    DeferredPersisted, // BASE is running; ordinary updates may proceed.
}
static LAUNCH_OUTCOME: AtomicU8 = AtomicU8::new(LaunchOutcome::Pending as u8);

pub(crate) fn launch_deferred() -> bool {
    let outcome = LAUNCH_OUTCOME.load(Ordering::Acquire);
    outcome == LaunchOutcome::Deferred as u8 || outcome == LaunchOutcome::DeferredPersisted as u8
}

pub(crate) fn ensure_launch_deferral_resolved() -> Result<()> {
    anyhow::ensure!(
        LAUNCH_OUTCOME.load(Ordering::Acquire) != LaunchOutcome::Deferred as u8,
        "Interpreter launch deferral has unresolved bookkeeping"
    );
    Ok(())
}

pub(crate) fn mark_launch_deferral_persisted() {
    LAUNCH_OUTCOME.store(LaunchOutcome::DeferredPersisted as u8, Ordering::Release);
}

// Outcome writes are serialized by with_config, alongside boot bookkeeping.
pub(crate) fn begin_launch() {
    LAUNCH_OUTCOME.store(LaunchOutcome::Pending as u8, Ordering::Release);
}

pub(crate) fn complete_launch() {
    LAUNCH_OUTCOME.store(LaunchOutcome::Completed as u8, Ordering::Release);
}

pub(crate) fn defer_launch() -> Result<()> {
    anyhow::ensure!(
        LAUNCH_OUTCOME.load(Ordering::Acquire) != LaunchOutcome::Completed as u8,
        "Cannot defer a completed launch"
    );
    if !launch_deferred() {
        LAUNCH_OUTCOME.store(LaunchOutcome::Deferred as u8, Ordering::Release);
    }
    set_running_patch_number(None);
    Ok(())
}

// cbindgen looks for const, ignore these so it doesn't warn about them.

/// cbindgen:ignore
const DEFAULT_BASE_URL: &str = "http://localhost:8080";

/// cbindgen:ignore
const DEFAULT_CHANNEL: &str = "stable";

fn global_config() -> &'static Mutex<Option<UpdateConfig>> {
    static INSTANCE: OnceCell<Mutex<Option<UpdateConfig>>> = OnceCell::new();
    INSTANCE.get_or_init(|| Mutex::new(None))
}

/// Session-scoped patch number this process is using. Set by
/// `report_launch_start` from the next-boot patch at that moment, read
/// by `updater::running_patch()` (surfaced to Dart as
/// `shorebird_current_boot_patch_number`). Lives outside the on-disk
/// `PatchesState` because it tracks running state, not bootable-patch
/// metadata: it must survive a server-driven rollback of the running
/// patch (the process is still using it) and must reset to `None` on
/// every fresh process start. `report_launch_start` is called by
/// flutter_engine before `dart:ffi` is available, so the `None` window
/// before launch start is not observable from Dart.
fn global_running_patch() -> &'static Mutex<Option<usize>> {
    static INSTANCE: OnceCell<Mutex<Option<usize>>> = OnceCell::new();
    INSTANCE.get_or_init(|| Mutex::new(None))
}

pub fn running_patch_number() -> Option<usize> {
    *global_running_patch()
        .lock()
        .expect("Failed to acquire running_patch lock.")
}

pub fn set_running_patch_number(patch_number: Option<usize>) {
    *global_running_patch()
        .lock()
        .expect("Failed to acquire running_patch lock.") = patch_number;
}

/// Unit tests should call this to reset the config between tests.
/// Also exposed (via the `test-hooks` Cargo feature) to the
/// `library_test_hooks` cdylib so Dart-side integration tests can reset
/// state between scenarios without spawning a subprocess.
#[cfg(any(test, feature = "test-hooks"))]
pub fn testing_reset_config() {
    // A flush left over from the last test would read and send this one's
    // queue.
    crate::updater::testing_wait_for_event_flushes();
    with_config_mut(|config| {
        *config = None;
    });
    set_running_patch_number(None);
    crate::encrypted_patch::reset_provider();
    crate::native_boot::reset();
    CHECKED_NATIVE_ONLY.store(false, Ordering::Relaxed);
    SELECTION_V2_ONLY.store(false, Ordering::Relaxed);
    #[cfg(test)]
    crate::security::testing_set_compiled_policy(None);
    LAUNCH_OUTCOME.store(LaunchOutcome::Pending as u8, Ordering::Relaxed);
}

pub fn check_initialized_and_call<F, R>(
    f: F,
    maybe_config: &Option<UpdateConfig>,
) -> anyhow::Result<R>
where
    F: FnOnce(&UpdateConfig) -> anyhow::Result<R>,
{
    match maybe_config {
        Some(config) => f(config),
        None => anyhow::bail!(UpdateError::ConfigNotInitialized),
    }
}

pub fn with_config<F, R>(f: F) -> anyhow::Result<R>
where
    F: FnOnce(&UpdateConfig) -> anyhow::Result<R>,
{
    // expect() here should be OK, it's job is to propagate a panic across
    // threads if the lock is poisoned.
    let lock = global_config()
        .lock()
        .expect("Failed to acquire updater lock.");
    check_initialized_and_call(f, &lock)
}

pub fn with_config_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut Option<UpdateConfig>) -> R,
{
    let mut lock = global_config()
        .lock()
        .expect("Failed to acquire updater lock.");
    f(&mut lock)
}

// The config passed into init.  This is immutable once set and copyable.
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    pub(crate) selection_scope: Option<crate::selection_v2::ReleaseScope>,
    pub(crate) selection_baseline: Option<Box<dyn ExternalFileProvider>>,
    pub(crate) native_options: crate::native_boot::NativeOptions,
    pub storage_dir: PathBuf,
    pub download_dir: PathBuf,
    pub auto_update: bool,
    pub channel: String,
    pub app_id: String,
    pub release_version: String,
    pub libapp_path: PathBuf,
    pub base_url: String,
    pub network_hooks: NetworkHooks,
    pub file_provider: Box<dyn ExternalFileProvider>,
    pub patch_public_key: Option<String>,
    pub patch_decryption_key_provider: Option<crate::c_api::engine::PatchDecryptionKeyProvider>,
    pub patch_decryption_key_provider_v2:
        Option<crate::c_api::engine::PatchDecryptionKeyProviderV2>,
    pub patch_verification: PatchVerificationMode,
    pub patch_response_verification: PatchResponseVerificationMode,
}

/// Returns Ok if the config was set successfully, Err if it was already set.
pub fn set_config(
    app_config: AppConfig,
    file_provider: Box<dyn ExternalFileProvider>,
    libapp_path: PathBuf,
    yaml: &YamlConfig,
    network_hooks: NetworkHooks,
) -> Result<()> {
    set_config_with_native_options(
        app_config,
        file_provider,
        libapp_path,
        yaml,
        network_hooks,
        crate::native_boot::NativeOptions::default(),
        false,
    )
}

pub(crate) fn set_config_with_native_options(
    app_config: AppConfig,
    file_provider: Box<dyn ExternalFileProvider>,
    libapp_path: PathBuf,
    yaml: &YamlConfig,
    network_hooks: NetworkHooks,
    native_options: crate::native_boot::NativeOptions,
    checked: bool,
) -> Result<()> {
    set_config_with_binding(
        app_config,
        file_provider,
        libapp_path,
        yaml,
        network_hooks,
        native_options,
        checked,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn set_config_with_binding(
    app_config: AppConfig,
    file_provider: Box<dyn ExternalFileProvider>,
    libapp_path: PathBuf,
    yaml: &YamlConfig,
    network_hooks: NetworkHooks,
    native_options: crate::native_boot::NativeOptions,
    checked: bool,
    selection_scope: Option<crate::selection_v2::ReleaseScope>,
    selection_baseline: Option<Box<dyn ExternalFileProvider>>,
) -> Result<()> {
    // Security admission precedes everything else: a refused hardened
    // configuration publishes no config, so no key is requested and no patch
    // is activated (the engine continues on the bundled base). Every entry
    // point (v1, checked native, v2) passes through here, so none can serve
    // as a weaker retry path.
    let policy = crate::security::compiled();
    let admitted = crate::security::admit(&policy, yaml)?;
    // Hardened only: the signed build manifest, the loaded engine module and
    // the package identity must match (P3). Like admission, a failure
    // publishes nothing; legacy returns immediately.
    crate::integrity::check(&policy, &yaml.build_manifest, &libapp_path)?;
    shorebird_debug!("Security profile: {}", policy.profile.as_str());
    if policy.development_exceptions {
        shorebird_warn!(
            "DEVELOPMENT-ONLY hardened updater: loopback HTTP is allowed. Never ship this build."
        );
    }
    with_config_mut(|config: &mut Option<UpdateConfig>| {
        anyhow::ensure!(
            !SELECTION_V2_ONLY.load(Ordering::Acquire) || selection_scope.is_some(),
            "A v2 initialization attempt cannot fall back to a v1 updater"
        );
        if !checked && CHECKED_NATIVE_ONLY.load(Ordering::Relaxed) {
            bail!("A checked native initialization is required after encrypted native initialization was attempted");
        }
        if config.is_some() {
            // This previously returned an error, but this happens regularly
            // with apps that use Firebase Messaging, and logging it as an error
            // has caused confusion.
            bail!("Updater already initialized, ignoring second shorebird_init call.");
        }

        let mut code_cache_path = std::path::PathBuf::from(&app_config.code_cache_dir);
        code_cache_path.push("downloads");
        let download_dir = code_cache_path;

        let selection_baseline = if selection_scope
            .as_ref()
            .is_some_and(|s| s.runtime_profile == "native-aot")
        {
            None
        } else {
            selection_baseline
        };
        let new_config = UpdateConfig {
            selection_scope,
            selection_baseline,
            native_options,
            storage_dir: std::path::PathBuf::from(app_config.app_storage_dir),
            download_dir,
            channel: yaml
                .channel
                .as_deref()
                .unwrap_or(DEFAULT_CHANNEL)
                .to_owned(),
            auto_update: yaml.auto_update.unwrap_or(true),
            app_id: yaml.app_id.to_string(),
            release_version: app_config.release_version.to_string(),
            libapp_path,
            base_url: yaml
                .base_url
                .as_deref()
                .unwrap_or(DEFAULT_BASE_URL)
                .to_owned(),
            network_hooks,
            file_provider,
            patch_public_key: yaml.patch_public_key.to_owned(),
            patch_decryption_key_provider: crate::encrypted_patch::provider(),
            patch_decryption_key_provider_v2: crate::encrypted_patch::provider_v2(),
            patch_verification: admitted.patch_verification,
            patch_response_verification: admitted.patch_response_verification,
        };
        if CHECKED_NATIVE_ONLY.load(Ordering::Relaxed)
            && !new_config.native_options.encrypted(&new_config)
        {
            bail!("Encrypted native initialization must complete before this updater can be used");
        }
        if let Some(scope) = &new_config.selection_scope {
            scope.validate()?;
            anyhow::ensure!(
                checked
                    && scope.app_id == new_config.app_id
                    && scope.release_version == new_config.release_version
                    && scope.platform == current_platform()
                    && scope.arch == current_arch(),
                "V2 installed release identity mismatch"
            );
            anyhow::ensure!(
                new_config.patch_verification == PatchVerificationMode::Strict
                    && new_config.patch_response_verification
                        == PatchResponseVerificationMode::Required
                    && new_config.patch_public_key.is_some(),
                "V2 requires pinned signatures and strict boot verification"
            );
            anyhow::ensure!(
                new_config.patch_decryption_key_provider.is_none(),
                "V2 cannot use legacy transport keys"
            );
            use sha2::{Digest, Sha256};
            let mut base = if scope.runtime_profile == "native-aot" {
                anyhow::ensure!(new_config.patch_decryption_key_provider_v2.is_some() && new_config.native_options.encrypted(&new_config), "Native v2 requires a selection-aware provider and supported sealed FD/verified memory route");
                // Android resolves the actual original libapp.so inside the
                // installed APK; Apple/native keep their existing base stream.
                crate::updater::patch_base(&new_config)?
            } else {
                anyhow::ensure!(
                    new_config.patch_decryption_key_provider_v2.is_none(),
                    "Interpreter v2 owns artifact keys in the engine"
                );
                new_config
                    .selection_baseline
                    .as_ref()
                    .context("V2 requires independently supplied original bytecode baseline")?
                    .open()?
            };
            let mut digest = Sha256::new();
            let mut buffer = [0u8; 8192];
            loop {
                let count = std::io::Read::read(&mut base, &mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            anyhow::ensure!(
                hex::encode(digest.finalize()) == scope.base_artifact_hash,
                "Compiled v2 baseline does not match installed original bytes"
            );
        }
        new_config.native_options.validate()?;
        crate::encrypted_patch::validate_config(&new_config)?;
        shorebird_debug!("Updater configured with: {:?}", new_config);
        // Checked initialization is atomic to every API using with_config.
        // No configuration is published until crash recovery/migration succeed.
        if checked {
            if new_config.native_options.encrypted(&new_config) {
                CHECKED_NATIVE_ONLY.store(true, Ordering::Relaxed);
            }
            crate::updater::handle_prior_boot_failure_for_config(&new_config)?;
            if new_config.native_options.encrypted(&new_config) {
                let mut state = crate::updater::load_state(&new_config)?;
                state.lifecycle_mut().retire_plaintext_installed()?;
            }
        }
        *config = Some(new_config);

        Ok(())
    })
}

// Arch/Platform names need to be kept in sync with the shorebird cli.
pub fn current_arch() -> &'static str {
    #[cfg(target_arch = "x86")]
    static ARCH: &str = "x86";
    #[cfg(target_arch = "x86_64")]
    static ARCH: &str = "x86_64";
    #[cfg(target_arch = "aarch64")]
    static ARCH: &str = "aarch64";
    #[cfg(target_arch = "arm")]
    static ARCH: &str = "arm";
    ARCH
}

pub fn current_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    static PLATFORM: &str = "macos";
    #[cfg(target_os = "linux")]
    static PLATFORM: &str = "linux";
    #[cfg(target_os = "windows")]
    static PLATFORM: &str = "windows";
    #[cfg(target_os = "android")]
    static PLATFORM: &str = "android";
    #[cfg(target_os = "ios")]
    static PLATFORM: &str = "ios";
    PLATFORM
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::set_config;
    use crate::{network::NetworkHooks, testing_reset_config, AppConfig, ExternalFileProvider};
    use anyhow::Result;
    use serial_test::serial;

    #[derive(Debug, Clone)]
    pub struct FakeExternalFileProvider {}
    impl ExternalFileProvider for FakeExternalFileProvider {
        fn open(&self) -> anyhow::Result<Box<dyn crate::ReadSeek>> {
            Ok(Box::new(std::io::Cursor::new(vec![])))
        }
    }

    fn fake_app_config() -> AppConfig {
        AppConfig {
            app_storage_dir: "/tmp".to_string(),
            code_cache_dir: "/tmp".to_string(),
            release_version: "1.0.0".to_string(),
            original_libapp_paths: vec!["libapp.so".to_string()],
        }
    }

    fn fake_yaml() -> crate::yaml::YamlConfig {
        crate::yaml::YamlConfig {
            app_id: "fake_app_id".to_string(),
            channel: Some("fake_channel".to_string()),
            auto_update: Some(true),
            base_url: Some("fake_base_url".to_string()),
            patch_public_key: None,
            patch_verification: None,
            patch_response_verification: None,
            ..Default::default()
        }
    }

    // These tests are serial because they modify global state.
    #[serial]
    #[test]
    fn set_config_correctly_sets_values() -> Result<()> {
        testing_reset_config();

        set_config(
            AppConfig {
                app_storage_dir: "/app_storage".to_string(),
                code_cache_dir: "/code_cache".to_string(),
                release_version: "1.0.0".to_string(),
                original_libapp_paths: vec!["libapp.so".to_string()],
            },
            Box::new(FakeExternalFileProvider {}),
            "first_path".into(),
            &crate::yaml::YamlConfig {
                app_id: "fake_app_id".to_string(),
                channel: Some("fake_channel".to_string()),
                auto_update: Some(true),
                base_url: Some("fake_base_url".to_string()),
                patch_public_key: Some("patch_public_key".to_string()),
                patch_verification: None,
                patch_response_verification: None,
                ..Default::default()
            },
            NetworkHooks::default(),
        )?;

        let config = super::with_config(|config| Ok(config.clone())).unwrap();
        assert_eq!(config.storage_dir, PathBuf::from("/app_storage"));
        assert_eq!(
            config.download_dir,
            PathBuf::from("/").join("code_cache").join("downloads")
        );
        assert!(config.auto_update);
        assert_eq!(config.channel, "fake_channel");
        assert_eq!(config.app_id, "fake_app_id");
        assert_eq!(config.release_version, "1.0.0");
        assert_eq!(config.libapp_path.to_str(), Some("first_path"));
        assert_eq!(config.base_url, "fake_base_url");
        // We should also validate network hooks here
        assert_eq!(
            config.patch_public_key,
            Some("patch_public_key".to_string())
        );

        Ok(())
    }

    // These tests are serial because they modify global state.
    #[serial]
    #[test]
    fn set_config_defaults_to_open_self_hosted_server() -> Result<()> {
        testing_reset_config();

        let mut yaml = fake_yaml();
        yaml.base_url = None;

        set_config(
            fake_app_config(),
            Box::new(FakeExternalFileProvider {}),
            "first_path".into(),
            &yaml,
            NetworkHooks::default(),
        )?;

        let config = super::with_config(|config| Ok(config.clone())).unwrap();
        assert_eq!(config.base_url, super::DEFAULT_BASE_URL);

        Ok(())
    }

    // These tests are serial because they modify global state.
    #[serial]
    #[test]
    fn set_config_returns_err_on_subsequent_calls() -> Result<()> {
        testing_reset_config();

        assert!(set_config(
            fake_app_config(),
            Box::new(FakeExternalFileProvider {}),
            "first_path".into(),
            &fake_yaml(),
            NetworkHooks::default(),
        )
        .is_ok());

        assert!(set_config(
            fake_app_config(),
            Box::new(FakeExternalFileProvider {}),
            "second_path".into(),
            &fake_yaml(),
            NetworkHooks::default(),
        )
        .is_err());

        let config = super::with_config(|config| Ok(config.clone())).unwrap();
        assert_eq!(config.libapp_path.to_str(), Some("first_path"));

        Ok(())
    }

    mod hardened_admission {
        use super::{fake_app_config, FakeExternalFileProvider};
        use crate::integrity::tests::{
            hardened_with_key, manifest_json, module_entry, signed_hardened_yaml, signed_yaml,
            token, NO_IDENTITY, SEED,
        };
        use crate::integrity::{IntegrityFailure, MANIFEST_KEY};
        use crate::security::tests::{hardened, hardened_yaml_text};
        use crate::security::{testing_set_compiled_policy, CompiledPolicy, SecurityError};
        use crate::yaml::{PatchResponseVerificationMode, PatchVerificationMode, YamlConfig};
        use crate::{network::NetworkHooks, testing_reset_config, InitError};
        use serial_test::serial;

        fn configure(text: &str, checked: bool) -> anyhow::Result<()> {
            super::super::set_config_with_native_options(
                fake_app_config(),
                Box::new(FakeExternalFileProvider {}),
                "libapp.so".into(),
                &YamlConfig::from_yaml(text).map_err(anyhow::Error::msg)?,
                NetworkHooks::default(),
                crate::native_boot::NativeOptions::default(),
                checked,
            )
        }

        fn refusal(result: anyhow::Result<()>) -> SecurityError {
            result
                .unwrap_err()
                .downcast::<SecurityError>()
                .expect("a typed security refusal")
        }

        fn published() -> bool {
            super::super::with_config(|_| Ok(())).is_ok()
        }

        #[serial]
        #[test]
        fn hardened_updater_boots_the_hardened_build_output() {
            testing_reset_config();
            testing_set_compiled_policy(Some(hardened_with_key()));
            // The YAML omits nothing the floor needs; drop the explicit
            // verification keys to show the floor, not the YAML, decides.
            let text = hardened_yaml_text()
                .replace("patch_verification: strict\n", "")
                .replace("patch_response_verification: required\n", "");
            // P3: as built, i.e. with the signed build manifest bound to
            // this process's module.
            configure(&signed_yaml(&text), false).unwrap();
            let config = super::super::with_config(|c| Ok(c.clone())).unwrap();
            testing_reset_config();
            assert_eq!(config.patch_verification, PatchVerificationMode::Strict);
            assert_eq!(
                config.patch_response_verification,
                PatchResponseVerificationMode::Required
            );
            assert_eq!(config.base_url, "https://updates.example.com");
        }

        #[serial]
        #[test]
        fn refused_configuration_publishes_nothing_on_any_entry_point() {
            // Each tamper is refused by admission (the parser's own
            // required-needs-key/strict rules are removed from the way).
            let unpaired =
                hardened_yaml_text().replace("patch_response_verification: required\n", "");
            let tampered = [
                unpaired.replace("patch_public_key: AQID\n", ""),
                hardened_yaml_text().replace("security_profile: hardened\n", ""),
                unpaired.replace("strict", "install_only"),
                hardened_yaml_text().replace("required", "optional"),
                hardened_yaml_text().replace("https://", "http://"),
                hardened_yaml_text().replace(
                    "security_contract_version: 1",
                    "security_contract_version: 2",
                ),
                hardened_yaml_text().replace("toolchain_id: sha256:7", "toolchain_id: sha256:8"),
                "app_id: app\nbase_url: https://updates.example.com\npatch_public_key: AQID"
                    .to_string(),
            ];
            for text in &tampered {
                for checked in [false, true] {
                    testing_reset_config();
                    testing_set_compiled_policy(Some(hardened()));
                    refusal(configure(text, checked));
                    // Nothing is published, so no API can request a key,
                    // report a launch or select a patch.
                    assert!(!published(), "{text}");
                    assert!(crate::updater::next_boot_patch().is_err());
                }
            }
            testing_reset_config();
        }

        #[serial]
        #[test]
        fn init_reports_a_typed_security_refusal() {
            testing_reset_config();
            testing_set_compiled_policy(Some(hardened()));
            let tmp = tempfile::tempdir().unwrap();
            let result = crate::init(
                crate::AppConfig {
                    app_storage_dir: tmp.path().to_str().unwrap().to_string(),
                    code_cache_dir: tmp.path().to_str().unwrap().to_string(),
                    release_version: "1.0.0+1".to_string(),
                    original_libapp_paths: vec![tmp
                        .path()
                        .join("lib/arch/libapp.so")
                        .to_str()
                        .unwrap()
                        .to_string()],
                },
                Box::new(FakeExternalFileProvider {}),
                "app_id: app\nbase_url: http://localhost:8080",
            );
            testing_reset_config();
            assert!(matches!(result, Err(InitError::SecurityPolicy(_))));
        }

        #[serial]
        #[test]
        fn legacy_updater_refuses_hardened_yaml_but_keeps_legacy_defaults() {
            testing_reset_config();
            testing_set_compiled_policy(Some(CompiledPolicy::legacy()));
            assert!(matches!(
                refusal(configure(&hardened_yaml_text(), false)),
                SecurityError::ProfileMismatch { .. }
            ));
            assert!(!published());
            testing_reset_config();
            // Today's legacy shapes (no key, http default origin, install_only)
            // still configure exactly as before.
            configure("app_id: app\npatch_verification: install_only", false).unwrap();
            let config = super::super::with_config(|c| Ok(c.clone())).unwrap();
            testing_reset_config();
            assert_eq!(config.base_url, super::super::DEFAULT_BASE_URL);
            assert_eq!(
                config.patch_verification,
                PatchVerificationMode::InstallOnly
            );
            assert_eq!(
                config.patch_response_verification,
                PatchResponseVerificationMode::Optional
            );
            assert_eq!(config.patch_public_key, None);
        }

        fn integrity_refusal(result: anyhow::Result<()>) -> IntegrityFailure {
            result
                .unwrap_err()
                .downcast::<IntegrityFailure>()
                .expect("a typed integrity refusal")
        }

        #[serial]
        #[test]
        fn tampered_installs_publish_nothing_on_any_entry_point() {
            let signed = signed_hardened_yaml();
            let other_module = module_entry(
                crate::config::current_platform(),
                crate::config::current_arch(),
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            );
            let config = format!("{}\n", hardened_yaml_text());
            let replaced_engine = format!(
                "{config}{MANIFEST_KEY}: {}\n",
                token(&SEED, &manifest_json(&config, &other_module, NO_IDENTITY))
            );
            let cases = [
                // Unsigned (stripped manifest).
                (format!("{}\n", hardened_yaml_text()), "manifest_missing"),
                // Replaced key, consistent with the rest of the YAML.
                (
                    signed.replacen("patch_public_key: AQID", "patch_public_key: BAUG", 1),
                    "config_digest_mismatch",
                ),
                // Replaced origin (still https, so admission alone accepts it).
                (
                    signed.replacen("updates.example.com", "attacker.example.com", 1),
                    "config_digest_mismatch",
                ),
                // Engine/updater module that is not the one the manifest binds.
                (replaced_engine, "module_mismatch"),
                // Signature bytes swapped for another manifest's.
                (
                    {
                        let (head, _) = signed.rsplit_once('.').unwrap();
                        let (_, other_sig) = signed_yaml("app_id: x")
                            .rsplit_once('.')
                            .map(|(h, t)| (h.to_string(), t.to_string()))
                            .unwrap();
                        format!("{head}.{other_sig}")
                    },
                    "manifest_bad_signature",
                ),
            ];
            for (text, code) in &cases {
                for checked in [false, true] {
                    testing_reset_config();
                    testing_set_compiled_policy(Some(hardened_with_key()));
                    assert_eq!(integrity_refusal(configure(text, checked)).code(), *code);
                    assert_eq!(crate::integrity::status(), *code);
                    // Nothing is published: no key provider can be asked,
                    // no launch reported, no patch selected.
                    assert!(!published(), "{code}");
                    assert!(crate::updater::next_boot_patch().is_err());
                }
            }
            testing_reset_config();
            testing_set_compiled_policy(None);
        }

        #[serial]
        #[test]
        fn a_signed_manifest_cannot_lower_the_compiled_floor() {
            // Even a manifest signed by the compiled key does not admit a
            // configuration below the hardened floor: admission runs first.
            for weaker in [
                hardened_yaml_text().replace("https://", "http://"),
                hardened_yaml_text().replace("required", "optional"),
                hardened_yaml_text().replace("security_profile: hardened\n", ""),
            ] {
                testing_reset_config();
                testing_set_compiled_policy(Some(hardened_with_key()));
                refusal(configure(&signed_yaml(&weaker), false));
                assert!(!published());
            }
            testing_reset_config();
            testing_set_compiled_policy(None);
        }

        #[serial]
        #[test]
        fn init_reports_a_typed_integrity_refusal_and_keeps_user_data() {
            testing_reset_config();
            testing_set_compiled_policy(Some(hardened_with_key()));
            let tmp = tempfile::tempdir().unwrap();
            // Existing updater state and downloads from earlier launches.
            let state = tmp.path().join("patches_state.json");
            std::fs::write(&state, b"{\"previous\":true}").unwrap();
            std::fs::create_dir_all(tmp.path().join("downloads")).unwrap();
            let download = tmp.path().join("downloads/1");
            std::fs::write(&download, b"patch bytes").unwrap();
            let tampered = signed_hardened_yaml().replacen("app_id: app", "app_id: other", 1);
            let result = crate::init(
                crate::AppConfig {
                    app_storage_dir: tmp.path().to_str().unwrap().to_string(),
                    code_cache_dir: tmp.path().to_str().unwrap().to_string(),
                    release_version: "1.0.0+1".to_string(),
                    original_libapp_paths: vec![tmp
                        .path()
                        .join("lib/arch/libapp.so")
                        .to_str()
                        .unwrap()
                        .to_string()],
                },
                Box::new(FakeExternalFileProvider {}),
                &tampered,
            );
            testing_reset_config();
            testing_set_compiled_policy(None);
            assert_eq!(result, Err(InitError::Integrity("config_digest_mismatch")));
            // Recovery never deletes user data.
            assert_eq!(std::fs::read(&state).unwrap(), b"{\"previous\":true}");
            assert_eq!(std::fs::read(&download).unwrap(), b"patch bytes");
        }

        #[serial]
        #[test]
        fn legacy_ignores_the_manifest_line_entirely() {
            // A legacy updater never runs the gate, whatever the YAML ends
            // with; legacy configurations behave exactly as before.
            testing_reset_config();
            testing_set_compiled_policy(Some(CompiledPolicy::legacy()));
            configure(
                &format!("app_id: app\n{MANIFEST_KEY}: v1.garbage.garbage\n"),
                false,
            )
            .unwrap();
            assert!(published());
            testing_reset_config();
            testing_set_compiled_policy(None);
        }
    }
}
