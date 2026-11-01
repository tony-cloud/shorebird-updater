import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:meta/meta.dart';
import 'package:shorebird_code_push/src/generated/selection_bindings.g.dart'
    show SelectionBindings;
import 'package:shorebird_code_push/src/generated/updater_bindings.g.dart';
import 'package:shorebird_code_push/src/selection_status.dart';
import 'package:shorebird_code_push/src/shorebird_updater.dart';

/// {@template updater}
/// A wrapper around the generated [UpdaterBindings] that, when necessary,
/// translates ffi types into easier to use Dart types.
/// {@endtemplate}
class Updater {
  /// {@macro updater}
  const Updater();

  /// The ffi bindings to the Updater library.
  @visibleForTesting
  static UpdaterBindings bindings = UpdaterBindings(
    ffi.DynamicLibrary.process(),
  );

  /// Additive selection bindings, generated separately to preserve the legacy
  /// bindings and their independently shipped ABI.
  @visibleForTesting
  static SelectionBindings selectionBindings = SelectionBindings(
    ffi.DynamicLibrary.process(),
  );

  /// Availability probe for additive symbols missing on older engines.
  @visibleForTesting
  static bool Function(String) supportsSymbol =
      ffi.DynamicLibrary.process().providesSymbol;

  String? _readString(String symbol, Pointer<Char> Function() read) {
    if (!supportsSymbol(symbol) ||
        !supportsSymbol('shorebird_free_status_string')) {
      return null;
    }
    final pointer = read();
    if (pointer == nullptr) return null;
    try {
      return pointer.cast<Utf8>().toDartString();
    } finally {
      selectionBindings.shorebird_free_status_string(pointer);
    }
  }

  /// Existing routing ID; null on older engines or unavailable state.
  String? installationId() => _readString(
        'shorebird_installation_id',
        selectionBindings.shorebird_installation_id,
      );

  /// Atomic v2 status; null on older engines, v1 or unavailable state.
  VariantSelectionStatus? selectionStatus() {
    final json = _readString(
      'shorebird_selection_status_json',
      selectionBindings.shorebird_selection_status_json,
    );
    return json == null
        ? null
        : VariantSelectionStatus.fromJson(
            jsonDecode(json) as Map<String, dynamic>,
          );
  }

  /// The currently active patch number.
  int currentPatchNumber() => bindings.shorebird_current_boot_patch_number();

  /// The next patch number that will be loaded. Will be the same as
  /// currentPatchNumber if no new patch is available.
  int nextPatchNumber() => bindings.shorebird_next_boot_patch_number();

  /// Whether a new patch is available for download.
  bool checkForDownloadableUpdate({UpdateTrack? track}) =>
      bindings.shorebird_check_for_downloadable_update(
        track == null ? ffi.nullptr : track.name.toNativeUtf8().cast<Char>(),
      );

  /// Overrides the generated per-install device id sent in patch checks.
  bool setDeviceIdOverride(String deviceId) {
    final nativeDeviceId = deviceId.toNativeUtf8();
    try {
      return bindings.shorebird_set_device_id_override(
        nativeDeviceId.cast<Char>(),
      );
    } finally {
      malloc.free(nativeDeviceId);
    }
  }

  /// Downloads the latest patch, if available and returns an [UpdateResult]
  /// to indicate whether the update was successful.
  Pointer<UpdateResult> update({UpdateTrack? track}) =>
      bindings.shorebird_update_with_result(
        track == null ? ffi.nullptr : track.name.toNativeUtf8().cast<Char>(),
      );

  /// Frees an update result allocated by the updater.
  void freeUpdateResult(Pointer<UpdateResult> ptr) =>
      bindings.shorebird_free_update_result(ptr);
}
