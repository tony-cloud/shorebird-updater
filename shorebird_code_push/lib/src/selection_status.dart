/// A process-pinned or accepted variant authorization identity.
///
/// Epochs order authorization; patch numbers only identify immutable content.
/// These values are routing/status information and do not grant entitlement.
class VariantSelection {
  /// Creates a variant selection identity.
  const VariantSelection({
    required this.epoch,
    required this.digest,
    required this.variantId,
    required this.licenseType,
    required this.patchNumber,
  });

  /// Parses an updater status identity without losing 64-bit epoch precision.
  factory VariantSelection.fromJson(Map<String, dynamic> json) {
    final epochText = json['epoch'] as String;
    final epoch = BigInt.parse(epochText);
    if (!RegExp(r'^(0|[1-9][0-9]*)$').hasMatch(epochText) ||
        epoch > BigInt.parse('9223372036854775807')) {
      throw const FormatException('Invalid selection epoch');
    }
    final digest = json['digest'] as String?;
    if ((epoch == BigInt.zero) != (digest == null) ||
        (digest != null && !RegExp(r'^[a-f0-9]{64}$').hasMatch(digest))) {
      throw const FormatException('Invalid selection digest');
    }
    return VariantSelection(
      epoch: epoch,
      digest: digest,
      variantId: json['variant_id'] as String,
      licenseType: json['license_type'] as String,
      patchNumber: _patchNumber(json['patch_number']),
    );
  }

  /// Accepted epoch, or zero when no authorization is available.
  final BigInt epoch;

  /// Stable descriptor digest, or null with epoch zero.
  final String? digest;

  /// Effective variant for current content, or the accepted grant's variant.
  final String variantId;

  /// Effective license for current content, or the accepted grant's license.
  final String licenseType;

  /// Immutable content number; null means bundled free base.
  final int? patchNumber;
}

/// The effective content selected for the next cold launch.
class VariantActivation {
  /// Creates a next-launch activation status.
  const VariantActivation({
    required this.variantId,
    required this.licenseType,
    required this.patchNumber,
    required this.reason,
  });

  /// Parses an updater activation status.
  factory VariantActivation.fromJson(Map<String, dynamic> json) =>
      VariantActivation(
        variantId: json['variant_id'] as String,
        licenseType: json['license_type'] as String,
        patchNumber: _patchNumber(json['patch_number']),
        reason: json['reason'] as String,
      );

  /// Effective next-launch variant, including free when falling back to base.
  final String variantId;

  /// Effective next-launch license.
  final String licenseType;

  /// Next content number, or null for bundled base.
  final int? patchNumber;

  /// One of ready, selected_base, expired, not_yet_valid,
  /// content_unavailable, quarantined, or no_authorization.
  /// Readiness still requires successful key resolution at cold launch.
  final String reason;
}

/// An atomic snapshot of running, accepted and next-launch variant state.
class VariantSelectionStatus {
  /// Creates a selection status snapshot.
  const VariantSelectionStatus({
    required this.current,
    required this.accepted,
    required this.nextBoot,
    required this.restartRequired,
  });

  /// Parses a protocol-2 status snapshot.
  factory VariantSelectionStatus.fromJson(Map<String, dynamic> json) {
    if (json['version'] != 2) {
      throw const FormatException('Unsupported selection status version');
    }
    return VariantSelectionStatus(
      current: VariantSelection.fromJson(
        json['current'] as Map<String, dynamic>,
      ),
      accepted: VariantSelection.fromJson(
        json['accepted'] as Map<String, dynamic>,
      ),
      nextBoot: VariantActivation.fromJson(
        json['next_boot'] as Map<String, dynamic>,
      ),
      restartRequired: json['restart_required'] as bool,
    );
  }

  /// Authorization/content frozen for this process, including later engines.
  final VariantSelection current;

  /// Latest accepted grant; expiry or missing keys do not lower its epoch.
  final VariantSelection accepted;

  /// Effective next cold-launch content after lease/cache checks.
  final VariantActivation nextBoot;

  /// Whether the process must restart to adopt the accepted authorization or
  /// effective content. Can be true when both content numbers are identical.
  final bool restartRequired;
}

int? _patchNumber(Object? value) {
  if (value == null) return null;
  final text = value as String;
  final number = int.parse(text);
  if (!RegExp(r'^[1-9][0-9]*$').hasMatch(text) || number > 2147483647) {
    throw const FormatException('Invalid selection content number');
  }
  return number;
}
