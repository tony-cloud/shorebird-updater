import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:mocktail/mocktail.dart';
import 'package:shorebird_code_push/shorebird_code_push.dart';
import 'package:shorebird_code_push/src/generated/selection_bindings.g.dart';
import 'package:shorebird_code_push/src/updater.dart';
import 'package:test/test.dart';

class _MockSelectionBindings extends Mock implements SelectionBindings {}

Map<String, dynamic> identity(String epoch, {int? patch = 2}) => {
      'epoch': epoch,
      'digest': epoch == '0' ? null : 'a' * 64,
      'variant_id': patch == null ? 'free' : 'pro',
      'license_type': patch == null ? 'free' : 'pro',
      'patch_number': patch?.toString(),
    };

Map<String, dynamic> snapshot() => {
      'version': 2,
      'current': identity('11'),
      'accepted': identity('9223372036854775807'),
      'next_boot': {
        'variant_id': 'free',
        'license_type': 'free',
        'patch_number': null,
        'reason': 'expired',
      },
      'restart_required': true,
    };

void main() {
  group(VariantSelectionStatus, () {
    test('preserves full epoch precision and paid authorization on base', () {
      final status = VariantSelectionStatus.fromJson(snapshot());
      expect(status.current.epoch, BigInt.from(11));
      expect(status.accepted.epoch, BigInt.parse('9223372036854775807'));
      expect(status.accepted.patchNumber, 2);
      expect(status.nextBoot.patchNumber, isNull);
      expect(status.nextBoot.variantId, 'free');
      expect(status.nextBoot.reason, 'expired');
      expect(status.restartRequired, isTrue);
    });

    test('rejects noncanonical epochs and content numbers', () {
      for (final epoch in ['-1', '01', '9223372036854775808']) {
        expect(
          () => VariantSelection.fromJson(identity(epoch)),
          throwsFormatException,
        );
      }
      final invalid = identity('11')..['patch_number'] = '2147483648';
      expect(
        () => VariantSelection.fromJson(invalid),
        throwsFormatException,
      );
      final invalidDigest = identity('0')..['digest'] = 'a' * 64;
      expect(
        () => VariantSelection.fromJson(invalidDigest),
        throwsFormatException,
      );
    });
  });

  group('additive status FFI', () {
    late SelectionBindings originalBindings;
    late bool Function(String) originalProbe;
    late _MockSelectionBindings bindings;
    const updater = Updater();

    setUpAll(() {
      registerFallbackValue(Pointer<Char>.fromAddress(0));
    });

    setUp(() {
      originalBindings = Updater.selectionBindings;
      originalProbe = Updater.supportsSymbol;
      bindings = _MockSelectionBindings();
      Updater.selectionBindings = bindings;
      Updater.supportsSymbol = (_) => true;
    });

    tearDown(() {
      Updater.selectionBindings = originalBindings;
      Updater.supportsSymbol = originalProbe;
    });

    void returnsString(String value, {bool status = false}) {
      final pointer = value.toNativeUtf8().cast<Char>();
      if (status) {
        when(bindings.shorebird_selection_status_json).thenReturn(pointer);
      } else {
        when(bindings.shorebird_installation_id).thenReturn(pointer);
      }
      when(() => bindings.shorebird_free_status_string(pointer))
          .thenAnswer((_) {
        malloc.free(pointer);
      });
    }

    test('older engines return null without calling missing functions', () {
      Updater.supportsSymbol = (_) => false;
      expect(updater.installationId(), isNull);
      expect(updater.selectionStatus(), isNull);
      verifyZeroInteractions(bindings);
    });

    test('missing deallocator is detected before allocation', () {
      Updater.supportsSymbol = (name) => name != 'shorebird_free_status_string';
      expect(updater.installationId(), isNull);
      expect(updater.selectionStatus(), isNull);
      verifyZeroInteractions(bindings);
    });

    test('copies and frees installation identity', () {
      returnsString('installation-routing-id');
      expect(updater.installationId(), 'installation-routing-id');
      verify(() => bindings.shorebird_free_status_string(any())).called(1);
    });

    test('copies and frees atomic selection status', () {
      returnsString(jsonEncode(snapshot()), status: true);
      expect(updater.selectionStatus()!.restartRequired, isTrue);
      verify(() => bindings.shorebird_free_status_string(any())).called(1);
    });

    test('malformed JSON is freed before parsing fails', () {
      returnsString('{malformed', status: true);
      expect(updater.selectionStatus, throwsFormatException);
      verify(() => bindings.shorebird_free_status_string(any())).called(1);
    });

    test('v1 null status never calls the deallocator', () {
      when(bindings.shorebird_selection_status_json).thenReturn(nullptr);
      expect(updater.selectionStatus(), isNull);
      verifyNever(() => bindings.shorebird_free_status_string(any()));
    });
  });
}
