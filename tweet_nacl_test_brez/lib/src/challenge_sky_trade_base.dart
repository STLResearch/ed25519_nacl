import 'dart:typed_data';
import 'package:challenge_sky_trade/src/nacl.dart';
import 'package:convert/convert.dart' show hex;

Int64List gf() =>
    Int64List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

const String _base58Alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

Map<String, dynamic> getED25519Key({
  String privateKey,
}) {
  final privKey = Uint8List.fromList(
    hex.decode(
      privateKey,
    ),
  );
  final d = Uint8List(64);
  final p = [gf(), gf(), gf(), gf()];
  final sk = Uint8List.fromList(
    [
      ...Uint8List.fromList(privKey),
      ...Uint8List(32),
    ],
  );
  final pk = Uint8List(32);

  TweetNaclFast.crypto_hash(d, sk);

  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  TweetNaclFast.scalarbase(p, d, 0);
  TweetNaclFast.pack(pk, p);

  for (var i = 0; i < 32; i += 1) {
    sk[i + 32] = pk[i];
  }
  return {'sk': Uint8List.fromList(sk), 'pk': Uint8List.fromList(pk)};
}

String toBase58(List<int> bytes) {
  String encoded = '';
  if (bytes.isEmpty) return encoded;
  final zeroes = bytes.takeWhile((v) => v == 0).length;
  int length = 0;
  // Compute final size
  final size = (bytes.length - zeroes) * 138 ~/ 100 + 1;
  // Create temporary storage
  final List<int> b58bytes = List<int>.filled(size, 0);
  for (final byteValue in bytes.skip(zeroes)) {
    int carry = byteValue;
    int i = 0;
    for (int j = 0; j < size; j++, i++) {
      // ignore: avoid-inverted-boolean-checks, fix later
      if (!((carry != 0) || (i < length))) break;
      carry += 256 * b58bytes[j];
      b58bytes[j] = carry % 58;
      carry ~/= 58;
    }
    length = i;
  }
  final List<int> finalBytes = b58bytes.sublist(0, length);
  for (final byte in finalBytes) {
    encoded = _base58Alphabet[byte] + encoded;
  }

  return '1' * zeroes + encoded;
}
