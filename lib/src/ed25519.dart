import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'nacl.dart' as l;

class ED25519Key {
  const ED25519Key({
    required this.secretKey,
    required this.publicKey,
  });

  final Uint8List secretKey;
  final Uint8List publicKey;
}

ED25519Key computeED25519KeyFrom({
  required dynamic eVMPrivateKey,
}) {
  late final Uint8List privateKey;

  if (eVMPrivateKey is String) {
    privateKey = Uint8List.fromList(
      hex.decode(
        eVMPrivateKey,
      ),
    );
  } else if (eVMPrivateKey is Uint8List) {
    privateKey = eVMPrivateKey;
  } else {
    throw ArgumentError(
      'EVMPrivateKey must be a String or a Uint8List',
    );
  }

  final d = Uint8List(64);

  final p = [
    l.gf(),
    l.gf(),
    l.gf(),
    l.gf(),
  ];

  final sk = Uint8List.fromList(
    [
      ...Uint8List.fromList(privateKey),
      ...Uint8List(32),
    ],
  );

  final pk = Uint8List(32);

  l.cryptoHash(d, sk, 32);

  d[0] &= 248;

  d[31] &= 127;

  d[31] |= 64;

  l.scalarbase(p, d);

  l.pack(pk, p);

  for (var i = 0; i < 32; i += 1) {
    sk[i + 32] = pk[i];
  }

  return ED25519Key(
    secretKey: Uint8List.fromList(
      sk,
    ),
    publicKey: Uint8List.fromList(
      pk,
    ),
  );
}
