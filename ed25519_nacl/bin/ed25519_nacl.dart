import '../lib/ed25519_nacl.dart';

void main(List<String> arguments) {
  final eVMPrivateKey =
      'e339b83fe5bd8c8eac084161514c0f32ac0e47c52a694ea25aadfe6b33d3bb63';

  final g = computeED25519KeyFrom(eVMPrivateKey: eVMPrivateKey);

  print('sk is ${g.secretKey}, pk is ${g.publicKey}');
}
