import 'package:challenge_sky_trade/challenge_sky_trade.dart';

void main() {
  final x = getED25519Key(privateKey: 'e339b83fe5bd8c8eac084161514c0f32ac0e47c52a694ea25aadfe6b33d3bb63');
  print(x['pk']);
  print(x['sk']);

  print(toBase58(x['pk']));
}
