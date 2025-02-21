import 'dart:typed_data';

import 'utils/constants.dart';

gf([
  List? init,
]) {
  var i, r = Float64List(16);

  if (init != null) {
    for (i = 0; i < init.length; i++) {
      r[i] = init[i].toDouble();
    }
  }

  return r;
}

cryptoHash(out, m, n) {
  var h = Uint8List(64), x = Uint8List(256);
  var i, b = n;

  for (i = 0; i < 64; i++) {
    h[i] = iv[i];
  }

  cryptoHashblocks(h, m, n);
  n %= 128;

  for (i = 0; i < 256; i++) {
    x[i] = 0;
  }

  for (i = 0; i < n; i++) {
    x[i] = m[b - n + i];
  }

  x[n] = 128;

  n = 256 - 128 * (n < 112 ? 1 : 0);
  x[n - 9] = 0;
  ts64(x, n - 8, u64((b ~/ 0x20000000) | 0, b << 3));
  cryptoHashblocks(h, x, n);

  for (i = 0; i < 64; i++) {
    out[i] = h[i];
  }

  return 0;
}

cryptoHashblocks(x, m, n) {
  emptyList(int len) => List.generate(len, (_) => dl64(x, 8 * 0));

  var z = emptyList(8),
      b = emptyList(8),
      a = emptyList(8),
      w = emptyList(16),
      t,
      i,
      j;

  for (i = 0; i < 8; i++) {
    z[i] = a[i] = dl64(x, 8 * i);
  }

  var pos = 0;
  while (n >= 128) {
    for (i = 0; i < 16; i++) {
      w[i] = dl64(m, 8 * i + pos);
    }

    for (i = 0; i < 80; i++) {
      for (j = 0; j < 8; j++) {
        b[j] = a[j];
      }

      t = add64([
        a[7],
        Sigma1(a[4]),
        Ch(a[4], a[5], a[6]),
        K[i],
        w[i % 16],
      ]);

      b[7] = add64([
        t,
        Sigma0(a[0]),
        Maj(a[0], a[1], a[2]),
      ]);

      b[3] = add64([b[3], t]);

      for (j = 0; j < 8; j++) {
        a[(j + 1) % 8] = b[j];
      }

      if (i % 16 == 15) {
        for (j = 0; j < 16; j++) {
          w[j] = add64([
            w[j],
            w[(j + 9) % 16],
            sigma0(w[(j + 1) % 16]),
            sigma1(w[(j + 14) % 16]),
          ]);
        }
      }
    }

    for (i = 0; i < 8; i++) {
      a[i] = add64([a[i], z[i]]);
      z[i] = a[i];
    }

    pos += 128;
    n -= 128;
  }

  for (i = 0; i < 8; i++) {
    ts64(x, 8 * i, z[i]);
  }
  return n;
}

dl64(x, i) {
  var h = (x[i] << 24) | (x[i + 1] << 16) | (x[i + 2] << 8) | x[i + 3];
  var l = (x[i + 4] << 24) | (x[i + 5] << 16) | (x[i + 6] << 8) | x[i + 7];
  return u64(h, l);
}

add64(List arguments) {
  int a = 0, b = 0, c = 0, d = 0, m16 = 65535, l, h, i;
  for (i = 0; i < arguments.length; i++) {
    l = arguments[i].lo;
    h = arguments[i].hi;
    a += (l & m16);
    b += (l >>> 16);
    c += (h & m16);
    d += (h >>> 16);
  }

  b += (a >>> 16);
  c += (b >>> 16);
  d += (c >>> 16);

  return u64((c & m16) | (d << 16), (a & m16) | (b << 16));
}

class u64 {
  u64(
    h,
    l,
  )   : hi = h | 0 >>> 0,
        lo = l | 0 >>> 0;

  late int hi;
  late int lo;
}

Sigma0(x) {
  return xor64([
    R(x, 28),
    R(x, 34),
    R(x, 39),
  ]);
}

Maj(x, y, z) {
  var h = (x.hi & y.hi) ^ (x.hi & z.hi) ^ (y.hi & z.hi),
      l = (x.lo & y.lo) ^ (x.lo & z.lo) ^ (y.lo & z.lo);
  return u64(h, l);
}

Sigma1(x) {
  return xor64([
    R(x, 14),
    R(x, 18),
    R(x, 41),
  ]);
}

Ch(x, y, z) {
  var h = (x.hi & y.hi) ^ (~x.hi & z.hi), l = (x.lo & y.lo) ^ (~x.lo & z.lo);
  return u64(h, l);
}

sigma0(x) {
  return xor64([
    R(x, 1),
    R(x, 8),
    shr64(x, 7),
  ]);
}

sigma1(x) {
  return xor64([
    R(x, 19),
    R(x, 61),
    shr64(x, 6),
  ]);
}

xor64(List arguments) {
  var l = 0, h = 0, i;
  for (i = 0; i < arguments.length; i++) {
    l ^= arguments[i].lo;
    h ^= arguments[i].hi;
  }
  return u64(h, l);
}

// R(x, c) {
//   var h, l, c1 = 32 - c;
//   if (c < 32) {
//     h = (x.hi >>> c) | (x.lo << c1);
//     l = (x.lo >>> c) | (x.hi << c1);
//   } else if (c < 64) {
//     h = (x.lo >>> c) | (x.hi << c1);
//     l = (x.hi >>> c) | (x.lo << c1);
//   }
//   return u64(h, l);
// }

R(x, c) {
  var h, l;
  c = c & 63; // Ensure c is within 0-63 range
  var c1 = 32 - c;
  
  if (c < 32) {
    h = (x.hi >>> c) | (x.lo << c1);
    l = (x.lo >>> c) | (x.hi << c1);
  } else {
    // When c ≥ 32, ensure c1 doesn't become negative
    c -= 32;
    h = (x.lo >>> c) | (x.hi << (32 - c));
    l = (x.hi >>> c) | (x.lo << (32 - c));
  }
  return u64(h, l);
}

shr64(x, c) {
  return u64((x.hi >>> c), (x.lo >>> c) | (x.hi << (32 - c)));
}

ts64(x, i, u) {
  x[i] = (u.hi >> 24) & 0xff;
  x[i + 1] = (u.hi >> 16) & 0xff;
  x[i + 2] = (u.hi >> 8) & 0xff;
  x[i + 3] = u.hi & 0xff;
  x[i + 4] = (u.lo >> 24) & 0xff;
  x[i + 5] = (u.lo >> 16) & 0xff;
  x[i + 6] = (u.lo >> 8) & 0xff;
  x[i + 7] = u.lo & 0xff;
}

scalarbase(p, s) {
  var q = [gf(), gf(), gf(), gf()];
  set25519(q[0], X);
  set25519(q[1], Y);
  set25519(q[2], gf1);
  M(q[3], X, Y);
  scalarmult(p, q, s);
}

// set25519(r, a) {
//   var i;
//   for (i = 0; i < 16; i++) {
//     r[i] = a[i] | 0;
//   }
// }

set25519(r, a) {
  for (var i = 0; i < 16; i++) {
    // Convert to integer and back to double if needed
    r[i] = a[i].toInt().toDouble();
  }
}

M(o, a, b) {
  var i, j, t = Float64List(31);

  for (i = 0; i < 31; i++) {
    t[i] = 0;
  }

  for (i = 0; i < 16; i++) {
    for (j = 0; j < 16; j++) {
      t[i + j] += a[i] * b[j];
    }
  }

  for (i = 0; i < 15; i++) {
    t[i] += 38 * t[i + 16];
  }

  for (i = 0; i < 16; i++) {
    o[i] = t[i];
  }

  car25519(o);
  car25519(o);
}

car25519(o) {
  var c;
  var i;
  for (i = 0; i < 16; i++) {
    o[i] += 65536;
    c = (o[i] / 65536).floor();
    o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i == 15 ? 1 : 0);
    o[i] -= (c * 65536);
  }
}

// scalarmult(p, q, s) {
//   var b, i;
//   set25519(p[0], gf0);
//   set25519(p[1], gf1);
//   set25519(p[2], gf1);
//   set25519(p[3], gf0);
//   for (i = 255; i >= 0; --i) {
//     b = (s[(i / 8) | 0] >> (i & 7)) & 1;
//     cswap(p, q, b);
//     add(q, p);
//     add(p, p);
//     cswap(p, q, b);
//   }
// }

scalarmult(p, q, s) {
  var b, i;
  set25519(p[0], gf0);
  set25519(p[1], gf1);
  set25519(p[2], gf1);
  set25519(p[3], gf0);
  for (i = 255; i >= 0; --i) {
    // Use integer division (~/) instead of (i / 8) | 0
    b = (s[i ~/ 8] >> (i & 7)) & 1;
    cswap(p, q, b);
    add(q, p);
    add(p, p);
    cswap(p, q, b);
  }
}

cswap(p, q, b) {
  var i;
  for (i = 0; i < 4; i++) {
    sel25519(p[i], q[i], b);
  }
}

// sel25519(p, q, b) {
//   var t, c = ~(b - 1);
//   for (var i = 0; i < 16; i++) {
//     t = c & (p[i] ^ q[i]);
//     p[i] ^= t;
//     q[i] ^= t;
//   }
// }

sel25519(p, q, b) {
  // Ensure b is an integer
  int bInt = b.toInt();
  var c = ~(bInt - 1);
  
  for (var i = 0; i < 16; i++) {
    // Convert to integers for bitwise operations
    int pInt = p[i].toInt();
    int qInt = q[i].toInt();
    
    // Perform the bitwise operations
    int t = c & (pInt ^ qInt);
    
    // Store the results back as doubles
    p[i] = (pInt ^ t).toDouble();
    q[i] = (qInt ^ t).toDouble();
  }
}

add(p, q) {
  var a = gf(),
      b = gf(),
      c = gf(),
      d = gf(),
      e = gf(),
      f = gf(),
      g = gf(),
      h = gf(),
      t = gf();

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

// Z(o, a, b) {
//   var i;
//   for (i = 0; i < 16; i++) {
//     o[i] = (a[i] - b[i]) | 0;
//   }
// }

Z(o, a, b) {
  for (var i = 0; i < 16; i++) {
    // Convert the result to an integer and back to double to match JavaScript's | 0 behavior
    o[i] = (a[i] - b[i]).toInt().toDouble();
  }
}

// A(o, a, b) {
//   var i;
//   for (i = 0; i < 16; i++) {
//     o[i] = (a[i] + b[i]) | 0;
//   }
// }

A(o, a, b) {
  for (var i = 0; i < 16; i++) {
    // Convert the result to an integer and back to double
    o[i] = (a[i] + b[i]).toInt().toDouble();
  }
}

pack(r, p) {
  var tx = gf(), ty = gf(), zi = gf();
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

inv25519(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) {
    c[a] = i[a];
  }
  for (a = 253; a >= 0; a--) {
    S(c, c);
    if (a != 2 && a != 4) M(c, c, i);
  }
  for (a = 0; a < 16; a++) {
    o[a] = c[a];
  }
}

S(o, a) {
  M(o, a, a);
}

pack25519(o, n) {
  var i, j, b;
  var m = gf(), t = gf();
  for (i = 0; i < 16; i++) {
    t[i] = n[i];
  }
  car25519(t);
  car25519(t);
  car25519(t);
  for (j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1 - b);
  }
  for (i = 0; i < 16; i++) {
    o[2 * i] = t[i] & 0xff;
    o[2 * i + 1] = t[i] >> 8;
  }
}

par25519(a) {
  var d = Uint8List(32);
  pack25519(d, a);
  return d[0] & 1;
}
