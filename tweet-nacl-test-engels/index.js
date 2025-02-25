const ed25519 = require("./ed-25519.js");
const base58 = require("./base-58.js");
const nacl = require("./nacl.js");

const privateKey = "e339b83fe5bd8c8eac084161514c0f32ac0e47c52a694ea25aadfe6b33d3bb63";

const keyPair = ed25519.getED25519Key(privateKey);

const sk = keyPair.sk;
const pk = keyPair.pk;

const base58EncodedSk = base58.toBase58(sk);
const base58EncodedPk = base58.toBase58(pk);

const f = nacl.sign.keyPair.fromSecretKey(sk);

console.log(keyPair);
console.log(sk);
console.log(pk);

console.log(base58EncodedSk);
console.log(base58EncodedPk);

console.log(f);

console.log(JSON.stringify(sk)); // [227,57,184,63,229,189,140,142,172,8,65,97,81,76,15,50,172,14,71,197,42,105,78,162,90,173,254,107,51,211,187,99,73,11,0,130,134,114,84,209,63,234,78,36,187,97,244,251,15,236,64,43,191,90,117,244,72,178,182,156,180,234,51,153]
console.log(JSON.stringify(pk)); // [73,11,0,130,134,114,84,209,63,234,78,36,187,97,244,251,15,236,64,43,191,90,117,244,72,178,182,156,180,234,51,153]