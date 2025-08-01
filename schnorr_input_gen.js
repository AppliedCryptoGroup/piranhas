import { Schnorr } from '@aztec/foundation/crypto';
import { GrumpkinScalar } from '@aztec/foundation/fields';
import { toBigIntBE } from '@aztec/foundation/bigint-buffer';
import fs from 'fs';

// 1. Private key and message
const privateKey = GrumpkinScalar.random();
const msg = [122, 73, 139, 47, 208, 5, 141, 100, 197, 228, 151, 29, 207, 222, 14, 206, 6, 242, 217, 47, 241, 190, 80, 228, 233, 173, 169, 165, 31, 178, 236, 0];

// 2. Signature generation
const schnorr = new Schnorr();
const signature = await schnorr.constructSignature(msg, privateKey);

// 3. Extract public key
const pubKey = await schnorr.computePublicKey(privateKey);
const pubKeyHex = Buffer.from(pubKey.toBuffer()).toString('hex');
const pubX = '0x' + pubKeyHex.slice(0, 64);
const pubY = '0x' + pubKeyHex.slice(64);

// 4. Signature bytes
const sigBytes = Array.from(signature.toBuffer()); // 64-byte array
const msgBytes = Array.from(msg); // Message as array of bytes

// 5. Prepare Noir input
const noirInput = {
  pub_key: {
    x: pubX,
    y: pubY,
    is_infinite: false,
  },
  signature: sigBytes,
  message: msgBytes,
};

// 6. Write to file
fs.writeFileSync('schnorr_input.json', JSON.stringify({ schnorr_signature: noirInput }, null, 2));

console.log('✅ Generated schnorr_input.json');
