const PBKDF2_ITER = 200_000;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const KEY_LEN = 32;

async function deriveKeys(passphrase: string, salt: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITER,
      hash: 'SHA-256'
    },
    keyMaterial,
    KEY_LEN * 2 * 8
  );

  const dk = new Uint8Array(derivedBits);
  return [dk.slice(0, KEY_LEN), dk.slice(KEY_LEN, KEY_LEN * 2)];
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(signature);
}

async function* hmacStream(key: Uint8Array, prefix: Uint8Array) {
  let counter = 0;
  while (true) {
    const ctrBytes = new Uint8Array(8);
    const view = new DataView(ctrBytes.buffer);
    view.setBigUint64(0, BigInt(counter), false);

    const combined = new Uint8Array(prefix.length + ctrBytes.length);
    combined.set(prefix);
    combined.set(ctrBytes, prefix.length);

    yield await hmacSha256(key, combined);
    counter++;
  }
}

async function makePermutationFromKey(key: Uint8Array, n: number = 256): Promise<number[]> {
  const perm = Array.from({ length: n }, (_, i) => i);
  const prefix = new TextEncoder().encode('permute-v1-');
  const stream = hmacStream(key, prefix);

  for (let i = n - 1; i > 0; i--) {
    const rndBlock = await stream.next();
    let rndInt = 0n;
    for (let b = 0; b < rndBlock.value.length; b++) {
      rndInt = (rndInt << 8n) | BigInt(rndBlock.value[b]);
    }
    const j = Number(rndInt % BigInt(i + 1));
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }

  return perm;
}

function invertPermutation(perm: number[]): number[] {
  const inv = new Array(perm.length);
  for (let i = 0; i < perm.length; i++) {
    inv[perm[i]] = i;
  }
  return inv;
}

export async function encrypt(message: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const [keystreamKey, macKey] = await deriveKeys(passphrase, salt);

  const perm = await makePermutationFromKey(keystreamKey, 256);
  const pt = new TextEncoder().encode(message);

  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ksPrefix = new Uint8Array([...'ks-'.split('').map(c => c.charCodeAt(0)), ...nonce]);
  const ks = hmacStream(keystreamKey, ksPrefix);

  const keystreamBytes = new Uint8Array(pt.length);
  let offset = 0;
  for await (const block of ks) {
    const toCopy = Math.min(block.length, pt.length - offset);
    keystreamBytes.set(block.slice(0, toCopy), offset);
    offset += toCopy;
    if (offset >= pt.length) break;
  }

  const xored = new Uint8Array(pt.length);
  for (let i = 0; i < pt.length; i++) {
    xored[i] = pt[i] ^ keystreamBytes[i];
  }

  const ciphertext = new Uint8Array(xored.length);
  for (let i = 0; i < xored.length; i++) {
    ciphertext[i] = perm[xored[i]];
  }

  const tagData = new Uint8Array(nonce.length + ciphertext.length);
  tagData.set(nonce);
  tagData.set(ciphertext, nonce.length);
  const tag = await hmacSha256(macKey, tagData);

  const payload = {
    salt: btoa(String.fromCharCode(...salt)),
    nonce: btoa(String.fromCharCode(...nonce)),
    ciphertext: btoa(String.fromCharCode(...ciphertext)),
    tag: btoa(String.fromCharCode(...tag)),
  };

  return btoa(JSON.stringify(payload));
}

export async function decrypt(packageB64: string, passphrase: string): Promise<string> {
  try {
    const raw = atob(packageB64);
    const payload = JSON.parse(raw);

    const salt = Uint8Array.from(atob(payload.salt), c => c.charCodeAt(0));
    const nonce = Uint8Array.from(atob(payload.nonce), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(payload.ciphertext), c => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(payload.tag), c => c.charCodeAt(0));

    const [keystreamKey, macKey] = await deriveKeys(passphrase, salt);

    const tagData = new Uint8Array(nonce.length + ciphertext.length);
    tagData.set(nonce);
    tagData.set(ciphertext, nonce.length);
    const expectedTag = await hmacSha256(macKey, tagData);

    let isValid = tag.length === expectedTag.length;
    for (let i = 0; i < tag.length && i < expectedTag.length; i++) {
      if (tag[i] !== expectedTag[i]) {
        isValid = false;
      }
    }

    if (!isValid) {
      throw new Error('Authentication failed (bad passphrase or tampered data)');
    }

    const perm = await makePermutationFromKey(keystreamKey, 256);
    const invPerm = invertPermutation(perm);

    const xored = new Uint8Array(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i++) {
      xored[i] = invPerm[ciphertext[i]];
    }

    const ksPrefix = new Uint8Array([...'ks-'.split('').map(c => c.charCodeAt(0)), ...nonce]);
    const ks = hmacStream(keystreamKey, ksPrefix);

    const keystreamBytes = new Uint8Array(xored.length);
    let offset = 0;
    for await (const block of ks) {
      const toCopy = Math.min(block.length, xored.length - offset);
      keystreamBytes.set(block.slice(0, toCopy), offset);
      offset += toCopy;
      if (offset >= xored.length) break;
    }

    const ptBytes = new Uint8Array(xored.length);
    for (let i = 0; i < xored.length; i++) {
      ptBytes[i] = xored[i] ^ keystreamBytes[i];
    }

    return new TextDecoder().decode(ptBytes);
  } catch (e) {
    throw new Error('Invalid package format or decryption failed');
  }
}
