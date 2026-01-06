import { useState } from 'react';
import { Lock, Unlock, Key, FileText, AlertCircle, Download } from 'lucide-react';
import { encrypt, decrypt } from './lib/crypto';

function App() {
  const [encryptPassphrase, setEncryptPassphrase] = useState('');
  const [encryptMessage, setEncryptMessage] = useState('');
  const [encryptResult, setEncryptResult] = useState('');
  const [encryptLoading, setEncryptLoading] = useState(false);
  const [encryptError, setEncryptError] = useState('');

  const [decryptPassphrase, setDecryptPassphrase] = useState('');
  const [decryptMessage, setDecryptMessage] = useState('');
  const [decryptResult, setDecryptResult] = useState('');
  const [decryptLoading, setDecryptLoading] = useState(false);
  const [decryptError, setDecryptError] = useState('');

  const handleEncrypt = async () => {
    if (!encryptPassphrase || !encryptMessage) {
      setEncryptError('Lütfen tüm alanları doldurun');
      return;
    }

    setEncryptLoading(true);
    setEncryptError('');

    try {
      const encrypted = await encrypt(encryptMessage, encryptPassphrase);
      setEncryptResult(encrypted);
    } catch (e) {
      setEncryptError('Şifreleme hatası oluştu');
    } finally {
      setEncryptLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!decryptPassphrase || !decryptMessage) {
      setDecryptError('Lütfen tüm alanları doldurun');
      return;
    }

    setDecryptLoading(true);
    setDecryptError('');

    try {
      const decrypted = await decrypt(decryptMessage, decryptPassphrase);
      setDecryptResult(decrypted);
    } catch (e) {
      setDecryptError('Çözme hatası: Yanlış anahtar veya bozuk veri');
    } finally {
      setDecryptLoading(false);
    }
  };

  const downloadPythonFile = () => {
    const pythonCode = `import os
import hmac
import json
import struct
import base64
import hashlib
import secrets
from typing import List

# ---------- Parametreler ----------
PBKDF2_ITER = 200_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # 256-bit keys

# ---------- Yardımcılar ----------
def derive_keys(passphrase: str, salt: bytes) -> (bytes, bytes):
    """
    PBKDF2 ile şifrelerden'ten iki ayrı anahtar üretir:
    - keystream_key (AES/CTR yerine HMAC-DRBG için)
    - mac_key (HMAC doğrulama)
    """
    dk = hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, PBKDF2_ITER, dklen=KEY_LEN * 2)
    return dk[:KEY_LEN], dk[KEY_LEN:KEY_LEN*2]


def hmac_stream(key: bytes, prefix: bytes):
    """
    HMAC-SHA256 tabanlı deterministik "random stream" üretici (counter mode).
    Kullanım: çıkıştan byte'ları istediğiniz kadar tüketin.
    """
    counter = 0
    while True:
        ctr_bytes = struct.pack(">Q", counter)  # 8 byte big-endian
        yield hmac.new(key, prefix + ctr_bytes, hashlib.sha256).digest()
        counter += 1


def make_permutation_from_key(key: bytes, n: int = 256) -> List[int]:
    """
    Anahtara dayalı deterministik permütasyon üretir (Fisher-Yates
    ama random sayılarını HMAC stream'den alır).
    """
    perm = list(range(n))
    stream = hmac_stream(key, b'permute-v1-')  # sabit prefix
    # Fisher-Yates (ters) — rastgele sayı alma: büyük bir blok alıp mod ile kullan
    for i in range(n-1, 0, -1):
        # alacağımız rastgele değeri üret (8 byte'tan fazla -> int)
        # çektiğimiz blokların yeterli olduğunu garanti etmek için 8 byte kullanıyoruz
        rnd_block = next(stream)
        rnd_int = int.from_bytes(rnd_block, 'big')
        j = rnd_int % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def invert_permutation(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for i, v in enumerate(perm):
        inv[v] = i
    return inv

# ---------- Şifreleme / Çözme ----------
def encrypt(message: str, passphrase: str) -> str:
    """
    Döndürür: base64 encoded JSON string içerir: {salt, nonce, ciphertext (b64), tag (b64)}
    """
    salt = os.urandom(SALT_LEN)
    keystream_key, mac_key = derive_keys(passphrase, salt)

    # deterministik mapping (parolaya bağlı)
    perm = make_permutation_from_key(keystream_key, 256)
    # plaintext bytes
    pt = message.encode('utf-8')

    nonce = os.urandom(NONCE_LEN)
    ks = hmac_stream(keystream_key, b'ks-' + nonce)  # keystream üreticisi
    # oluşturulacak XOR keystream'i pt uzunluğunda al
    keystream_bytes = b''.join(next(ks) for _ in range((len(pt) + 31)//32))[:len(pt)]

    # XOR ile karıştır, sonra mapping uygula
    xored = bytes([pt[i] ^ keystream_bytes[i] for i in range(len(pt))])
    ciphertext = bytes([perm[b] for b in xored])  # bijektif dönüşüm uygulandı

    # HMAC doğrulama etiketi: nonce || ciphertext
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()

    payload = {
        "salt": base64.b64encode(salt).decode('ascii'),
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
        "tag": base64.b64encode(tag).decode('ascii'),
    }
    return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('ascii')


def decrypt(package_b64: str, passphrase: str) -> str:
    """
    package_b64: encrypt() tarafından üretilen string
    returns: çözümlenmiş plaintext (str) veya ValueError (eğer doğrulama başarısızsa)
    """
    try:
        raw = base64.b64decode(package_b64)
        payload = json.loads(raw.decode('utf-8'))
        salt = base64.b64decode(payload['salt'])
        nonce = base64.b64decode(payload['nonce'])
        ciphertext = base64.b64decode(payload['ciphertext'])
        tag = base64.b64decode(payload['tag'])
    except Exception as e:
        raise ValueError("Invalid package format") from e

    keystream_key, mac_key = derive_keys(passphrase, salt)

    # doğrulama
    expected_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Authentication failed (bad passphrase or tampered data)")

    perm = make_permutation_from_key(keystream_key, 256)
    inv_perm = invert_permutation(perm)

    # apply inverse mapping
    xored = bytes([inv_perm[b] for b in ciphertext])

    ks = hmac_stream(keystream_key, b'ks-' + nonce)
    keystream_bytes = b''.join(next(ks) for _ in range((len(xored) + 31)//32))[:len(xored)]

    pt_bytes = bytes([xored[i] ^ keystream_bytes[i] for i in range(len(xored))])
    return pt_bytes.decode('utf-8')

# ---------- Kullanım örneği ----------
if __name__ == "__main__":
    pwd = input("Anahtarınızı Yazınız: ")
    msg = input("Şifrelenecek metni yazınız: ")
    packaged = encrypt(msg, pwd)
    print("\\nŞifrelenmiş/mühürlenmiş metin (kopyalayınız):\\n", packaged)

    # hemen deneme
    try:
        plain = decrypt(packaged, pwd)
        print("\\nÇözülen metin:", plain)
    except ValueError as e:
        print("Çözme hatası:", e)
`;

    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(pythonCode));
    element.setAttribute('download', 'secure_bijective_cipher.py');
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      <div className="container mx-auto px-4 py-12">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-600 to-green-600 rounded-2xl mb-4">
              <Lock className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-4xl font-bold text-slate-800 mb-3">
              Güvenli Şifreleme Uygulaması
            </h1>
            <p className="text-slate-600 text-lg">
              Deterministik Anahtar Akışı, Bijektif Dönüşümler ve HMAC ile Güvenli Mesajlaşma Uygulaması 
            </p>
          </div>

          <div className="grid grid-cols-2 gap-6 lg:gap-8">
            <div className="bg-white rounded-2xl shadow-xl p-8">
              <div className="flex items-center gap-3 mb-6">
                <div className="inline-flex items-center justify-center w-8 h-8 bg-green-100 rounded-lg">
                  <Lock className="w-5 h-5 text-green-600" />
                </div>
                <h2 className="text-2xl font-bold text-slate-800">Şifreleme</h2>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="flex items-center text-sm font-semibold text-slate-700 mb-2">
                    <Key className="w-4 h-4 mr-2 text-green-600" />
                    Anahtar Değeri
                  </label>
                  <input
                    type="text"
                    value={encryptPassphrase}
                    onChange={(e) => setEncryptPassphrase(e.target.value)}
                    placeholder="Güçlü bir anahtar girin"
                    className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-green-500 transition-colors text-slate-800 font-mono text-sm"
                  />
                </div>

                <div>
                  <label className="flex items-center text-sm font-semibold text-slate-700 mb-2">
                    <FileText className="w-4 h-4 mr-2 text-green-600" />
                    Şifrelenecek Metin
                  </label>
                  <textarea
                    value={encryptMessage}
                    onChange={(e) => setEncryptMessage(e.target.value)}
                    placeholder="Şifrelemek istediğiniz metni girin..."
                    rows={5}
                    className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-green-500 transition-colors resize-none text-slate-800 font-mono text-sm"
                  />
                </div>

                {encryptError && (
                  <div className="flex items-center gap-2 p-3 bg-red-50 border-2 border-red-200 rounded-lg text-red-700">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    <span className="text-xs font-medium">{encryptError}</span>
                  </div>
                )}

                <button
                  onClick={handleEncrypt}
                  disabled={encryptLoading}
                  className="w-full py-3 rounded-xl font-bold text-white bg-green-600 hover:bg-green-700 shadow-lg shadow-green-200 transition-all disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-xl"
                >
                  {encryptLoading ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      İşleniyor...
                    </span>
                  ) : (
                    <>
                      <Lock className="w-5 h-5 inline mr-2" />
                      Şifrele
                    </>
                  )}
                </button>

                {encryptResult && (
                  <div className="mt-4 p-3 bg-green-50 border-2 border-green-200 rounded-xl">
                    <p className="text-xs font-semibold text-green-700 mb-2">Şifrelenmiş Sonuç:</p>
                    <div className="relative">
                      <textarea
                        value={encryptResult}
                        readOnly
                        rows={4}
                        className="w-full px-3 py-2 border border-green-300 rounded-lg bg-white text-slate-800 font-mono text-xs resize-none"
                      />
                      <button
                        onClick={() => navigator.clipboard.writeText(encryptResult)}
                        className="absolute top-2 right-2 px-3 py-1 bg-green-600 text-white text-xs font-semibold rounded hover:bg-green-700 transition-colors"
                      >
                        Kopyala
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-white rounded-2xl shadow-xl p-8">
              <div className="flex items-center gap-3 mb-6">
                <div className="inline-flex items-center justify-center w-8 h-8 bg-blue-100 rounded-lg">
                  <Unlock className="w-5 h-5 text-blue-600" />
                </div>
                <h2 className="text-2xl font-bold text-slate-800">Deşifreleme</h2>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="flex items-center text-sm font-semibold text-slate-700 mb-2">
                    <Key className="w-4 h-4 mr-2 text-blue-600" />
                    Anahtar Değeri
                  </label>
                  <input
                    type="text"
                    value={decryptPassphrase}
                    onChange={(e) => setDecryptPassphrase(e.target.value)}
                    placeholder="Şifrelenmiş paketi açmak için anahtar girin"
                    className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-blue-500 transition-colors text-slate-800 font-mono text-sm"
                  />
                </div>

                <div>
                  <label className="flex items-center text-sm font-semibold text-slate-700 mb-2">
                    <FileText className="w-4 h-4 mr-2 text-blue-600" />
                    Şifrelenmiş Paket
                  </label>
                  <textarea
                    value={decryptMessage}
                    onChange={(e) => setDecryptMessage(e.target.value)}
                    placeholder="Şifreli metni buraya yapıştırınız..."
                    rows={5}
                    className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-blue-500 transition-colors resize-none text-slate-800 font-mono text-sm"
                  />
                </div>

                {decryptError && (
                  <div className="flex items-center gap-2 p-3 bg-red-50 border-2 border-red-200 rounded-lg text-red-700">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    <span className="text-xs font-medium">{decryptError}</span>
                  </div>
                )}

                <button
                  onClick={handleDecrypt}
                  disabled={decryptLoading}
                  className="w-full py-3 rounded-xl font-bold text-white bg-blue-600 hover:bg-blue-700 shadow-lg shadow-blue-200 transition-all disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-xl"
                >
                  {decryptLoading ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      İşleniyor...
                    </span>
                  ) : (
                    <>
                      <Unlock className="w-5 h-5 inline mr-2" />
                      Deşifrele
                    </>
                  )}
                </button>

                {decryptResult && (
                  <div className="mt-4 p-3 bg-blue-50 border-2 border-blue-200 rounded-xl">
                    <p className="text-xs font-semibold text-blue-700 mb-2">Deşifre Edilmiş Metin:</p>
                    <div className="relative">
                      <textarea
                        value={decryptResult}
                        readOnly
                        rows={4}
                        className="w-full px-3 py-2 border border-blue-300 rounded-lg bg-white text-slate-800 font-mono text-xs resize-none"
                      />
                      <button
                        onClick={() => navigator.clipboard.writeText(decryptResult)}
                        className="absolute top-2 right-2 px-3 py-1 bg-blue-600 text-white text-xs font-semibold rounded hover:bg-blue-700 transition-colors"
                      >
                        Kopyala
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="mt-12 text-center space-y-4">
            <p className="text-sm text-slate-500">Deterministik Anahtar Akışı, Bijektif Dönüşümler ve HMAC ile Güvenli Mesajlaşma Uygulaması | Melisa - Ömer - Tuğkan</p>
            <button
              onClick={downloadPythonFile}
              className="inline-flex items-center gap-2 px-6 py-3 bg-slate-700 hover:bg-slate-800 text-white rounded-lg font-semibold transition-colors shadow-lg"
            >
              <Download className="w-5 h-5" />
              Python Dosyasını İndir
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
