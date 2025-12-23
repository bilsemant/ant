import { useState } from 'react';
import { Lock, Unlock, Key, FileText, AlertCircle } from 'lucide-react';
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
              PBKDF2 ve HMAC-SHA256 tabanlı güvenli bijektif şifreleme sistemi
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

          <div className="mt-12 text-center text-sm text-slate-500">
            <p>200,000 iterasyon PBKDF2 | HMAC-SHA256 | Bijektif şifreleme</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
