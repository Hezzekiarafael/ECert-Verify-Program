import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  ShieldCheck, 
  Key, 
  FileSignature, 
  FileSearch, 
  Download, 
  Upload, 
  CheckCircle2, 
  AlertCircle,
  Clock,
  Activity,
  Zap,
  Copy,
  ChevronRight,
  Menu,
  X
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api';

const App = () => {
  const [activeTab, setActiveTab] = useState('keygen');
  const [loading, setLoading] = useState(false);
  const [notification, setNotification] = useState(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // --- Shared Global State ---
  
  // Key Generator State
  const [keys, setKeys] = useState(null);
  const [keygenMetrics, setKeygenMetrics] = useState(null);

  // Signer State
  const [signerFile, setSignerFile] = useState(null);
  const [signerPrivateKey, setSignerPrivateKey] = useState('');
  const [signerResult, setSignerResult] = useState(null);

  // Verifier State
  const [verifierFile, setVerifierFile] = useState(null);
  const [verifierPublicKey, setVerifierPublicKey] = useState('');
  const [verifierSignature, setVerifierSignature] = useState('');
  const [verifierOriginalHash, setVerifierOriginalHash] = useState('');
  const [verifierResult, setVerifierResult] = useState(null);
  const [history, setHistory] = useState([]);


  const notify = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  // Sync keys to other views when generated
  useEffect(() => {
    if (keys) {
      if (!signerPrivateKey) setSignerPrivateKey(keys.private_key);
      if (!verifierPublicKey) setVerifierPublicKey(keys.public_key);
    }
  }, [keys]);

  // Fetch History from Database on mount
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/history/`);
        const totalItems = response.data.data.length;
        const fetchedHistory = response.data.data.map((item, idx) => ({
          id: totalItems - idx,
          file: item.file_name,
          bit_similarity: item.bit_similarity,
          avalanche: item.avalanche_effect,
          bit_diffusion: item.bit_diffusion,
          verify_time: item.verify_time,
          status: item.status,
          timestamp: new Date(item.created_at).toLocaleTimeString()
        }));
        setHistory(fetchedHistory);
      } catch (err) {
        console.error("Failed to fetch history:", err);
      }
    };
    fetchHistory();
  }, []);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    notify('Copied to clipboard!');
  };

  return (
    <>
      {/* Mobile Top Bar */}
      <div className="mobile-topbar glass">
        <div className="logo-section" style={{ paddingBottom: 0, borderBottom: 'none', marginBottom: 0 }}>
          <div className="logo-icon" style={{ width: '32px', height: '32px' }}>
            <ShieldCheck size={18} color="#3b82f6" />
          </div>
          <span className="logo-text" style={{ fontSize: '1.1rem' }}>ECert Verify</span>
        </div>
      </div>

      {/* Sidebar Navigation */}
      <nav className="sidebar glass">
        <div className="sidebar-header-mobile">
          <div className="logo-section" style={{ paddingBottom: 0, borderBottom: 'none', marginBottom: 0 }}>
            <div className="logo-icon">
              <ShieldCheck size={24} color="#3b82f6" />
            </div>
            <span className="logo-text">ECert Verify</span>
          </div>
          <button className="icon-btn close-btn" onClick={() => setIsMobileMenuOpen(false)}>
            <X size={24} color="#94a3b8" />
          </button>
        </div>

        <div className="logo-section desktop-logo">
          <div className="logo-icon">
            <ShieldCheck size={24} color="#3b82f6" />
          </div>
          <span className="logo-text">ECert Verify</span>
        </div>

        <div className="nav-items">
          <NavItem 
            icon={<Key size={20} />} 
            label="Key Generator" 
            active={activeTab === 'keygen'} 
            onClick={() => setActiveTab('keygen')} 
          />
          <NavItem 
            icon={<FileSignature size={20} />} 
            label="Sign Certificate" 
            active={activeTab === 'signer'} 
            onClick={() => setActiveTab('signer')} 
          />
          <NavItem 
            icon={<FileSearch size={20} />} 
            label="Verify Authenticity" 
            active={activeTab === 'verifier'} 
            onClick={() => setActiveTab('verifier')} 
          />
        </div>

        <div className="sidebar-footer">
          <div className="system-status">
            <div className="status-dot"></div>
            <span>System Secure</span>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="main-content">
        <header className="content-header">
          <h1>{activeTab === 'keygen' ? 'RSA Key Management' : 
               activeTab === 'signer' ? 'Certificate Signing' : 'Verification Dashboard'}</h1>
          <div className="user-profile">
            <div className="badge-blue metric-badge">Researcher Node #1</div>
          </div>
        </header>

        <div className="view-container">
          <AnimatePresence mode="wait">
            {activeTab === 'keygen' && (
              <KeyGeneratorView 
                key="keygen" 
                notify={notify} 
                loading={loading} 
                setLoading={setLoading}
                keys={keys}
                setKeys={setKeys}
                metrics={keygenMetrics}
                setMetrics={setKeygenMetrics}
              />
            )}
            {activeTab === 'signer' && (
              <SignerView 
                key="signer" 
                notify={notify} 
                loading={loading} 
                setLoading={setLoading}
                file={signerFile}
                setFile={setSignerFile}
                privateKey={signerPrivateKey}
                setPrivateKey={setSignerPrivateKey}
                result={signerResult}
                setResult={setSignerResult}
              />
            )}
            {activeTab === 'verifier' && (
              <VerifierView 
                key="verifier" 
                notify={notify} 
                loading={loading} 
                setLoading={setLoading}
                file={verifierFile}
                setFile={setVerifierFile}
                publicKey={verifierPublicKey}
                setPublicKey={setVerifierPublicKey}
                signature={verifierSignature}
                setSignature={setVerifierSignature}
                originalHash={verifierOriginalHash}
                setOriginalHash={setVerifierOriginalHash}
                result={verifierResult}
                setResult={setVerifierResult}
                history={history}
                setHistory={setHistory}
              />
            )}
          </AnimatePresence>
        </div>
      </main>

      {/* Notifications */}
      <AnimatePresence>
        {notification && (
          <motion.div 
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 50 }}
            className={`notification ${notification.type}`}
          >
            {notification.type === 'success' ? <CheckCircle2 size={18} /> : <AlertCircle size={18} />}
            {notification.message}
          </motion.div>
        )}
      </AnimatePresence>


      {/* Mobile Bottom Navigation */}
      <nav className="mobile-bottom-nav glass print-only-hide">
        <div 
          className={`bottom-nav-item ${activeTab === 'keygen' ? 'active' : ''}`}
          onClick={() => setActiveTab('keygen')}
        >
          <Key size={22} />
          <span>Keygen</span>
        </div>
        <div 
          className={`bottom-nav-item ${activeTab === 'signer' ? 'active' : ''}`}
          onClick={() => setActiveTab('signer')}
        >
          <FileSignature size={22} />
          <span>Sign</span>
        </div>
        <div 
          className={`bottom-nav-item ${activeTab === 'verifier' ? 'active' : ''}`}
          onClick={() => setActiveTab('verifier')}
        >
          <ShieldCheck size={22} />
          <span>Verify</span>
        </div>
      </nav>
    </>
  );
};

const NavItem = ({ icon, label, active, onClick }) => (
  <div className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>
    {icon}
    <span>{label}</span>
    {active && <ChevronRight size={16} style={{ marginLeft: 'auto' }} />}
  </div>
);

// --- KEY GENERATOR VIEW ---
const KeyGeneratorView = ({ notify, loading, setLoading, keys, setKeys, metrics, setMetrics }) => {

  const generateKeys = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE_URL}/generate-keys/`);
      setKeys(response.data.data);
      setMetrics({ time: response.data.execution_time_ms });
      notify('RSA-2048 Key Pair Generated successfully!');
    } catch (err) {
      notify('Failed to generate keys', 'error');
    } finally {
      setLoading(false);
    }
  };

  const downloadKey = (content, filename) => {
    const element = document.createElement("a");
    const file = new Blob([content], {type: 'text/plain'});
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <motion.div 
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      className="view-layout"
    >
      <div className="glass p-32">
        <div className="card-header">
          <div className="icon-badge badge-blue"><Key size={24} /></div>
          <div>
            <h2 className="card-title">RSA Key Pair Generator</h2>
            <p className="card-desc">Generate NIST-compliant RSA-2048 bit keys for signing and verification.</p>
          </div>
        </div>

        {!keys ? (
          <div className="empty-state">
            <button className="btn btn-primary btn-large" onClick={generateKeys} disabled={loading}>
              {loading ? <Zap className="animate-spin" /> : <Zap size={20} />}
              {loading ? 'Computing Prime Numbers...' : 'Generate New Key Pair'}
            </button>
          </div>
        ) : (
          <div className="keys-display">
            <div className="key-section">
              <div className="flex-between mb-8">
                <span className="label">Public Key (Distribute this)</span>
                <div className="flex-gap">
                  <button className="icon-btn" onClick={() => downloadKey(keys.public_key, 'public_key.pem')} title="Download"><Download size={16}/></button>
                  <button className="icon-btn" onClick={() => navigator.clipboard.writeText(keys.public_key)} title="Copy"><Copy size={16}/></button>
                </div>
              </div>
              <pre className="key-code">{keys.public_key}</pre>
            </div>

            <div className="key-section mt-24">
              <div className="flex-between mb-8">
                <span className="label">Private Key (Keep this secure!)</span>
                <div className="flex-gap">
                  <button className="icon-btn" onClick={() => downloadKey(keys.private_key, 'private_key.pem')} title="Download"><Download size={16}/></button>
                  <button className="icon-btn" onClick={() => navigator.clipboard.writeText(keys.private_key)} title="Copy"><Copy size={16}/></button>
                </div>
              </div>
              <pre className="key-code private">{keys.private_key}</pre>
            </div>

            <div className="metrics-grid mt-32">
              <MetricItem icon={<Clock size={16}/>} label="Generation Time" value={`${metrics.time.toFixed(2)} ms`} badge="badge-purple" />
              <MetricItem icon={<Activity size={16}/>} label="Key Strength" value="2048-bit" badge="badge-blue" />
              <MetricItem icon={<ShieldCheck size={16}/>} label="Algorithm" value="RSA" badge="badge-green" />
            </div>

            <button className="btn btn-secondary mt-32 w-full" onClick={() => setKeys(null)}>Generate Another Pair</button>
          </div>
        )}
      </div>



    </motion.div>
  );
};

// --- SIGNER VIEW ---
const SignerView = ({ notify, loading, setLoading, file, setFile, privateKey, setPrivateKey, result, setResult }) => {

  const handleSign = async () => {
    if (!file || !privateKey) {
      notify('Please select a file and provide a private key', 'error');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append('image', file);
    formData.append('private_key', privateKey);

    try {
      const response = await axios.post(`${API_BASE_URL}/sign-certificate/`, formData);
      setResult(response.data);
      notify('Certificate Signed successfully!');
    } catch (err) {
      notify(err.response?.data?.message || 'Signing failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      className="view-layout"
    >
      <div className="glass p-32">
        <div className="card-header">
          <div className="icon-badge badge-purple"><FileSignature size={24} /></div>
          <div>
            <h2 className="card-title">Sign Certificate</h2>
            <p className="card-desc">Apply a cryptographically secure digital signature to your academic certificate.</p>
          </div>
        </div>

        {!result ? (
          <div className="form-grid">
            <div className="input-group">
              <span className="label">Certificate Image</span>
              <FileUploader onFileSelect={setFile} selectedFile={file} />
            </div>

            <div className="input-group">
              <div className="flex-between mb-8">
                <span className="label">RSA Private Key (PEM)</span>
                <label className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', margin: 0, width: 'fit-content' }}>
                  <Upload size={14} /> Upload .pem
                  <input 
                    type="file" 
                    accept=".pem,.txt" 
                    style={{ display: 'none' }} 
                    onChange={(e) => {
                      const selected = e.target.files[0];
                      if (!selected) return;
                      const reader = new FileReader();
                      reader.onload = (event) => {
                        setPrivateKey(event.target.result);
                        notify('Private Key loaded from file');
                      };
                      reader.readAsText(selected);
                      e.target.value = null;
                    }} 
                  />
                </label>
              </div>
              <textarea 
                className="text-input h-200" 
                placeholder="Paste -----BEGIN PRIVATE KEY----- here..."
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
              />
            </div>

            <button className="btn btn-primary w-full mt-8" onClick={handleSign} disabled={loading}>
              {loading ? 'Processing Cryptography...' : 'Sign Certificate'}
            </button>
          </div>
        ) : (
          <div className="result-display">
            <div className="status-banner success">
              <CheckCircle2 size={24} />
              <div>
                <h3>Signature Generated</h3>
                <p>File: <strong>{file?.name}</strong> — Digital proof of authenticity has been created.</p>
              </div>
            </div>

            <div className="data-grid mt-24">
              <div className="badge-blue mb-8" style={{ fontSize: '0.75rem', width: 'fit-content' }}>
                <Activity size={12} style={{ marginRight: '6px' }} />
                SOURCE: Normalized Digital Image (Grayscale, 300 DPI, A4 Matrix)
              </div>
              <DataField label="SHA-256 Hash" value={result.data.sha256_hash} copyable downloadable filename="original_hash.txt" />
              <DataField label="Digital Signature (Base64)" value={result.data.digital_signature_b64} copyable isLong downloadable filename="digital_signature.sig" />
            </div>

            <div className="section-title mt-32">Academic Metrics</div>
            <div className="metrics-grid mt-16">
              <MetricItem 
                icon={<Zap size={16}/>} 
                label="Shannon Entropy" 
                value={`${result.data.entropy_analysis.entropy_bits.toFixed(4)} bits`} 
                badge="badge-purple" 
                desc={`Ratio: ${(result.data.entropy_analysis.randomness_ratio * 100).toFixed(2)}%`}
              />
              <MetricItem 
                icon={<Clock size={16}/>} 
                label="Process Time" 
                value={`${result.execution_time_ms.toFixed(2)} ms`} 
                badge="badge-blue" 
              />
              <MetricItem 
                icon={<ShieldCheck size={16}/>} 
                label="Algorithm" 
                value="RSA-PSS" 
                badge="badge-green" 
              />
              <MetricItem 
                icon={<Clock size={16}/>} 
                label="Normalization Time" 
                value={`${result.data.normalization_time_ms.toFixed(2)} ms`} 
                badge="badge-purple" 
              />
              <MetricItem 
                icon={<Clock size={16}/>} 
                label="Hashing Time" 
                value={`${result.data.hashing_time_ms.toFixed(2)} ms`} 
                badge="badge-blue" 
              />
            </div>

            {result.data.normalized_image_b64 && (
              <div className="normalized-preview mt-24">
                <div className="section-title" style={{ marginBottom: '8px' }}>Normalized Digital Image (Master Copy)</div>
                <p style={{ fontSize: '0.75rem', opacity: 0.6, marginBottom: '12px' }}>
                  Gunakan file ini untuk proses verifikasi agar hasilnya 100% cocok.
                </p>
                <div style={{ 
                  border: '1px solid rgba(255,255,255,0.1)', 
                  borderRadius: '12px', 
                  overflow: 'hidden',
                  marginBottom: '12px',
                  maxHeight: '200px',
                  display: 'flex',
                  justifyContent: 'center',
                  background: 'rgba(0,0,0,0.3)'
                }}>
                  <img 
                    src={`data:image/png;base64,${result.data.normalized_image_b64}`} 
                    alt="Normalized Grayscale Certificate" 
                    style={{ maxWidth: '100%', maxHeight: '200px', objectFit: 'contain' }}
                  />
                </div>
                <button 
                  className="btn btn-primary w-full"
                  style={{ padding: '10px 20px', fontSize: '0.85rem' }}
                  onClick={() => {
                    const link = document.createElement('a');
                    link.href = `data:image/png;base64,${result.data.normalized_image_b64}`;
                    link.download = `normalized_certificate_${Date.now()}.png`;
                    link.click();
                    notify('Normalized image downloaded!');
                  }}
                >
                  <Download size={16} style={{ marginRight: '8px' }} />
                  Download Normalized Image (Grayscale, 300 DPI PNG)
                </button>
              </div>
            )}

            <button className="btn btn-secondary mt-32 w-full" onClick={() => setResult(null)}>Sign Another Document</button>
          </div>
        )}
      </div>


    </motion.div>
  );
};

// --- VERIFIER VIEW ---
const VerifierView = ({ 
  notify, loading, setLoading, file, setFile, publicKey, setPublicKey, 
  signature, setSignature, originalHash, setOriginalHash, result, setResult,
  history, setHistory 
}) => {

  const handleVerify = async () => {
    if (!file || !publicKey || !signature) {
      notify('Please provide all required fields', 'error');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append('image', file);
    formData.append('public_key', publicKey);
    formData.append('signature', signature);
    if (originalHash) formData.append('original_hash', originalHash);

    try {
      const response = await axios.post(`${API_BASE_URL}/verify-certificate/`, formData);
      const newResult = response.data;
      setResult(newResult);
      
      // Prepare history entry for DB
      const avalancheEffectPct = newResult.data.avalanche_analysis && !newResult.data.avalanche_analysis.note 
        ? `${newResult.data.avalanche_analysis.avalanche_effect_pct.toFixed(2)}%` : "0.00%";
      const diffBits = newResult.data.avalanche_analysis && !newResult.data.avalanche_analysis.note 
        ? `${newResult.data.avalanche_analysis.differing_bits} Δ Bits` : "0 Δ Bits";

      const dbHistoryEntry = {
        file_name: file.name,
        bit_similarity: newResult.data.is_valid ? "100%" : "0%",
        avalanche_effect: avalancheEffectPct,
        bit_diffusion: diffBits,
        verify_time: `${newResult.execution_time_ms.toFixed(2)} ms`,
        status: newResult.data.is_valid ? "VALID" : "INVALID",
      };

      try {
        // Save to DB
        await axios.post(`${API_BASE_URL}/history/`, dbHistoryEntry);
        
        // Update local state
        const localHistoryEntry = {
          id: history.length + 1,
          file: dbHistoryEntry.file_name,
          bit_similarity: dbHistoryEntry.bit_similarity,
          avalanche: dbHistoryEntry.avalanche_effect,
          bit_diffusion: dbHistoryEntry.bit_diffusion,
          verify_time: dbHistoryEntry.verify_time,
          status: dbHistoryEntry.status,
          timestamp: new Date().toLocaleTimeString()
        };
        setHistory(prev => [...prev, localHistoryEntry]);
      } catch (err) {
        console.error("Failed to save history to DB", err);
      }

      if (newResult.data.is_valid) {
        notify('Verification Successful! Document is authentic.');
      } else {
        notify('Verification Failed! Document may be tampered.', 'error');
      }
    } catch (err) {
      notify(err.response?.data?.message || 'Verification failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      className="view-layout"
    >
      <div className="glass p-32">
        <div className="card-header">
          <div className="icon-badge badge-green"><FileSearch size={24} /></div>
          <div>
            <h2 className="card-title">Verify Authenticity</h2>
            <p className="card-desc">Verify a digital signature against a certificate to ensure non-repudiation and integrity.</p>
          </div>
        </div>

        {!result ? (
          <div className="form-grid">
            <div className="input-group">
              <span className="label">Certificate to Verify</span>
              <FileUploader onFileSelect={setFile} selectedFile={file} />
            </div>

            <div className="flex-gap-32">
              <div className="input-group flex-1">
                <div className="flex-between mb-8">
                  <span className="label">RSA Public Key</span>
                  <label className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', margin: 0, width: 'fit-content' }}>
                    <Upload size={14} /> Upload .pem
                    <input 
                      type="file" 
                      accept=".pem,.txt" 
                      style={{ display: 'none' }} 
                      onChange={(e) => {
                        const selected = e.target.files[0];
                        if (!selected) return;
                        const reader = new FileReader();
                        reader.onload = (event) => {
                          setPublicKey(event.target.result);
                          notify('Public Key loaded from file');
                        };
                        reader.readAsText(selected);
                        e.target.value = null;
                      }} 
                    />
                  </label>
                </div>
                <textarea 
                  className="text-input h-120" 
                  placeholder="Paste -----BEGIN PUBLIC KEY-----"
                  value={publicKey}
                  onChange={(e) => setPublicKey(e.target.value)}
                />
              </div>
              <div className="input-group flex-1">
                <div className="flex-between mb-8">
                  <span className="label">Digital Signature (Base64)</span>
                  <label className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', margin: 0, width: 'fit-content' }}>
                    <Upload size={14} /> Upload .sig
                    <input 
                      type="file" 
                      accept=".sig,.txt" 
                      style={{ display: 'none' }} 
                      onChange={(e) => {
                        const selected = e.target.files[0];
                        if (!selected) return;
                        const reader = new FileReader();
                        reader.onload = (event) => {
                          setSignature(event.target.result);
                          notify('Signature loaded from file');
                        };
                        reader.readAsText(selected);
                        e.target.value = null;
                      }} 
                    />
                  </label>
                </div>
                <textarea 
                  className="text-input h-120" 
                  placeholder="Paste base64 signature"
                  value={signature}
                  onChange={(e) => setSignature(e.target.value)}
                />
              </div>
            </div>

            <div className="input-group">
              <div className="flex-between mb-8">
                <span className="label">Original Hash (Optional for Avalanche analysis)</span>
                <label className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', margin: 0, width: 'fit-content' }}>
                  <Upload size={14} /> Upload .txt
                  <input 
                    type="file" 
                    accept=".txt,.hash" 
                    style={{ display: 'none' }} 
                    onChange={(e) => {
                      const selected = e.target.files[0];
                      if (!selected) return;
                      const reader = new FileReader();
                      reader.onload = (event) => {
                        setOriginalHash(event.target.result);
                        notify('Hash loaded from file');
                      };
                      reader.readAsText(selected);
                      e.target.value = null;
                    }} 
                  />
                </label>
              </div>
              <input 
                type="text"
                className="text-input" 
                placeholder="Paste SHA-256 hex hash"
                value={originalHash}
                onChange={(e) => setOriginalHash(e.target.value)}
              />
            </div>

            <button className="btn btn-primary w-full mt-8" onClick={handleVerify} disabled={loading}>
              {loading ? 'Performing Verification...' : 'Verify Certificate'}
            </button>
          </div>
        ) : (
          <div className="result-display">
            <div className={`status-banner ${result.data.is_valid ? 'success' : 'error'}`}>
              {result.data.is_valid ? <CheckCircle2 size={24} /> : <AlertCircle size={24} />}
              <div>
                <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {result.data.is_valid ? 'Verification Successful' : 'Verification Failed'}
                  <span className="badge-blue" style={{ fontSize: '0.7rem', padding: '2px 8px' }}>
                    {result.data.is_valid ? 'CONFIDENCE: 100%' : 'CONFIDENCE: 0%'}
                  </span>
                </h3>
                <p>File: <strong>{file?.name}</strong> — {result.data.message}</p>
                <div style={{ fontSize: '0.7rem', marginTop: '8px', opacity: 0.8, display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Activity size={10} />
                  IMAGE NORMALIZED: Grayscale, 300 DPI, A4 Matrix
                </div>
              </div>
            </div>

            <div className="metrics-grid mt-32">
              <MetricItem 
                icon={<Activity size={16}/>} 
                label="Bit Similarity" 
                value={result.data.is_valid ? "100%" : "0%"} 
                badge={result.data.is_valid ? "badge-green" : "badge-red"} 
                desc={result.data.is_valid ? "256/256 bits match" : "Cryptographically distinct"}
              />
              <MetricItem 
                icon={<Clock size={16}/>} 
                label="Verify Time" 
                value={`${result.execution_time_ms.toFixed(2)} ms`} 
                badge="badge-blue" 
              />
              <MetricItem 
                icon={<ShieldCheck size={16}/>} 
                label="RSA-PSS Status" 
                value="VERIFIED" 
                badge="badge-purple" 
              />
            </div>

            {result.data.avalanche_analysis && !result.data.avalanche_analysis.note && (
              <div className="avalanche-section mt-32">
                <div className="section-title">Empirical Tamper Analysis (Avalanche Effect)</div>
                <div className="avalanche-card mt-16 glass">
                  <div className="avalanche-header">
                    <div className="avalanche-stat">
                      <span className="label">Avalanche Value</span>
                      <span className={`avalanche-value ${result.data.avalanche_analysis.avalanche_effect_pct > 40 ? 'good' : 'warning'}`}>
                        {result.data.avalanche_analysis.avalanche_effect_pct.toFixed(2)}%
                      </span>
                    </div>
                    <div className="avalanche-stat">
                      <span className="label">Bit Diffusion</span>
                      <span className="avalanche-value">{result.data.avalanche_analysis.differing_bits} Δ Bits</span>
                    </div>
                  </div>
                  
                  <div className="avalanche-bar-bg">
                    <div 
                      className="avalanche-bar-fill" 
                      style={{ 
                        width: `${result.data.avalanche_analysis.avalanche_effect_pct}%`,
                        backgroundColor: result.data.is_valid ? '#10b981' : '#3b82f6'
                      }}
                    ></div>
                  </div>
                  
                  <p className="avalanche-hint">
                    {result.data.is_valid 
                      ? "MATHEMATICAL PROOF: All 256 bits of the SHA-256 hash match the signed record perfectly." 
                      : `EMPIRICAL ALERT: Hash has mutated by ${result.data.avalanche_analysis.differing_bits} bits. This high diffusion confirms the file is not the original.`}
                  </p>
                </div>
              </div>
            )}

            <button className="btn btn-secondary mt-24 w-full" onClick={() => setResult(null)}>New Verification</button>
          </div>
        )}
      </div>

      {history.length > 0 && (
        <div className="glass p-32 mt-32 no-print">
          <div className="flex-between mb-24">
            <h2 className="section-title">Verification History Log</h2>
            <button className="btn btn-primary" style={{ padding: '8px 16px', fontSize: '0.8rem' }} onClick={() => window.print()}>
              <Download size={14} /> Download PDF Report
            </button>
          </div>
          
          <div className="table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th>No</th>
                  <th>File</th>
                  <th>Bit Similarity</th>
                  <th>Avalanche</th>
                  <th>Bit Diffusion</th>
                  <th>Verify Time</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry, idx) => (
                  <tr key={idx}>
                    <td>{entry.id}</td>
                    <td style={{ color: 'white', fontWeight: 500 }}>{entry.file}</td>
                    <td>{entry.bit_similarity}</td>
                    <td>{entry.avalanche}</td>
                    <td>{entry.bit_diffusion}</td>
                    <td>{entry.verify_time}</td>
                    <td>
                      <span className={`status-tag ${entry.status === 'VALID' ? 'valid' : 'invalid'}`}>
                        {entry.status} {entry.status === 'VALID' ? '✓' : '✗'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Print-only View */}
      <div className="print-only">
        <h1 style={{ color: 'black', marginBottom: '10px' }}>Digital Certificate Integrity Report</h1>
        <p style={{ color: '#666', marginBottom: '30px' }}>Generated on: {new Date().toLocaleString()}</p>
        
        <table style={{ width: '100%', borderCollapse: 'collapse', color: 'black' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #000', textAlign: 'left' }}>
              <th style={{ padding: '10px' }}>No</th>
              <th style={{ padding: '10px' }}>File Name</th>
              <th style={{ padding: '10px' }}>Bit Similarity</th>
              <th style={{ padding: '10px' }}>Avalanche</th>
              <th style={{ padding: '10px' }}>Bit Diffusion</th>
              <th style={{ padding: '10px' }}>Time</th>
              <th style={{ padding: '10px' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {history.map((entry, idx) => (
              <tr key={idx} style={{ borderBottom: '1px solid #ddd' }}>
                <td style={{ padding: '10px' }}>{entry.id}</td>
                <td style={{ padding: '10px' }}>{entry.file}</td>
                <td style={{ padding: '10px' }}>{entry.bit_similarity}</td>
                <td style={{ padding: '10px' }}>{entry.avalanche}</td>
                <td style={{ padding: '10px' }}>{entry.bit_diffusion}</td>
                <td style={{ padding: '10px' }}>{entry.verify_time}</td>
                <td style={{ padding: '10px', fontWeight: 'bold' }}>{entry.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
        
        <div style={{ marginTop: '50px', fontSize: '0.8rem', color: '#888' }}>
          This report provides empirical evidence of cryptographic integrity and bit-diffusion analysis (Avalanche Effect).
        </div>
      </div>


    </motion.div>
  );
};

// --- HELPER COMPONENTS ---

const FileUploader = ({ onFileSelect, selectedFile }) => (
  <div className="file-dropzone" onClick={() => document.getElementById('file-input').click()}>
    <input 
      type="file" 
      id="file-input" 
      style={{ display: 'none' }} 
      onChange={(e) => onFileSelect(e.target.files[0])} 
    />
    {selectedFile ? (
      <>
        <CheckCircle2 size={32} color="#10b981" />
        <span style={{ color: 'white', fontWeight: 600 }}>{selectedFile.name}</span>
        <span style={{ fontSize: '0.8rem', opacity: 0.6 }}>{(selectedFile.size / 1024).toFixed(2)} KB</span>
      </>
    ) : (
      <>
        <Upload size={32} color="#94a3b8" />
        <span style={{ color: 'white', fontWeight: 600 }}>Click to upload certificate</span>
        <span style={{ fontSize: '0.8rem', opacity: 0.6 }}>Supports PDF, PNG, JPG (Max 10MB)</span>
      </>
    )}
  </div>
);

const MetricItem = ({ icon, label, value, badge, desc }) => (
  <div className="metric-item glass">
    <div className="metric-top">
      {icon}
      <span className={`metric-badge ${badge}`}>{value}</span>
    </div>
    <div className="metric-label">{label}</div>
    {desc && <div className="metric-desc">{desc}</div>}

  </div>
);

export const downloadTextFile = (content, filename) => {
  const element = document.createElement("a");
  const file = new Blob([content], {type: 'text/plain'});
  element.href = URL.createObjectURL(file);
  element.download = filename;
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
};

const DataField = ({ label, value, copyable, isLong, downloadable, filename }) => (
  <div className="data-field">
    <div className="flex-between mb-4">
      <span className="label">{label}</span>
      <div style={{ display: 'flex', gap: '8px' }}>
        {downloadable && (
          <button className="icon-btn-tiny" onClick={() => downloadTextFile(value, filename)} title="Download file">
            <Download size={12}/>
          </button>
        )}
        {copyable && (
          <button className="icon-btn-tiny" onClick={() => navigator.clipboard.writeText(value)} title="Copy to clipboard">
            <Copy size={12}/>
          </button>
        )}
      </div>
    </div>
    <div className={`data-value ${isLong ? 'scroll' : ''}`}>{value}</div>

  </div>
);

export default App;
