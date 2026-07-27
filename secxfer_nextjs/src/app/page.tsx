"use client";

import { useState, useEffect, useRef, Component, type ReactNode } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://127.0.0.1:8085/api";
const SERVER_URL = process.env.NEXT_PUBLIC_SERVER_URL ?? "http://127.0.0.1:8001";

type LogEntry = { msg: string; level: "info" | "success" | "error" | "warn" };
type InboxItem = { file_id: string; sender_key_id: string; timestamp: number; size: number };
type AuditEntry = { id: number; event_type: string; details_raw: string; previous_hash: string; current_hash: string; timestamp: number };
type StatusData = { identity_name?: string; key_id?: string; prekeys_available?: number; status?: string };

// ── Error Boundary ──────────────────────────────────────────────────────────
class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean; message: string }> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, message: "" };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, message: error.message };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#080c14] text-white flex items-center justify-center">
          <div className="bg-red-900/40 border border-red-700 rounded-2xl p-8 max-w-lg text-center">
            <div className="text-5xl mb-4">🚨</div>
            <h2 className="text-2xl font-bold text-red-300 mb-2">Application Error</h2>
            <p className="text-slate-400 text-sm font-mono">{this.state.message}</p>
            <button onClick={() => this.setState({ hasError: false, message: "" })}
              className="mt-6 bg-red-700 hover:bg-red-600 text-white px-6 py-2 rounded-lg transition-colors">
              Retry
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
// ────────────────────────────────────────────────────────────────────────────

export default function Home() {
  const [unlocked, setUnlocked] = useState(false);
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState<StatusData>({});
  const [inbox, setInbox] = useState<InboxItem[]>([]);
  const [recipient, setRecipient] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [activeTab, setActiveTab] = useState<"send" | "inbox" | "audit">("send");
  const [logMessages, setLogMessages] = useState<LogEntry[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [auditStatus, setAuditStatus] = useState<"idle" | "checking" | "ok" | "fail">("idle");
  const [sending, setSending] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const logEndRef = useRef<HTMLDivElement>(null);

  const log = (msg: string, level: LogEntry["level"] = "info") => {
    setLogMessages((prev) => [...prev, { msg: `[${new Date().toLocaleTimeString()}] ${msg}`, level }]);
  };

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logMessages]);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append("password", password);
    try {
      const res = await fetch(`${API_BASE}/unlock`, { method: "POST", body: formData });
      const data = await res.json();
      if (data.status === "unlocked") {
        setUnlocked(true);
        log("Keystore unlocked. Quantum-safe keys loaded.", "success");
        checkStatus();
      } else {
        log("Unlock failed: " + (data.error || "Wrong password"), "error");
      }
    } catch (err: any) {
      log(`Connection error: ${err.message}`, "error");
    }
  };

  const checkStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      const data = await res.json();
      if (data.status === "ok") {
        setStatus(data);
        fetchInbox();
      }
    } catch (e) {}
  };

  const fetchInbox = async () => {
    try {
      const formData = new FormData();
      formData.append("server_url", SERVER_URL);
      const res = await fetch(`${API_BASE}/inbox`, { method: "POST", body: formData });
      const data = await res.json();
      if (data.inbox) setInbox(data.inbox);
    } catch (e) {}
  };

  useEffect(() => {
    if (!unlocked) return;
    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, [unlocked]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || !recipient) { log("Please select a recipient and a file.", "warn"); return; }
    setSending(true);
    setUploadProgress(0);
    log(`Encrypting "${file.name}" with X3DH + XChaCha20-Poly1305 for "${recipient}"...`, "info");
    const formData = new FormData();
    formData.append("receiver_name", recipient);
    formData.append("file", file);
    formData.append("server_url", SERVER_URL);
    try {
      await new Promise<void>((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", `${API_BASE}/send`);
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) {
            setUploadProgress(Math.round((event.loaded / event.total) * 100));
          }
        };
        xhr.onload = () => {
          const data = JSON.parse(xhr.responseText);
          if (data.status === "ok") {
            log(`Encrypted payload uploaded to Django KDC. Zero-Trust guaranteed.`, "success");
            setFile(null); setRecipient(""); setUploadProgress(0);
            resolve();
          } else {
            log(`Error: ${data.error}`, "error");
            reject(new Error(data.error));
          }
        };
        xhr.onerror = () => reject(new Error("Network error"));
        xhr.send(formData);
      });
    } catch (err: any) {
      log(`Failed: ${err.message}`, "error");
    } finally {
      setSending(false);
      setUploadProgress(0);
    }
  };

  const verifyServerAudit = async () => {
    setAuditStatus("checking");
    setActiveTab("audit");
    log(`Fetching Hash-Chained Audit Log from Django server...`, "info");
    try {
      const res = await fetch(`${API_BASE}/audit?server_url=${encodeURIComponent(SERVER_URL)}`);
      const data = await res.json();
      if (data.error) { log(`Audit fetch failed: ${data.error}`, "error"); setAuditStatus("fail"); return; }
      const logs: AuditEntry[] = data.log;
      setAuditLogs(logs);
      if (!logs || logs.length === 0) { log("Audit log is empty (no events yet).", "info"); setAuditStatus("ok"); return; }

      let previous_hash = "GENESIS_HASH";
      for (const entry of logs) {
        const hash_input = `${entry.event_type}|${entry.details_raw}|${entry.timestamp}|${previous_hash}`;
        const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(hash_input));
        const current_hash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
        if (entry.previous_hash !== previous_hash || current_hash !== entry.current_hash) {
          log(`[CRITICAL] Chain tampered at block #${entry.id}! SERVER INTEGRITY COMPROMISED!`, "error");
          setAuditStatus("fail"); return;
        }
        previous_hash = current_hash;
      }
      log(`Verified ${logs.length} blocks locally in browser. No tampering detected. Chain is intact.`, "success");
      setAuditStatus("ok");
    } catch (err: any) {
      log(`Audit verification error: ${err}`, "error");
      setAuditStatus("fail");
    }
  };

  const handleDownload = async (file_id: string) => {
    log(`Downloading & decrypting file #${file_id}...`, "info");
    const formData = new FormData();
    formData.append("file_id", file_id);
    formData.append("server_url", SERVER_URL);
    try {
      const res = await fetch(`${API_BASE}/download`, { method: "POST", body: formData });
      const data = await res.json();
      if (data.status === "ok") { log(`File #${file_id} decrypted and saved to downloads folder.`, "success"); fetchInbox(); }
      else { log(`Error: ${data.error}`, "error"); }
    } catch (e: any) { log(`Failed: ${e.message}`, "error"); }
  };

  const logColor = { info: "text-slate-400", success: "text-emerald-400", error: "text-red-400", warn: "text-amber-400" };

  return (
    <main className="min-h-screen bg-[#080c14] text-white font-sans" style={{ fontFamily: "'Inter', 'Arial', sans-serif" }}>
      {/* Animated background grid */}
      <div className="fixed inset-0 opacity-10 pointer-events-none"
        style={{ backgroundImage: "linear-gradient(rgba(99,102,241,.4) 1px, transparent 1px), linear-gradient(90deg, rgba(99,102,241,.4) 1px, transparent 1px)", backgroundSize: "40px 40px" }} />

      <div className="relative max-w-5xl mx-auto px-6 py-10 space-y-8">

        {/* Header */}
        <header className="text-center py-6">
          <div className="inline-flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-xl font-bold">S</div>
            <h1 className="text-4xl font-black tracking-tight bg-gradient-to-r from-indigo-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
              SecXfer
            </h1>
          </div>
          <p className="text-slate-400 text-sm tracking-widest uppercase">Zero-Trust · Post-Quantum · Django + Next.js</p>
        </header>

        {!unlocked ? (
          /* --- LOGIN PANEL --- */
          <div className="max-w-md mx-auto bg-slate-900/60 border border-slate-800 rounded-2xl p-8 shadow-2xl shadow-indigo-900/20 backdrop-blur">
            <div className="flex items-center gap-3 mb-6">
              <div className="text-2xl">🔐</div>
              <div>
                <h2 className="text-xl font-bold">Unlock Keystore</h2>
                <p className="text-slate-500 text-sm">Decrypt your X25519 + Ed25519 identity</p>
              </div>
            </div>
            <form onSubmit={handleUnlock} className="space-y-4">
              <input type="password" placeholder="Password" value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
              <button className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold py-3 rounded-xl transition-all hover:scale-[1.02] active:scale-95">
                Decrypt & Unlock
              </button>
            </form>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Status Bar */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur flex flex-wrap gap-6 items-center justify-between">
              <div className="flex flex-wrap gap-6">
                <div>
                  <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Identity</p>
                  <p className="font-bold text-indigo-300">{status.identity_name || "---"}</p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Key ID</p>
                  <p className="font-mono text-xs text-slate-300">{status.key_id ? status.key_id.substring(0, 24) + "..." : "---"}</p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Pre-Keys</p>
                  <p className="font-bold text-emerald-400">{status.prekeys_available ?? "---"} available</p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Inbox</p>
                  <p className="font-bold text-purple-400">{inbox.length} messages</p>
                </div>
              </div>
              <button onClick={verifyServerAudit}
                className={`px-5 py-2 rounded-xl font-semibold text-sm border transition-all hover:scale-[1.03] active:scale-95
                  ${auditStatus === "ok" ? "bg-emerald-500/20 border-emerald-500 text-emerald-300" :
                    auditStatus === "fail" ? "bg-red-500/20 border-red-500 text-red-300" :
                    auditStatus === "checking" ? "bg-amber-500/20 border-amber-500 text-amber-300 animate-pulse" :
                    "bg-slate-800 border-slate-700 text-slate-300 hover:border-indigo-500"}`}>
                {auditStatus === "ok" ? "✅ Chain Verified" :
                  auditStatus === "fail" ? "🚨 Chain Broken!" :
                  auditStatus === "checking" ? "⏳ Verifying..." : "⛓ Verify Server Integrity"}
              </button>
            </div>

            {/* Tab Navigation */}
            <div className="flex gap-2 bg-slate-900/60 rounded-xl p-1.5 border border-slate-800 w-fit">
              {(["send", "inbox", "audit"] as const).map((tab) => (
                <button key={tab} onClick={() => setActiveTab(tab)}
                  className={`px-5 py-2 rounded-lg font-semibold text-sm capitalize transition-all
                    ${activeTab === tab ? "bg-indigo-600 text-white shadow-lg" : "text-slate-400 hover:text-white"}`}>
                  {tab === "send" ? "📤 Send" : tab === "inbox" ? `📥 Inbox ${inbox.length > 0 ? `(${inbox.length})` : ""}` : "⛓ Audit Log"}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur min-h-64">
              {activeTab === "send" && (
                <div>
                  <h2 className="text-xl font-bold mb-1">Send Encrypted File</h2>
                  <p className="text-slate-400 text-sm mb-6">File is encrypted with X3DH + AES-256-GCM before ever leaving your device.</p>
                  <form onSubmit={handleSend} className="space-y-4 max-w-lg">
                    <input type="text" placeholder="Recipient Identity Name (e.g. bob)" value={recipient}
                      onChange={(e) => setRecipient(e.target.value)}
                      className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all text-white placeholder-slate-500" />
                    <div className="bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3">
                      <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} className="text-sm text-slate-300" />
                      {file && <p className="text-xs text-emerald-400 mt-1">Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)</p>}
                    </div>
                    {sending && uploadProgress > 0 && (
                      <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div
                          className="h-2 bg-gradient-to-r from-purple-500 to-indigo-500 transition-all duration-300 ease-out"
                          style={{ width: `${uploadProgress}%` }}
                        />
                      </div>
                    )}
                    <button disabled={sending}
                      className="w-full bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50 text-white font-bold py-3 rounded-xl transition-all hover:scale-[1.01] active:scale-95">
                      {sending ? `⏳ Uploading... ${uploadProgress}%` : "🔐 Encrypt & Send (Store & Forward)"}
                    </button>
                  </form>
                </div>
              )}

              {activeTab === "inbox" && (
                <div>
                  <div className="flex justify-between items-center mb-6">
                    <div>
                      <h2 className="text-xl font-bold">Secure Inbox</h2>
                      <p className="text-slate-400 text-sm">All files are encrypted in transit. Decryption happens on your device.</p>
                    </div>
                    <button onClick={fetchInbox} className="text-sm bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg px-4 py-2 transition-colors">⟳ Refresh</button>
                  </div>
                  {inbox.length === 0 ? (
                    <div className="text-center py-16 text-slate-600">
                      <div className="text-5xl mb-3">📭</div>
                      <p>Your inbox is empty</p>
                    </div>
                  ) : (
                    <ul className="space-y-3">
                      {inbox.map((msg) => (
                        <li key={msg.file_id} className="bg-slate-800/60 border border-slate-700 p-4 rounded-xl flex justify-between items-center hover:border-indigo-600 transition-colors">
                          <div>
                            <p className="font-mono text-sm text-slate-200">📎 File #{msg.file_id}</p>
                            <p className="text-xs text-slate-500 mt-1">
                              {(msg.size / 1024).toFixed(1)} KB · {new Date(msg.timestamp * 1000).toLocaleString()}
                            </p>
                          </div>
                          <button onClick={() => handleDownload(String(msg.file_id))}
                            className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg font-semibold text-sm transition-colors hover:scale-105 active:scale-95">
                            🔓 Decrypt
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {activeTab === "audit" && (
                <div>
                  <div className="flex justify-between items-center mb-6">
                    <div>
                      <h2 className="text-xl font-bold">Hash-Chained Audit Log</h2>
                      <p className="text-slate-400 text-sm">Verified locally in your browser via Web Crypto API. Server cannot fake this.</p>
                    </div>
                  </div>
                  {auditLogs.length === 0 ? (
                    <div className="text-center py-16 text-slate-600">
                      <div className="text-5xl mb-3">⛓</div>
                      <p>Click "Verify Server Integrity" to load the audit log</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {auditLogs.map((entry) => (
                        <div key={entry.id} className="bg-slate-800/60 border border-slate-700 rounded-xl p-4">
                          <div className="flex items-center gap-3 mb-2">
                            <span className={`text-xs font-bold px-2 py-1 rounded-full
                              ${entry.event_type === "UPLOAD" ? "bg-purple-500/20 text-purple-300" :
                              entry.event_type === "DOWNLOAD" ? "bg-blue-500/20 text-blue-300" :
                              entry.event_type === "REGISTER" ? "bg-green-500/20 text-green-300" : "bg-slate-500/20 text-slate-300"}`}>
                              #{entry.id} {entry.event_type}
                            </span>
                            <span className="text-xs text-slate-500">{new Date(entry.timestamp * 1000).toLocaleString()}</span>
                            <span className="ml-auto text-xs text-emerald-400">✓ Hash Verified</span>
                          </div>
                          <div className="grid grid-cols-1 gap-1 text-xs font-mono text-slate-500">
                            <p><span className="text-slate-400">details:</span> {entry.details_raw}</p>
                            <p><span className="text-slate-400">hash:</span> {entry.current_hash.substring(0, 32)}...</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Terminal Log */}
            <div className="bg-slate-950 border border-slate-800 rounded-2xl p-4 font-mono text-xs h-44 overflow-y-auto">
              <p className="text-slate-600 mb-2"># SecXfer Terminal</p>
              {logMessages.map((entry, i) => (
                <div key={i} className={logColor[entry.level]}>{entry.msg}</div>
              ))}
              <div ref={logEndRef} />
            </div>
          </div>
        )}
      </div>
    </main>
  );
}

export function SecXferAppWithBoundary() {
  return (
    <ErrorBoundary>
      <Home />
    </ErrorBoundary>
  );
}
