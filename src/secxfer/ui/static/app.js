const $ = (id) => document.getElementById(id);

function log(msg, type='info') {
    const logs = $('logs');
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    const time = new Date().toLocaleTimeString();
    entry.textContent = `[${time}] ${msg}`;
    logs.appendChild(entry);
    logs.scrollTop = logs.scrollHeight;
}

async function checkStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        
        const ident = $('status-identity');
        const keyid = $('status-keyid');

        if (data.exists) {
            ident.textContent = "Found (On Disk)";
            ident.className = "value";
            $('keygen-panel').classList.add('hidden');
            
            if (data.unlocked) {
                ident.textContent = "Unlocked & Ready";
                keyid.textContent = data.key_id;
                $('unlock-panel').classList.add('hidden');
                $('action-panel').classList.remove('hidden');
            } else {
                $('unlock-panel').classList.remove('hidden');
                $('action-panel').classList.add('hidden');
            }
        } else {
            ident.textContent = "Not Found";
            ident.className = "value offline";
            $('keygen-panel').classList.remove('hidden');
            $('unlock-panel').classList.add('hidden');
            $('action-panel').classList.add('hidden');
        }
    } catch (e) {
        log("Failed to connect to backend UI server.", "error");
    }
}

function switchTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    
    document.querySelector(`button[onclick="switchTab('${tabId}')"]`).classList.add('active');
    $(`tab-${tabId}`).classList.remove('hidden');
}

// Event Listeners
$('keygen-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('password', $('keygen-password').value);
    fd.append('duress_password', $('keygen-duress').value);
    fd.append('entropy', $('keygen-entropy').value);

    log("Generating cryptographic identity...", "info");
    const res = await fetch('/api/keygen', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.error) log(`Keygen failed: ${data.error}`, "error");
    else {
        log("Identity generated successfully!", "success");
        $('keygen-password').value = "";
        $('keygen-duress').value = "";
        $('keygen-entropy').value = "";
        await checkStatus();
    }
});

$('unlock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('password', $('unlock-password').value);

    log("Decrypting private keys...", "info");
    const res = await fetch('/api/unlock', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.error) log(`Unlock failed: ${data.error}`, "error");
    else {
        log(`Unlocked Identity. KeyID: ${data.key_id}`, "success");
        $('unlock-password').value = "";
        await checkStatus();
    }
});

$('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const serverUrl = $('register-server').value || "http://127.0.0.1:54321";
    log(`Registering with Key Directory at ${serverUrl}...`, "info");
    
    const fd = new FormData();
    fd.append('server_url', serverUrl);
    
    const res = await fetch('/api/register', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.error) log(`Registration failed: ${data.error}`, "error");
    else log("Successfully registered with Key Directory.", "success");
});


$('send-file').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        e.target.nextElementSibling.textContent = `Selected: ${file.name} (${(file.size/1024).toFixed(1)} KB)`;
    }
});

$('send-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = $('send-file').files[0];
    if (!file) return;

    const fd = new FormData();
    fd.append('target_key_id', $('send-target').value);
    fd.append('server_url', $('send-server').value || 'http://127.0.0.1:54321');
    fd.append('file', file);
    fd.append('pqc_psk', $('send-pqc').value);

    log(`Uploading encrypted file to ${$('send-server').value} for ${$('send-target').value}...`, "info");
    const btn = e.target.querySelector('button');
    btn.textContent = "Sending...";
    btn.disabled = true;

    try {
        const res = await fetch('/api/send', { method: 'POST', body: fd });
        const data = await res.json();
        if (data.error) log(`Transfer failed: ${data.error}`, "error");
        else log("File sent successfully!", "success");
    } catch(err) {
        log(`Network error: ${err}`, "error");
    } finally {
        btn.textContent = "Encrypt & Send";
        btn.disabled = false;
        $('send-file').value = "";
        $('send-file').nextElementSibling.textContent = "Drag & Drop file here or click to select";
    }
});

$('inbox-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const server_url = $('inbox-server').value;
    log(`Checking inbox at ${server_url}...`, "info");
    const btn = e.target.querySelector('button');
    btn.textContent = "Checking...";
    btn.disabled = true;

    try {
        const res = await fetch(`/api/inbox?server_url=${encodeURIComponent(server_url)}`);
        const data = await res.json();
        if (data.error) {
            log(`Inbox check failed: ${data.error}`, "error");
        } else {
            const list = $('inbox-list');
            list.innerHTML = "";
            if (data.inbox.length === 0) {
                list.innerHTML = "<p>Inbox is empty.</p>";
            } else {
                data.inbox.forEach(file => {
                    const div = document.createElement('div');
                    div.style = "padding: 10px; background: rgba(255,255,255,0.05); margin-bottom: 5px; border-radius: 4px; display: flex; justify-content: space-between;";
                    div.innerHTML = `
                        <div>
                            <strong>Sender ID:</strong> ${file.sender_key_id}<br>
                            <strong>Size:</strong> ${(file.size/1024).toFixed(1)} KB<br>
                            <strong>Date:</strong> ${new Date(file.timestamp * 1000).toLocaleString()}
                        </div>
                        <button class="btn secondary" onclick="downloadFile(${file.file_id})">Download</button>
                    `;
                    list.appendChild(div);
                });
            }
            log("Inbox refreshed.", "success");
        }
    } catch(err) {
        log(`Network error: ${err}`, "error");
    } finally {
        btn.textContent = "Check Inbox";
        btn.disabled = false;
    }
});

async function downloadFile(file_id) {
    const server_url = $('inbox-server').value;
    const pqc_psk = $('receive-pqc').value;
    log(`Downloading and decrypting file ${file_id}...`, "info");
    
    const fd = new FormData();
    fd.append('file_id', file_id);
    fd.append('server_url', server_url);
    fd.append('pqc_psk', pqc_psk);
    
    try {
        const res = await fetch('/api/download', { method: 'POST', body: fd });
        const data = await res.json();
        if (data.error) log(`Download failed: ${data.error}`, "error");
        else log(`File downloaded and decrypted successfully! Check keystore/downloads directory.`, "success");
    } catch(err) {
        log(`Network error: ${err}`, "error");
    }
}

// Init
checkStatus();
setInterval(checkStatus, 5000);

async function verifyServerAudit() {
    const server_url = $('audit-server').value;
    log(`Fetching cryptographic audit log from ${server_url}...`, "info");
    
    try {
        const res = await fetch(`/api/audit?server_url=${encodeURIComponent(server_url)}`);
        const data = await res.json();
        
        if (data.error) {
            log(`Audit fetch failed: ${data.error}`, "error");
            return;
        }
        
        const logs = data.log;
        if (!logs || logs.length === 0) {
            log("Audit log is empty.", "info");
            return;
        }
        
        let previous_hash = "GENESIS_HASH";
        for (let i = 0; i < logs.length; i++) {
            const entry = logs[i];
            
            const hash_input = `${entry.event_type}|${entry.details_raw}|${entry.timestamp}|${previous_hash}`;
            
            const msgBuffer = new TextEncoder().encode(hash_input);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const current_hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            if (entry.previous_hash !== previous_hash) {
                log(`[CRITICAL] Chain broken at block ${entry.id}. Expected previous hash ${previous_hash}, got ${entry.previous_hash}. SERVER TAMPERING DETECTED!`, "error");
                return;
            }
            if (current_hash !== entry.current_hash) {
                log(`[CRITICAL] Data manipulation detected at block ${entry.id}. Calculated hash ${current_hash} != ${entry.current_hash}. SERVER TAMPERING DETECTED!`, "error");
                return;
            }
            
            previous_hash = current_hash;
        }
        
        log(`Success! Cryptographic integrity verified for all ${logs.length} blocks in the server audit log. No tampering detected.`, "success");
        
    } catch(err) {
        log(`Network error: ${err}`, "error");
    }
}
