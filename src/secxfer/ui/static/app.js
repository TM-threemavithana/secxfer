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
    fd.append('target_host', $('send-host').value || '127.0.0.1');
    fd.append('target_port', $('send-port').value || '9090');
    fd.append('file', file);
    fd.append('pqc_psk', $('send-pqc').value);

    log(`Starting encrypted P2P transfer to ${$('send-target').value} @ ${$('send-host').value}:${$('send-port').value}...`, "info");
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

$('receive-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('port', $('receive-port').value);
    fd.append('pqc_psk', $('receive-pqc').value);

    log(`Listening for incoming transfer on port ${$('receive-port').value}...`, "info");
    const btn = e.target.querySelector('button');
    btn.textContent = "Listening...";
    btn.disabled = true;

    try {
        const res = await fetch('/api/receive', { method: 'POST', body: fd });
        const data = await res.json();
        if (data.error) log(`Receive failed: ${data.error}`, "error");
        else log("File received successfully! Check keystore/downloads directory.", "success");
    } catch(err) {
        log(`Network error: ${err}`, "error");
    } finally {
        btn.textContent = "Listen for Transfer";
        btn.disabled = false;
    }
});

// Init
checkStatus();
setInterval(checkStatus, 5000);
