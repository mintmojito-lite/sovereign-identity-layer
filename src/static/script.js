const P = 2n ** 256n - 189n;

// Modular Exponentiation: base^exp % mod
function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) result = (result * base) % modulus;
        exponent = exponent >> 1n;
        base = (base * base) % modulus;
    }
    return result;
}

function generateMasterKey() {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    const hex = "0x" + Array.from(array).map(b => b.toString(16).padStart(2, "0")).join("");
    return BigInt(hex) % P;
}

// State
let currentMasterKey = null;
let currentUserId = null;
let activeSessionToken = null;

// DOM Elements
const views = {
    register: document.getElementById('view-register'),
    login: document.getElementById('view-login'),
    dashboard: document.getElementById('view-dashboard')
};

const tabs = {
    register: document.getElementById('tab-register'),
    login: document.getElementById('tab-login')
};

// Log Helper
function log(msg, type = 'info') {
    const el = document.getElementById('console-output');
    const line = document.createElement('div');
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    if (type === 'error') line.style.color = '#f85149';
    if (type === 'success') line.style.color = '#2ea043';
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

// Switch View
function showView(viewName) {
    Object.values(views).forEach(el => el.classList.add('hidden'));
    views[viewName].classList.remove('hidden');

    // Update tabs
    if (viewName === 'register') {
        tabs.register.classList.add('active');
        tabs.login.classList.remove('active');
    } else if (viewName === 'login') {
        tabs.login.classList.add('active');
        tabs.register.classList.remove('active');
    }
}

// 1. Register
document.getElementById('btn-register').addEventListener('click', async () => {
    const userId = document.getElementById('reg-user-id').value.trim();
    if (!userId) return alert('Please enter User ID');

    // Generate Key
    currentMasterKey = generateMasterKey();
    log(`Generated Master Key (x): ${currentMasterKey.toString().substring(0, 16)}...`, 'success');

    // Save locally for convenience
    localStorage.setItem(`sdi_l_key_${userId}`, currentMasterKey.toString());

    // Register with Server (Sending x as public_ver_key per PoC)
    try {
        const res = await fetch('/register_device', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: userId,
                public_ver_key: currentMasterKey.toString() // Send as string
            })
        });
        const data = await res.json();
        if (res.ok) {
            log(`Registration Successful: ${data.message}`, 'success');
            currentUserId = userId;
            // Switch to Login
            document.getElementById('login-user-id').value = userId;
            showView('login');
        } else {
            log(`Error: ${data.error}`, 'error');
        }
    } catch (e) {
        log(`Network Error: ${e.message}`, 'error');
    }
});

// 2. Login Flow
document.getElementById('btn-login').addEventListener('click', async () => {
    const userId = document.getElementById('login-user-id').value.trim();
    if (!userId) return alert('Enter User ID');

    // Load Key
    const keyStr = localStorage.getItem(`sdi_l_key_${userId}`);
    if (!keyStr) {
        log('No key found for this user in local storage. Please register first.', 'error');
        return;
    }
    currentMasterKey = BigInt(keyStr);
    currentUserId = userId;

    log('Starting ZKP Login Sequence...');

    try {
        // Step A: Get Challenge
        log('Requesting Challenge...');
        const resChallenge = await fetch('/generate_challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId })
        });
        const dataChallenge = await resChallenge.json();

        if (!resChallenge.ok) throw new Error(dataChallenge.error);

        const challenge = BigInt(dataChallenge.challenge);
        log(`Challenge Received: ${challenge.toString().substring(0, 16)}...`);

        // Step B: Calculate Proof (C^x mod P)
        log('Calculating Proof (C^x mod P)...');
        const proof = modPow(challenge, currentMasterKey, P);
        log(`Proof Generated: ${proof.toString().substring(0, 16)}...`);

        // Step C: Verify
        log('Sending Proof to Server...');
        const resVerify = await fetch('/verify_proof', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: userId,
                challenge: challenge.toString(),
                proof: proof.toString()
            })
        });
        const dataVerify = await resVerify.json();

        if (resVerify.ok && dataVerify.verified) {
            log('Identity Verified! Session Token Received.', 'success');
            activeSessionToken = dataVerify.token;
            // Show Dashboard
            setupDashboard();
            showView('dashboard');
        } else {
            log(`Verification Failed: ${dataVerify.error}`, 'error');
        }

    } catch (e) {
        log(`Login Error: ${e.message}`, 'error');
    }
});

// Dashboard
function setupDashboard() {
    document.getElementById('dash-user-id').textContent = activeSessionToken.user_id;
    document.getElementById('dash-token-id').textContent = activeSessionToken.token_id;
    document.getElementById('dash-expires').textContent = new Date(activeSessionToken.expires_at * 1000).toLocaleString();
}

document.getElementById('btn-validate').addEventListener('click', async () => {
    if (!activeSessionToken) return;
    try {
        const res = await fetch('/validate_session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: activeSessionToken.user_id,
                token: activeSessionToken
            })
        });
        const data = await res.json();
        if (data.valid) log('Session is Valid ✅', 'success');
        else log('Session is Invalid ❌', 'error');
    } catch (e) { log(e.message, 'error'); }
});

document.getElementById('btn-revoke').addEventListener('click', async () => {
    if (!activeSessionToken) return;
    try {
        const res = await fetch('/revoke_session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: activeSessionToken.user_id })
        });
        if (res.ok) {
            log('Session Revoked.', 'info');
            showView('login');
            activeSessionToken = null;
        }
    } catch (e) { log(e.message, 'error'); }
});

// Tab Listeners
tabs.register.onclick = () => showView('register');
tabs.login.onclick = () => showView('login');
