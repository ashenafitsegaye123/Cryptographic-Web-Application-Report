const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 5000;

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Generate a random IV for AES (16 bytes)
function generateIV() {
    return crypto.randomBytes(16);
}

// One-Time Pad (OTP) Encryption
// One-Time Pad (OTP) Encryption - Fixed to require key length >= text length
function otpEncrypt(text, key) {
    if (key.length < text.length) {
        throw new Error('OTP key must be at least as long as the text');
    }
    
    let encrypted = '';
    for (let i = 0; i < text.length; i++) {
        const charCode = text.charCodeAt(i) ^ key.charCodeAt(i);
        encrypted += String.fromCharCode(charCode);
    }
    return Buffer.from(encrypted).toString('base64');
}

// One-Time Pad (OTP) Decryption - Fixed with same requirement
function otpDecrypt(encryptedText, key) {
    const buffer = Buffer.from(encryptedText, 'base64');
    if (key.length < buffer.length) {
        throw new Error('OTP key must be at least as long as the encrypted text');
    }
    
    let decrypted = '';
    for (let i = 0; i < buffer.length; i++) {
        const charCode = buffer[i] ^ key.charCodeAt(i);
        decrypted += String.fromCharCode(charCode);
    }
    return decrypted;
}

// 3DES Encryption
function des3Encrypt(text, key) {
    const keyBuffer = crypto.createHash('sha256').update(key).digest().slice(0, 24); // 24 bytes for 3DES
    const iv = generateIV().slice(0, 8); // 8 bytes for 3DES
    const cipher = crypto.createCipheriv('des-ede3-cbc', keyBuffer, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') }; // Return IV with ciphertext
}

// 3DES Decryption
function des3Decrypt(encryptedText, key, iv) {
    const keyBuffer = crypto.createHash('sha256').update(key).digest().slice(0, 24); // 24 bytes for 3DES
    const decipher = crypto.createDecipheriv('des-ede3-cbc', keyBuffer, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// AES Encryption
function aesEncrypt(text, key, algorithm) {
    const keyBuffer = crypto.createHash('sha256').update(key).digest().slice(0, getKeySize(algorithm));
    const iv = generateIV(); // 16 bytes for AES
    const cipher = crypto.createCipheriv(algorithm, keyBuffer, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') }; // Return IV with ciphertext
}

// AES Decryption
function aesDecrypt(encryptedText, key, algorithm, iv) {
    const keyBuffer = crypto.createHash('sha256').update(key).digest().slice(0, getKeySize(algorithm));
    const decipher = crypto.createDecipheriv(algorithm, keyBuffer, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Get key size for AES
function getKeySize(algorithm) {
    return {
        'aes-256-cbc': 32,
        'aes-192-cbc': 24,
        'aes-128-cbc': 16
    }[algorithm] || 32;
}

// Encryption Endpoint
app.post('/encrypt', (req, res) => {
    const { text, algorithm, key } = req.body;

    if (!text || !algorithm || !key) {
        return res.status(400).json({ error: 'Missing text, algorithm, or key' });
    }

    try {
        let result;
        if (algorithm === 'otp') {
            result = { encrypted: otpEncrypt(text, key) };
        } else if (algorithm === '3des') {
            result = des3Encrypt(text, key);
        } else {
            result = aesEncrypt(text, key, algorithm);
        }
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Encryption failed', details: error.message });
    }
});

// Decryption Endpoint
app.post('/decrypt', (req, res) => {
    const { encryptedText, algorithm, key, iv } = req.body;

    if (!encryptedText || !algorithm || !key) {
        return res.status(400).json({ error: 'Missing encrypted text, algorithm, or key' });
    }

    try {
        let decrypted;
        if (algorithm === 'otp') {
            decrypted = otpDecrypt(encryptedText, key);
        } else if (algorithm === '3des') {
            decrypted = des3Decrypt(encryptedText, key, iv);
        } else {
            decrypted = aesDecrypt(encryptedText, key, algorithm, iv);
        }
        res.json({ decrypted });
    } catch (error) {
        res.status(500).json({ error: 'Decryption failed. Wrong key or algorithm?', details: error.message });
    }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));