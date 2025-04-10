const fs = require('fs');
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
// RSA Encryption
function rsaEncrypt(text, publicKeyPath) {
    try {
        const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
        const buffer = Buffer.from(text, 'utf8');
        const encrypted = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            buffer
        );
        return encrypted.toString('base64');
    } catch (error) {
        throw new Error('RSA encryption failed: ' + error.message);
    }
}

// RSA Decryption
function rsaDecrypt(encryptedText, privateKeyPath) {
    try {
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        const buffer = Buffer.from(encryptedText, 'base64');
        const decrypted = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            buffer
        );
        return decrypted.toString('utf8');
    } catch (error) {
        throw new Error('RSA decryption failed: ' + error.message);
    }
}
// Encryption Endpoint
app.post('/encrypt', (req, res) => {
    const { text, algorithm, key } = req.body;

    if (!text || !algorithm) {
        return res.status(400).json({ error: 'Missing text or algorithm' });
    }

    try {
        let result;
        if (algorithm === 'otp') {
            if (!key) throw new Error('Missing key for OTP');
            result = { encrypted: otpEncrypt(text, key) };
        } else if (algorithm === '3des') {
            if (!key) throw new Error('Missing key for 3DES');
            result = des3Encrypt(text, key);
        } else if (algorithm === 'rsa') {
            // For RSA, we don't need the key from client as we use server's public key
            result = { encrypted: rsaEncrypt(text, './public_key.pem') };
        } else {

            if (!key) throw new Error('Missing key for AES');
            result = aesEncrypt(text, key, algorithm);
        }
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// Decryption Endpoint
app.post('/decrypt', (req, res) => {
    const { encryptedText, algorithm, key, iv } = req.body;

    if (!encryptedText || !algorithm) {
        return res.status(400).json({ error: 'Missing encrypted text or algorithm' });
    }

    try {
        let decrypted;
        if (algorithm === 'otp') {
            if (!key) throw new Error('Missing key for OTP');
            decrypted = otpDecrypt(encryptedText, key);
        } else if (algorithm === '3des') {
            if (!key || !iv) throw new Error('Missing key or IV for 3DES');
            decrypted = des3Decrypt(encryptedText, key, iv);
        } else if (algorithm === 'rsa') {
            // For RSA, we use server's private key
            decrypted = rsaDecrypt(encryptedText, './private_key.pem');
        } else {
            if (!key || !iv) throw new Error('Missing key or IV for AES');
            decrypted = aesDecrypt(encryptedText, key, algorithm, iv);
        }
        res.json({ decrypted });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));