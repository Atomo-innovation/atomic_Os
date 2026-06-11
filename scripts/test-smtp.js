#!/usr/bin/env node
/**
 * Quick SMTP connectivity test for registration OTP emails.
 * Usage: node scripts/test-smtp.js
 * Reads SMTP settings from meshcentral-data/config.json or .env
 */
'use strict';

const fs = require('fs');
const path = require('path');

function loadDotEnv() {
    const envPath = path.join(__dirname, '..', '.env');
    if (!fs.existsSync(envPath)) return;
    fs.readFileSync(envPath, 'utf8').split(/\r?\n/).forEach(function (line) {
        line = line.trim();
        if (!line || line[0] === '#') return;
        const eq = line.indexOf('=');
        if (eq < 0) return;
        const key = line.substring(0, eq).trim();
        let val = line.substring(eq + 1).trim();
        if (val.length >= 2 && ((val[0] === '"' && val[val.length - 1] === '"') || (val[0] === "'" && val[val.length - 1] === "'"))) {
            val = val.substring(1, val.length - 1);
        }
        if (key && process.env[key] === undefined) process.env[key] = val;
    });
}

loadDotEnv();

const configPath = path.join(__dirname, '..', 'meshcentral-data', 'config.json');
let smtp = {};
if (fs.existsSync(configPath)) {
    try { smtp = JSON.parse(fs.readFileSync(configPath, 'utf8')).smtp || {}; } catch (e) { }
}
const user = process.env.SMTP_USER || smtp.user;
const pass = process.env.SMTP_PASS || smtp.pass;
const to = process.argv[2] || user;

if (!user || !pass || pass === 'APP_PASSWORD_HERE') {
    console.error('SMTP not configured. Set user/pass in meshcentral-data/config.json or .env (SMTP_USER, SMTP_PASS).');
    process.exit(1);
}

const nodemailer = require('nodemailer');
const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: user, pass: pass }
});

console.log('Testing Gmail SMTP as', user, '...');
transport.verify(function (err) {
    if (err) {
        console.error('SMTP verify FAILED:', err.code || err.message, err.command || '');
        if (err.code === 'ECONNECTION') {
            console.error('\nThis is a NETWORK problem — the server cannot reach Gmail.');
            console.error('Check: internet access, DNS, firewall, ISP blocking port 587/465.');
        } else if (err.code === 'EAUTH') {
            console.error('\nThis is an AUTH problem — wrong app password or 2FA not enabled on Gmail.');
        }
        process.exit(1);
    }
    console.log('SMTP verify OK. Sending test email to', to, '...');
    transport.sendMail({
        from: user,
        to: to,
        subject: 'Atomic Center SMTP Test',
        text: 'If you received this, registration OTP emails will work.'
    }, function (sendErr, info) {
        if (sendErr) {
            console.error('Send FAILED:', sendErr.code || sendErr.message);
            process.exit(1);
        }
        console.log('Test email sent successfully.', info && info.response ? info.response : '');
        process.exit(0);
    });
});
