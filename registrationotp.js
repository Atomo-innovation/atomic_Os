/**
 * @description Email OTP verification for account registration
 * @license Apache-2.0
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

(function loadDotEnv() {
    try {
        const envPath = path.join(__dirname, '.env');
        if (!fs.existsSync(envPath)) { return; }
        const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if ((line.length === 0) || (line[0] === '#')) { continue; }
            var eq = line.indexOf('=');
            if (eq < 0) { continue; }
            var key = line.substring(0, eq).trim();
            var val = line.substring(eq + 1).trim();
            if ((val.length >= 2) && (((val[0] === '"') && (val[val.length - 1] === '"')) || ((val[0] === "'") && (val[val.length - 1] === "'")))) {
                val = val.substring(1, val.length - 1);
            }
            if ((key.length > 0) && (process.env[key] === undefined)) { process.env[key] = val; }
        }
    } catch (ex) { }
})();

const OTP_VALIDITY_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 5;

module.exports.createRegistrationOtp = function (parent, db) {
    var obj = {};
    var rateLimitMap = {};

    function getSmtpConfig(domain) {
        if (domain && domain.smtp) { return domain.smtp; }
        if (parent.config && parent.config.smtp) { return parent.config.smtp; }
        return {
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT || '587', 10),
            user: process.env.SMTP_USER || 'tirthkuchara@gmail.com',
            pass: process.env.SMTP_PASS || '',
            from: process.env.SMTP_USER || 'tirthkuchara@gmail.com',
            name: 'Atomic Center'
        };
    }

    function generateOtp() {
        var bigInt;
        do { bigInt = crypto.randomBytes(4).readUInt32BE(0); } while (bigInt >= 4200000000);
        var otp = bigInt % 100000000;
        return String(otp).padStart(8, '0');
    }

    function hashOtp(otp) {
        var salt = crypto.randomBytes(16);
        var hash = crypto.scryptSync(String(otp), salt, 64);
        return salt.toString('base64') + ':' + hash.toString('base64');
    }

    function verifyOtpHash(otp, stored) {
        if (typeof stored != 'string') { return false; }
        var parts = stored.split(':');
        if (parts.length != 2) { return false; }
        try {
            var salt = Buffer.from(parts[0], 'base64');
            var hash = Buffer.from(parts[1], 'base64');
            var testHash = crypto.scryptSync(String(otp), salt, 64);
            if (hash.length != testHash.length) { return false; }
            return crypto.timingSafeEqual(hash, testHash);
        } catch (ex) {
            return false;
        }
    }

    function maskEmail(email) {
        if (typeof email != 'string' || email.indexOf('@') < 1) { return 'your email'; }
        var parts = email.split('@');
        var local = parts[0];
        var domain = parts[1];
        if (local.length <= 2) { return local[0] + '***@' + domain; }
        return local[0] + '***' + local[local.length - 1] + '@' + domain;
    }

    function checkRateLimit(key) {
        var now = Date.now();
        if (rateLimitMap[key] == null) { rateLimitMap[key] = []; }
        rateLimitMap[key] = rateLimitMap[key].filter(function (t) { return (now - t) < RATE_LIMIT_WINDOW_MS; });
        if (rateLimitMap[key].length >= RATE_LIMIT_MAX_REQUESTS) { return false; }
        rateLimitMap[key].push(now);
        return true;
    }

    function encryptPendingData(data) {
        return parent.encodeCookie(data, parent.loginCookieEncryptionKey, 10);
    }

    function decryptPendingData(token) {
        return parent.decodeCookie(token, parent.loginCookieEncryptionKey, 10);
    }

    function sendOtpEmail(domain, email, otp, func) {
        var smtp = getSmtpConfig(domain);
        if (!smtp.pass || smtp.pass === 'APP_PASSWORD_HERE') {
            if (func) { func('SMTP not configured'); }
            return;
        }

        var from = smtp.from || smtp.user;
        var subject = 'Atomic Center Verification Code';
        var text = 'Your Atomic Center verification code is:\n\n' + otp + '\n\nThis code expires in 10 minutes.';
        var html = '<p>Your Atomic Center verification code is:</p><p style="font-size:24px;font-weight:bold;letter-spacing:4px;">' + otp + '</p><p>This code expires in 10 minutes.</p>';

        if (domain && domain.mailserver != null) {
            domain.mailserver.sendRegistrationOtpMail(domain, email, otp, func);
            return;
        }

        try {
            var nodemailer = require('nodemailer');
            var options = { host: smtp.host, port: smtp.port, secure: (smtp.tls === true), auth: { user: smtp.user, pass: smtp.pass } };
            if (String(smtp.user).toLowerCase().endsWith('@gmail.com')) {
                options = { service: 'gmail', auth: { user: smtp.user, pass: smtp.pass } };
            }
            var transport = nodemailer.createTransport(options);
            transport.sendMail({ from: from, to: email, subject: subject, text: text, html: html }, function (err) {
                if (func) { func(err); }
            });
        } catch (ex) {
            if (func) { func(ex); }
        }
    }

    obj.OTP_VALIDITY_MS = OTP_VALIDITY_MS;
    obj.RESEND_COOLDOWN_MS = RESEND_COOLDOWN_MS;
    obj.MAX_ATTEMPTS = MAX_ATTEMPTS;
    obj.maskEmail = maskEmail;

    obj.createAndSend = function (domain, email, pendingData, clientIp, func) {
        email = String(email).toLowerCase().trim();
        var rateKey = email + ':' + (clientIp || '');
        if (!checkRateLimit(rateKey)) {
            if (func) { func('rate_limit'); }
            return;
        }

        var otp = generateOtp();
        var now = Date.now();
        var record = {
            id: crypto.randomBytes(16).toString('hex'),
            email: email,
            otpHash: hashOtp(otp),
            createdAt: now,
            expiresAt: now + OTP_VALIDITY_MS,
            attempts: 0,
            verified: false,
            lastSentAt: now,
            domain: domain.id,
            pendingData: encryptPendingData(pendingData)
        };

        db.RemoveRegistrationOtpByEmail(email, domain.id, function () {
            db.SetRegistrationOtp(record, function (err) {
                if (err) { if (func) { func('db_error'); } return; }
                sendOtpEmail(domain, email, otp, function (sendErr) {
                    if (sendErr) {
                        db.RemoveRegistrationOtp(record.id, function () { });
                        if (func) { func('email_error'); }
                        return;
                    }
                    if (func) { func(null, record.id, maskEmail(email)); }
                });
            });
        });
    };

    obj.resend = function (otpId, domain, clientIp, func) {
        db.GetRegistrationOtpById(otpId, function (err, record) {
            if (err || record == null || record.domain != domain.id || record.verified === true) {
                if (func) { func('not_found'); }
                return;
            }
            var now = Date.now();
            if (record.expiresAt <= now) {
                db.RemoveRegistrationOtp(otpId, function () { });
                if (func) { func('expired'); }
                return;
            }
            if (record.lastSentAt && (now - record.lastSentAt) < RESEND_COOLDOWN_MS) {
                if (func) { func('cooldown', Math.ceil((RESEND_COOLDOWN_MS - (now - record.lastSentAt)) / 1000)); }
                return;
            }
            var rateKey = record.email + ':' + (clientIp || '');
            if (!checkRateLimit(rateKey)) {
                if (func) { func('rate_limit'); }
                return;
            }

            var otp = generateOtp();
            record.otpHash = hashOtp(otp);
            record.lastSentAt = now;
            record.attempts = 0;
            record.expiresAt = now + OTP_VALIDITY_MS;

            db.SetRegistrationOtp(record, function (err2) {
                if (err2) { if (func) { func('db_error'); } return; }
                sendOtpEmail(domain, record.email, otp, function (sendErr) {
                    if (sendErr) { if (func) { func('email_error'); } return; }
                    if (func) { func(null, Math.ceil(RESEND_COOLDOWN_MS / 1000)); }
                });
            });
        });
    };

    obj.verify = function (otpId, otpInput, domain, func) {
        if (typeof otpInput != 'string' || !/^\d{8}$/.test(otpInput.trim())) {
            if (func) { func('invalid_format'); }
            return;
        }
        otpInput = otpInput.trim();

        db.GetRegistrationOtpById(otpId, function (err, record) {
            if (err || record == null || record.domain != domain.id || record.verified === true) {
                if (func) { func('not_found'); }
                return;
            }
            var now = Date.now();
            if (record.expiresAt <= now) {
                db.RemoveRegistrationOtp(otpId, function () { });
                if (func) { func('expired'); }
                return;
            }
            if (record.attempts >= MAX_ATTEMPTS) {
                db.RemoveRegistrationOtp(otpId, function () { });
                if (func) { func('max_attempts'); }
                return;
            }

            if (!verifyOtpHash(otpInput, record.otpHash)) {
                record.attempts = (record.attempts || 0) + 1;
                if (record.attempts >= MAX_ATTEMPTS) {
                    db.RemoveRegistrationOtp(otpId, function () { });
                    if (func) { func('max_attempts'); }
                    return;
                }
                db.SetRegistrationOtp(record, function () {
                    if (func) { func('invalid', MAX_ATTEMPTS - record.attempts); }
                });
                return;
            }

            var pending = decryptPendingData(record.pendingData);
            if (pending == null) {
                db.RemoveRegistrationOtp(otpId, function () { });
                if (func) { func('not_found'); }
                return;
            }

            record.verified = true;
            db.SetRegistrationOtp(record, function () {
                db.RemoveRegistrationOtp(otpId, function () {
                    if (func) { func(null, pending); }
                });
            });
        });
    };

    return obj;
};
