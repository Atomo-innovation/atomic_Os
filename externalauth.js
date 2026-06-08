/**
* @description MeshCentral external (Node application) authentication bridge.
*
* This module lets MeshCentral validate a username + password against an
* external Node application. It is intentionally minimal: the ONLY thing
* shared between the two systems is the username and the password.
*
* There is NO dashboard sync, NO profile sync, NO registration sync,
* NO device sync, NO form sync and NO user-data sync. MeshCentral keeps
* working exactly as before; this is purely an additional login path.
*
* Configuration is read from the environment variable NODE_AUTH_API, which
* can be placed in a `.env` file at the MeshCentral root. Example:
*     NODE_AUTH_API=http://localhost:3000/api/auth/external-login
*
* @license Apache-2.0
*/

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

var envLoaded = false;

// Load a `.env` file located at the MeshCentral root into process.env (only
// values that are not already defined in the real environment). This is a tiny
// self-contained parser so no extra npm dependency is required.
function loadDotEnv() {
    if (envLoaded) { return; }
    envLoaded = true;
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
            // Strip optional surrounding quotes.
            if ((val.length >= 2) && (((val[0] === '"') && (val[val.length - 1] === '"')) || ((val[0] === "'") && (val[val.length - 1] === "'")))) {
                val = val.substring(1, val.length - 1);
            }
            if ((key.length > 0) && (process.env[key] === undefined)) { process.env[key] = val; }
        }
    } catch (ex) { /* Ignore .env parsing problems and fall back to the real environment. */ }
}

// Return the configured external Node auth API URL, or null when not configured.
function getAuthApiUrl() {
    loadDotEnv();
    var u = process.env.NODE_AUTH_API;
    if (typeof u !== 'string') { return null; }
    u = u.trim();
    return (u.length > 0) ? u : null;
}

// Returns true when external authentication is configured/enabled.
function isEnabled() {
    return (getAuthApiUrl() != null);
}

// Verify a username + password against the external Node application.
//   callback(success<boolean>, info<object|null>)
// `info` is the parsed JSON body returned by the Node app (may contain an
// optional `username` / `email` to use when creating the MeshCentral user).
function verifyCredentials(username, password, callback) {
    var apiUrl = getAuthApiUrl();
    if (apiUrl == null) { callback(false, null); return; }

    var parsed;
    try { parsed = new URL(apiUrl); } catch (ex) { callback(false, null); return; }

    var payload = JSON.stringify({ username: username, password: password });
    var isHttps = (parsed.protocol === 'https:');
    var lib = isHttps ? https : http;
    var options = {
        method: 'POST',
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + (parsed.search || ''),
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'Accept': 'application/json'
        },
        timeout: 10000
    };

    var done = false;
    function finish(success, info) { if (done) { return; } done = true; callback(success, info); }

    var req = lib.request(options, function (res) {
        var body = '';
        res.on('data', function (chunk) { body += chunk; if (body.length > 65536) { try { req.destroy(); } catch (e) { } } });
        res.on('end', function () {
            var data = null;
            try { data = JSON.parse(body); } catch (ex) { data = null; }
            // Treat any HTTP 2xx as success, unless the body explicitly says { success: false }.
            var ok = ((res.statusCode >= 200) && (res.statusCode < 300));
            if (ok && data && (data.success === false)) { ok = false; }
            finish(ok, data);
        });
    });
    req.on('error', function () { finish(false, null); });
    req.on('timeout', function () { try { req.destroy(); } catch (e) { } finish(false, null); });
    req.write(payload);
    req.end();
}

module.exports.getAuthApiUrl = getAuthApiUrl;
module.exports.isEnabled = isEnabled;
module.exports.verifyCredentials = verifyCredentials;
