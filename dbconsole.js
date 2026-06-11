/**
* @description Hidden developer/admin database console for MeshCentral (SQLite).
* @author Atomic Center
* @license Apache-2.0
*
* Self-contained module. It registers a hidden, password-protected web UI on the
* main MeshCentral Express app (same port, so it works on localhost and AWS with
* no extra ports/Security-Group rules). Browsing uses a read-only SQLite connection;
* row deletion uses a separate writable connection and POST /api/deleteRow only.
*
* ---------------------------------------------------------------------------
* CONFIGURATION (all optional, code defaults below are used if not set)
* ---------------------------------------------------------------------------
* meshcentral-data/config.json -> "settings": { "dbconsole": {
*     "path": "/_dbconsole",                // hidden route (configurable from code)
*     "password": "<strong-password>",      // overrides the code default below
*     "enabled": true
* }}
* Environment override (handy on AWS, no file edit needed):
*     MESHCENTRAL_DBCONSOLE_PASSWORD=<strong-password>
* ---------------------------------------------------------------------------
*/

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ===========================================================================
// CODE DEFAULTS (edit here). Requirement: password is stored in code/config,
// NOT user-created, and is a strong random password (never a 4-digit PIN).
// ===========================================================================
const DEFAULTS = {
    CONSOLE_PATH: '/_dbconsole',                                   // Hidden route name
    COOKIE_NAME: 'mc_dbconsole',                                   // Session cookie name
    // Strong, randomly generated default password (40+ chars). Change for production.
    PASSWORD: 'atomo3004@',
    SESSION_MS: 1000 * 60 * 60,                                    // Session lifetime: 1 hour
    MAX_FAILED_ATTEMPTS: 5,                                        // Failures before lockout (per IP)
    ATTEMPT_WINDOW_MS: 1000 * 60 * 15,                            // Rolling window for counting failures
    LOCKOUT_MS: 1000 * 60 * 15,                                   // Lockout duration after threshold
    GLOBAL_SEARCH_LIMIT: 300,                                     // Max matches returned by global search
    PER_TABLE_SEARCH_LIMIT: 100,                                  // Max matches per table in global search
    EXPORT_ROW_LIMIT: 100000,                                     // Safety cap for CSV export
    MAX_PAGE_SIZE: 500                                            // Max rows per browse page
};

module.exports.CreateDbConsole = function (parent, args) {
    const obj = {};
    obj.parent = parent;
    obj.args = args;

    // ---- Resolve configuration (config.json -> env -> code default) --------
    const cfg = (parent.config && parent.config.settings && parent.config.settings.dbconsole) ? parent.config.settings.dbconsole : {};
    obj.enabled = (cfg.enabled !== false);
    obj.consolePath = (typeof cfg.path === 'string' && cfg.path.length > 0) ? cfg.path : DEFAULTS.CONSOLE_PATH;
    if (obj.consolePath[0] !== '/') { obj.consolePath = '/' + obj.consolePath; }
    obj.cookieName = (typeof cfg.cookieName === 'string' && cfg.cookieName.length > 0) ? cfg.cookieName : DEFAULTS.COOKIE_NAME;
    obj.password = process.env['MESHCENTRAL_DBCONSOLE_PASSWORD'] || (typeof cfg.password === 'string' && cfg.password.length > 0 ? cfg.password : DEFAULTS.PASSWORD);
    obj.readonly = true; // Browse/export remain read-only; delete uses a separate writable connection.
    obj.deleteEnabled = true;

    // SQLite internal tables that must never be modified via the console.
    const PROTECTED_TABLES = { sqlite_master: 1, sqlite_sequence: 1, sqlite_stat1: 1, sqlite_stat4: 1 };

    // Friendly views map to a real table + primary key column for safe deletes.
    const VIEW_DELETE_MAP = {
        atomic_center_users: { target: 'main', key: 'id' },
        atomic_center_device_groups: { target: 'main', key: 'id' },
        atomic_center_devices: { target: 'main', key: 'id' },
        atomic_center_registration_otp: { target: 'registration_otp', key: 'id' },
        atomic_center_recent_events: { target: 'events', key: 'id' }
    };

    // ---- Resolve SQLite database file path (same logic as db.js) -----------
    function resolveDbFile() {
        try {
            const s = parent.config && parent.config.settings ? parent.config.settings : {};
            let name = 'meshcentral';
            if (s.sqlite3 != null) { name = (typeof s.sqlite3 === 'string') ? s.sqlite3 : (s.sqlite3.name || 'meshcentral'); }
            return path.join(parent.datapath, name + '.sqlite');
        } catch (ex) { return null; }
    }
    obj.dbFile = resolveDbFile();

    // ---- Per-process signing secret (restart invalidates all sessions) -----
    const sessionSecret = crypto.randomBytes(48);

    // ---- In-memory brute-force tracking (per client IP) --------------------
    const failTracker = {}; // ip -> { count, firstAt, lockedUntil }
    const sessionModes = {}; // auth token -> 'readonly' | 'delete'

    // ---- Audit log ---------------------------------------------------------
    function auditLogFile() { return path.join(parent.datapath, 'dbconsole-audit.log'); }
    function audit(req, event, detail) {
        try {
            const line = JSON.stringify({
                time: new Date().toISOString(),
                ip: clientIp(req),
                ua: (req && req.headers) ? (req.headers['user-agent'] || '') : '',
                event: event,
                detail: detail || ''
            }) + '\n';
            fs.appendFile(auditLogFile(), line, function () { });
        } catch (ex) { /* never throw from audit */ }
    }
    function auditDelete(req, table, rowid, data) {
        try {
            const line = JSON.stringify({
                time: new Date().toISOString(),
                ip: clientIp(req),
                ua: (req && req.headers) ? (req.headers['user-agent'] || '') : '',
                event: 'row_deleted',
                table: table,
                rowid: rowid,
                data: data || null
            }) + '\n';
            fs.appendFile(auditLogFile(), line, function () { });
        } catch (ex) { /* never throw from audit */ }
    }

    function clientIp(req) {
        if (!req) return '';
        const xf = req.headers ? (req.headers['x-forwarded-for'] || '') : '';
        if (xf) return String(xf).split(',')[0].trim();
        return (req.ip) || (req.connection && req.connection.remoteAddress) || (req.socket && req.socket.remoteAddress) || '';
    }

    function isSecureReq(req) {
        if (req.secure) return true;
        const xfp = req.headers ? req.headers['x-forwarded-proto'] : null;
        return (xfp === 'https');
    }

    // ---- Token (signed cookie) helpers ------------------------------------
    function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
    function createToken() {
        const payload = b64url(JSON.stringify({ exp: Date.now() + DEFAULTS.SESSION_MS, n: b64url(crypto.randomBytes(9)) }));
        const sig = b64url(crypto.createHmac('sha256', sessionSecret).update(payload).digest());
        return payload + '.' + sig;
    }
    function verifyToken(token) {
        if (typeof token !== 'string' || token.indexOf('.') < 0) return false;
        const parts = token.split('.');
        if (parts.length !== 2) return false;
        const expSig = b64url(crypto.createHmac('sha256', sessionSecret).update(parts[0]).digest());
        const a = Buffer.from(parts[1]); const b = Buffer.from(expSig);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
        try {
            const payload = JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
            return (typeof payload.exp === 'number' && payload.exp > Date.now());
        } catch (ex) { return false; }
    }

    function parseCookies(req) {
        const out = {};
        const raw = req.headers ? req.headers.cookie : null;
        if (!raw) return out;
        raw.split(';').forEach(function (c) {
            const i = c.indexOf('=');
            if (i > 0) { out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim()); }
        });
        return out;
    }

    function isAuthed(req) {
        const c = parseCookies(req);
        return verifyToken(c[obj.cookieName]);
    }
    function getSessionToken(req) {
        const c = parseCookies(req);
        return (c && c[obj.cookieName]) ? c[obj.cookieName] : null;
    }
    function getConsoleMode(req) {
        const tok = getSessionToken(req);
        if (!tok || !verifyToken(tok)) return 'readonly';
        return (sessionModes[tok] === 'delete') ? 'delete' : 'readonly';
    }
    function setConsoleMode(req, mode) {
        const tok = getSessionToken(req);
        if (tok && verifyToken(tok)) { sessionModes[tok] = (mode === 'delete') ? 'delete' : 'readonly'; }
    }
    function clearConsoleMode(req) {
        const tok = getSessionToken(req);
        if (tok) { delete sessionModes[tok]; }
    }

    // ---- Secure password check + rate limiting ----------------------------
    function checkLockout(ip) {
        const t = failTracker[ip];
        if (t && t.lockedUntil && t.lockedUntil > Date.now()) { return Math.ceil((t.lockedUntil - Date.now()) / 1000); }
        return 0;
    }
    function registerFailure(ip) {
        const now = Date.now();
        let t = failTracker[ip];
        if (!t || (now - t.firstAt) > DEFAULTS.ATTEMPT_WINDOW_MS) { t = { count: 0, firstAt: now, lockedUntil: 0 }; }
        t.count++;
        if (t.count >= DEFAULTS.MAX_FAILED_ATTEMPTS) { t.lockedUntil = now + DEFAULTS.LOCKOUT_MS; }
        failTracker[ip] = t;
    }
    function clearFailures(ip) { delete failTracker[ip]; }

    function passwordMatches(provided) {
        if (typeof provided !== 'string') return false;
        // Constant-time comparison over fixed-length digests to avoid length/timing leaks.
        const a = crypto.createHash('sha256').update(String(provided)).digest();
        const b = crypto.createHash('sha256').update(String(obj.password)).digest();
        return crypto.timingSafeEqual(a, b);
    }

    // ===================================================================
    // SQLite access layer (read-only for browse; writable for delete only)
    // ===================================================================
    let sqlite3 = null;
    let roDb = null;
    let rwDb = null;
    function getDb(callback) {
        if (roDb) return callback(null, roDb);
        if (!obj.dbFile || !fs.existsSync(obj.dbFile)) { return callback(new Error('SQLite database file not found. The console supports SQLite databases only.')); }
        try { if (sqlite3 == null) { sqlite3 = require('sqlite3'); } } catch (ex) { return callback(new Error('sqlite3 module not available.')); }
        roDb = new sqlite3.Database(obj.dbFile, sqlite3.OPEN_READONLY, function (err) {
            if (err) { roDb = null; return callback(err); }
            callback(null, roDb);
        });
    }
    function getRwDb(callback) {
        if (rwDb) return callback(null, rwDb);
        if (!obj.dbFile || !fs.existsSync(obj.dbFile)) { return callback(new Error('SQLite database file not found. The console supports SQLite databases only.')); }
        try { if (sqlite3 == null) { sqlite3 = require('sqlite3'); } } catch (ex) { return callback(new Error('sqlite3 module not available.')); }
        rwDb = new sqlite3.Database(obj.dbFile, sqlite3.OPEN_READWRITE, function (err) {
            if (err) { rwDb = null; return callback(err); }
            callback(null, rwDb);
        });
    }
    function all(sql, params, callback) { getDb(function (e, db) { if (e) return callback(e); db.all(sql, params || [], callback); }); }
    function get(sql, params, callback) { getDb(function (e, db) { if (e) return callback(e); db.get(sql, params || [], callback); }); }

    function quoteId(name) { return '"' + String(name).replace(/"/g, '""') + '"'; }
    function isProtectedTable(name) {
        if (typeof name !== 'string' || name.length === 0) return true;
        const lower = name.toLowerCase();
        if (lower.indexOf('sqlite_') === 0) return true;
        return PROTECTED_TABLES[lower] === 1;
    }
    function isValidTableName(name) {
        return (typeof name === 'string' && /^[A-Za-z0-9_]+$/.test(name));
    }
    function parseRowid(rowid) {
        const rid = parseInt(rowid, 10);
        if (!Number.isFinite(rid) || rid < 1) return null;
        return rid;
    }
    function getViewDeleteTarget(viewName) {
        return VIEW_DELETE_MAP[viewName] || null;
    }
    function notifyMeshCentralRecordDeleted(deletedRow) {
        try {
            const ws = obj.parent && obj.parent.webserver;
            if (!ws || !deletedRow) { return; }
            const recordId = (typeof deletedRow.id === 'string') ? deletedRow.id : null;
            const recordType = (typeof deletedRow.type === 'string') ? deletedRow.type : null;
            if (recordId && (recordType === 'user' || recordId.indexOf('user/') === 0)) {
                if (typeof ws.purgeUserAccount === 'function') { ws.purgeUserAccount(recordId); }
            }
        } catch (ex) { console.log('DB console: failed to notify MeshCentral of deleted user: ' + ex); }
    }
    function deleteRowRecord(table, rowid, callback) {
        getRwDb(function (err, db) {
            if (err) return callback(err);
            const qTable = quoteId(table);
            db.serialize(function () {
                db.run('BEGIN IMMEDIATE');
                db.get('SELECT rowid AS _rowid, * FROM ' + qTable + ' WHERE rowid = ?', [rowid], function (e, row) {
                    if (e) { db.run('ROLLBACK'); return callback(e); }
                    if (!row) { db.run('ROLLBACK'); return callback(new Error('row_not_found')); }
                    db.run('DELETE FROM ' + qTable + ' WHERE rowid = ?', [rowid], function (e2) {
                        if (e2) { db.run('ROLLBACK'); return callback(e2); }
                        if (this.changes === 0) { db.run('ROLLBACK'); return callback(new Error('row_not_found')); }
                        db.run('COMMIT', function (e3) {
                            if (e3) { db.run('ROLLBACK'); return callback(e3); }
                            callback(null, row);
                        });
                    });
                });
            });
        });
    }
    function deleteByKeyRecord(sourceTable, targetTable, keyColumn, keyValue, callback) {
        if (keyColumn !== 'id') { return callback(new Error('invalid_key_column')); }
        if (isProtectedTable(targetTable) || !isValidTableName(targetTable)) { return callback(new Error('invalid_table')); }
        getRwDb(function (err, db) {
            if (err) return callback(err);
            const qTable = quoteId(targetTable);
            const qKey = quoteId(keyColumn);
            db.serialize(function () {
                db.run('BEGIN IMMEDIATE');
                db.get('SELECT rowid AS _rowid, * FROM ' + qTable + ' WHERE ' + qKey + ' = ?', [keyValue], function (e, row) {
                    if (e) { db.run('ROLLBACK'); return callback(e); }
                    if (!row) { db.run('ROLLBACK'); return callback(new Error('row_not_found')); }
                    db.run('DELETE FROM ' + qTable + ' WHERE ' + qKey + ' = ?', [keyValue], function (e2) {
                        if (e2) { db.run('ROLLBACK'); return callback(e2); }
                        if (this.changes === 0) { db.run('ROLLBACK'); return callback(new Error('row_not_found')); }
                        db.run('COMMIT', function (e3) {
                            if (e3) { db.run('ROLLBACK'); return callback(e3); }
                            row._sourceView = sourceTable;
                            row._deletedFrom = targetTable;
                            callback(null, row);
                        });
                    });
                });
            });
        });
    }

    function listTables(callback) {
        all("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name", [], function (err, rows) {
            if (err) return callback(err);
            callback(null, rows.map(function (r) { return { name: r.name, type: r.type }; }));
        });
    }
    function validateTable(table, callback) {
        listTables(function (err, tables) {
            if (err) return callback(err);
            const found = tables.find(function (t) { return t.name === table; });
            callback(null, found || null);
        });
    }
    function getColumns(table, callback) {
        all('PRAGMA table_info(' + quoteId(table) + ')', [], function (err, rows) {
            if (err) return callback(err);
            callback(null, rows.map(function (r) { return { name: r.name, type: r.type, notnull: r.notnull, pk: r.pk, dflt: r.dflt_value }; }));
        });
    }
    function getIndexes(table, callback) {
        all('PRAGMA index_list(' + quoteId(table) + ')', [], function (err, rows) {
            if (err) return callback(null, []);
            callback(null, rows || []);
        });
    }

    // Run a SELECT trying rowid first (for inspection/jump), falling back if unsupported.
    function selectWithRowid(table, where, params, order, limit, offset, callback) {
        const tail = (where ? (' WHERE ' + where) : '') + (order ? (' ORDER BY ' + order) : '') + (limit != null ? (' LIMIT ' + limit) : '') + (offset ? (' OFFSET ' + offset) : '');
        const withRid = 'SELECT rowid AS _rowid, * FROM ' + quoteId(table) + tail;
        all(withRid, params, function (err, rows) {
            if (!err) return callback(null, rows, true);
            const noRid = 'SELECT * FROM ' + quoteId(table) + tail;
            all(noRid, params, function (err2, rows2) { if (err2) return callback(err2); callback(null, rows2, false); });
        });
    }

    // ===================================================================
    // HTTP helpers
    // ===================================================================
    function sendJson(res, code, data) { res.status(code).set('Content-Type', 'application/json; charset=utf-8').set('X-Robots-Tag', 'noindex, nofollow').send(JSON.stringify(data)); }
    function requireAuth(req, res, next) {
        if (isAuthed(req)) return next();
        audit(req, 'api_unauthorized', req.path);
        return sendJson(res, 401, { error: 'unauthorized' });
    }

    // ===================================================================
    // Register routes on the Express app
    // ===================================================================
    obj.register = function (app) {
        if (!obj.enabled) { return; }
        const express = require('express');
        const router = express.Router();
        router.use(express.json({ limit: '256kb' }));
        router.use(express.urlencoded({ extended: false, limit: '256kb' }));
        // Make sure search engines / proxies never index the hidden console.
        router.use(function (req, res, next) { res.set('X-Robots-Tag', 'noindex, nofollow, noarchive'); next(); });

        // ---- Login / session ------------------------------------------
        router.post('/api/login', function (req, res) {
            const ip = clientIp(req);
            const wait = checkLockout(ip);
            if (wait > 0) { audit(req, 'login_blocked_lockout', wait + 's remaining'); return sendJson(res, 429, { error: 'too_many_attempts', retryAfter: wait }); }
            const provided = (req.body && typeof req.body.password === 'string') ? req.body.password : '';
            if (passwordMatches(provided)) {
                clearFailures(ip);
                audit(req, 'login_success', '');
                const secure = isSecureReq(req);
                const token = createToken();
                sessionModes[token] = 'readonly';
                const cookie = obj.cookieName + '=' + token + '; HttpOnly; SameSite=Strict; Path=' + obj.consolePath + '; Max-Age=' + Math.floor(DEFAULTS.SESSION_MS / 1000) + (secure ? '; Secure' : '');
                res.set('Set-Cookie', cookie);
                return sendJson(res, 200, { ok: true, consoleMode: 'readonly' });
            } else {
                registerFailure(ip);
                const remaining = Math.max(0, DEFAULTS.MAX_FAILED_ATTEMPTS - ((failTracker[ip] && failTracker[ip].count) || 0));
                audit(req, 'login_failed', 'remaining=' + remaining);
                const nowLocked = checkLockout(ip);
                if (nowLocked > 0) { return sendJson(res, 429, { error: 'too_many_attempts', retryAfter: nowLocked }); }
                return sendJson(res, 401, { error: 'invalid_password', attemptsRemaining: remaining });
            }
        });

        router.post('/api/logout', function (req, res) {
            audit(req, 'logout', '');
            clearConsoleMode(req);
            res.set('Set-Cookie', obj.cookieName + '=; HttpOnly; SameSite=Strict; Path=' + obj.consolePath + '; Max-Age=0');
            sendJson(res, 200, { ok: true });
        });

        router.get('/api/session', function (req, res) {
            const authed = isAuthed(req);
            sendJson(res, 200, {
                authenticated: authed,
                readonly: obj.readonly,
                deleteEnabled: obj.deleteEnabled,
                consoleMode: authed ? getConsoleMode(req) : 'readonly',
                deletableViews: Object.keys(VIEW_DELETE_MAP)
            });
        });

        router.post('/api/mode', requireAuth, function (req, res) {
            const mode = (req.body && typeof req.body.mode === 'string') ? req.body.mode.trim() : '';
            if (mode !== 'readonly' && mode !== 'delete') {
                return sendJson(res, 400, { error: 'invalid_mode' });
            }
            setConsoleMode(req, mode);
            audit(req, 'mode_change', mode);
            sendJson(res, 200, { ok: true, consoleMode: mode });
        });

        // ---- Database metadata ----------------------------------------
        router.get('/api/tables', requireAuth, function (req, res) {
            listTables(function (err, tables) {
                if (err) return sendJson(res, 500, { error: err.message });
                let pending = tables.length, out = [];
                if (pending === 0) return sendJson(res, 200, { tables: [] });
                tables.forEach(function (t) {
                    get('SELECT COUNT(*) AS c FROM ' + quoteId(t.name), [], function (e, row) {
                        out.push({ name: t.name, type: t.type, rows: (row && row.c != null) ? row.c : null });
                        if (--pending === 0) { out.sort(function (a, b) { return a.name.localeCompare(b.name); }); sendJson(res, 200, { tables: out }); }
                    });
                });
            });
        });

        router.get('/api/schema', requireAuth, function (req, res) {
            const table = req.query.table;
            validateTable(table, function (err, t) {
                if (err) return sendJson(res, 500, { error: err.message });
                if (!t) return sendJson(res, 404, { error: 'unknown_table' });
                getColumns(table, function (e, cols) {
                    if (e) return sendJson(res, 500, { error: e.message });
                    getIndexes(table, function (e2, idx) { sendJson(res, 200, { table: table, type: t.type, columns: cols, indexes: idx || [] }); });
                });
            });
        });

        // ---- Browse with pagination / search / sort / filters ----------
        // filters: JSON array of { col, op, value } ; logic: 'AND' | 'OR'
        function buildWhere(cols, query, callback) {
            const colNames = cols.map(function (c) { return c.name; });
            const clauses = [], params = [];
            // free-text search across all columns
            const search = (typeof query.search === 'string') ? query.search.trim() : '';
            if (search.length > 0) {
                const sub = colNames.map(function (c) { params.push('%' + search + '%'); return 'CAST(' + quoteId(c) + ' AS TEXT) LIKE ?'; });
                if (sub.length) clauses.push('(' + sub.join(' OR ') + ')');
            }
            // advanced filters
            let filters = [];
            try { if (query.filters) { filters = JSON.parse(query.filters); } } catch (ex) { filters = []; }
            const logic = (String(query.logic).toUpperCase() === 'OR') ? ' OR ' : ' AND ';
            const validOps = { 'eq': '= ?', 'neq': '<> ?', 'like': 'LIKE ?', 'gt': '> ?', 'gte': '>= ?', 'lt': '< ?', 'lte': '<= ?', 'null': 'IS NULL', 'notnull': 'IS NOT NULL' };
            const fClauses = [];
            (Array.isArray(filters) ? filters : []).forEach(function (f) {
                if (!f || colNames.indexOf(f.col) < 0) return;
                const opSql = validOps[f.op];
                if (!opSql) return;
                if (f.op === 'null' || f.op === 'notnull') { fClauses.push(quoteId(f.col) + ' ' + opSql); }
                else if (f.op === 'like') { fClauses.push('CAST(' + quoteId(f.col) + ' AS TEXT) LIKE ?'); params.push('%' + String(f.value) + '%'); }
                else { fClauses.push(quoteId(f.col) + ' ' + opSql); params.push(f.value); }
            });
            if (fClauses.length) { clauses.push('(' + fClauses.join(logic) + ')'); }
            callback(clauses.join(' AND '), params);
        }

        router.get('/api/browse', requireAuth, function (req, res) {
            const table = req.query.table;
            validateTable(table, function (err, t) {
                if (err) return sendJson(res, 500, { error: err.message });
                if (!t) return sendJson(res, 404, { error: 'unknown_table' });
                getColumns(table, function (e, cols) {
                    if (e) return sendJson(res, 500, { error: e.message });
                    const colNames = cols.map(function (c) { return c.name; });
                    const page = Math.max(1, parseInt(req.query.page) || 1);
                    const pageSize = Math.min(DEFAULTS.MAX_PAGE_SIZE, Math.max(1, parseInt(req.query.pageSize) || 50));
                    let order = '';
                    if (req.query.sort && colNames.indexOf(req.query.sort) >= 0) {
                        const dir = (String(req.query.dir).toUpperCase() === 'DESC') ? 'DESC' : 'ASC';
                        order = quoteId(req.query.sort) + ' ' + dir;
                    }
                    buildWhere(cols, req.query, function (where, params) {
                        get('SELECT COUNT(*) AS c FROM ' + quoteId(table) + (where ? (' WHERE ' + where) : ''), params, function (e2, countRow) {
                            if (e2) return sendJson(res, 500, { error: e2.message });
                            const total = (countRow && countRow.c != null) ? countRow.c : 0;
                            selectWithRowid(table, where, params, order, pageSize, (page - 1) * pageSize, function (e3, rows, hasRowid) {
                                if (e3) return sendJson(res, 500, { error: e3.message });
                                sendJson(res, 200, { table: table, tableType: t.type, columns: colNames, rows: rows, total: total, page: page, pageSize: pageSize, hasRowid: hasRowid });
                            });
                        });
                    });
                });
            });
        });

        // ---- Delete a single record (writable connection) -------------
        router.post('/api/deleteRow', requireAuth, function (req, res) {
            if (!obj.deleteEnabled) { return sendJson(res, 403, { error: 'delete_disabled', success: false }); }
            if (getConsoleMode(req) !== 'delete') {
                audit(req, 'delete_rejected', 'readonly_mode');
                return sendJson(res, 403, { error: 'readonly_mode', success: false });
            }
            const table = (req.body && typeof req.body.table === 'string') ? req.body.table.trim() : '';
            const rowid = parseRowid(req.body && req.body.rowid);
            const recordId = (req.body && req.body.recordId != null) ? String(req.body.recordId) : null;
            if (!isValidTableName(table) || isProtectedTable(table)) {
                audit(req, 'delete_rejected', 'invalid_table=' + table);
                return sendJson(res, 400, { error: 'invalid_table', success: false });
            }
            validateTable(table, function (err, t) {
                if (err) return sendJson(res, 500, { error: err.message, success: false });
                if (!t) {
                    audit(req, 'delete_rejected', 'unknown_table=' + table);
                    return sendJson(res, 404, { error: 'unknown_table', success: false });
                }
                const viewTarget = (t.type === 'view') ? getViewDeleteTarget(table) : null;
                if (t.type === 'view' && !viewTarget) {
                    audit(req, 'delete_rejected', 'view_table=' + table);
                    return sendJson(res, 400, { error: 'cannot_delete_view', success: false });
                }
                function finishDelete(auditKey, deletedRow) {
                    notifyMeshCentralRecordDeleted(deletedRow);
                    auditDelete(req, table, auditKey, deletedRow);
                    sendJson(res, 200, { success: true });
                }
                function handleDeleteError(msg, auditDetail) {
                    audit(req, 'delete_failed', auditDetail + ' ' + msg);
                    if (msg === 'row_not_found') { return sendJson(res, 404, { error: 'row_not_found', success: false }); }
                    return sendJson(res, 500, { error: msg, success: false });
                }
                if (viewTarget) {
                    if (recordId == null || recordId.length === 0) {
                        audit(req, 'delete_rejected', 'invalid_record_id view=' + table);
                        return sendJson(res, 400, { error: 'invalid_record_id', success: false });
                    }
                    deleteByKeyRecord(table, viewTarget.target, viewTarget.key, recordId, function (e2, deletedRow) {
                        if (e2) return handleDeleteError(e2.message || String(e2), table + ' recordId=' + recordId);
                        finishDelete(recordId, deletedRow);
                    });
                    return;
                }
                if (rowid == null) {
                    audit(req, 'delete_rejected', 'invalid_rowid');
                    return sendJson(res, 400, { error: 'invalid_rowid', success: false });
                }
                deleteRowRecord(table, rowid, function (e2, deletedRow) {
                    if (e2) return handleDeleteError(e2.message || String(e2), table + ' rowid=' + rowid);
                    finishDelete(rowid, deletedRow);
                });
            });
        });

        // ---- Inspect a single record ----------------------------------
        router.get('/api/row', requireAuth, function (req, res) {
            const table = req.query.table;
            const rowid = req.query.rowid;
            const recordId = (req.query.recordId != null) ? String(req.query.recordId) : null;
            validateTable(table, function (err, t) {
                if (err) return sendJson(res, 500, { error: err.message });
                if (!t) return sendJson(res, 404, { error: 'unknown_table' });
                const viewTarget = (t.type === 'view') ? getViewDeleteTarget(table) : null;
                if (viewTarget && recordId != null && recordId.length > 0) {
                    all('SELECT * FROM ' + quoteId(table) + ' WHERE ' + quoteId(viewTarget.key) + ' = ? LIMIT 1', [recordId], function (e, rows) {
                        if (e) return sendJson(res, 500, { error: e.message });
                        sendJson(res, 200, { table: table, row: (rows && rows[0]) || null });
                    });
                    return;
                }
                all('SELECT rowid AS _rowid, * FROM ' + quoteId(table) + ' WHERE rowid = ? LIMIT 1', [rowid], function (e, rows) {
                    if (e) return sendJson(res, 500, { error: e.message });
                    sendJson(res, 200, { table: table, row: (rows && rows[0]) || null });
                });
            });
        });

        // ---- Global search across all tables --------------------------
        router.get('/api/search', requireAuth, function (req, res) {
            const q = (typeof req.query.q === 'string') ? req.query.q.trim() : '';
            if (q.length === 0) return sendJson(res, 200, { results: [], q: q });
            const exact = (String(req.query.exact) === '1' || String(req.query.exact) === 'true');
            const onlyTable = (typeof req.query.table === 'string' && req.query.table.length) ? req.query.table : null;
            const onlyColumn = (typeof req.query.column === 'string' && req.query.column.length) ? req.query.column : null;
            listTables(function (err, tables) {
                if (err) return sendJson(res, 500, { error: err.message });
                if (onlyTable) { tables = tables.filter(function (t) { return t.name === onlyTable; }); }
                const results = [];
                let pending = tables.length;
                if (pending === 0) return sendJson(res, 200, { results: [], q: q });
                let stopped = false;
                tables.forEach(function (t) {
                    getColumns(t.name, function (e, cols) {
                        if (e || stopped) { if (--pending === 0 && !stopped) finish(); return; }
                        let useCols = cols.map(function (c) { return c.name; });
                        if (onlyColumn) { useCols = useCols.filter(function (c) { return c === onlyColumn; }); }
                        if (useCols.length === 0) { if (--pending === 0) finish(); return; }
                        const pattern = exact ? q : ('%' + q + '%');
                        const op = exact ? '= ?' : 'LIKE ?';
                        const params = [];
                        const sub = useCols.map(function (c) { params.push(pattern); return 'CAST(' + quoteId(c) + ' AS TEXT) ' + op; });
                        const sql = 'SELECT rowid AS _rowid, * FROM ' + quoteId(t.name) + ' WHERE ' + sub.join(' OR ') + ' LIMIT ' + DEFAULTS.PER_TABLE_SEARCH_LIMIT;
                        all(sql, params, function (e2, rows) {
                            if (!e2 && rows && rows.length) {
                                rows.forEach(function (row) {
                                    if (results.length >= DEFAULTS.GLOBAL_SEARCH_LIMIT) { stopped = true; return; }
                                    // find which columns matched (for highlighting)
                                    const matched = [];
                                    useCols.forEach(function (c) {
                                        const v = row[c];
                                        if (v == null) return;
                                        const sv = String(v).toLowerCase();
                                        if (exact ? (String(v) === q) : (sv.indexOf(q.toLowerCase()) >= 0)) matched.push(c);
                                    });
                                    results.push({ table: t.name, rowid: row._rowid, matchedColumns: matched, row: row });
                                });
                            }
                            if (--pending === 0) finish();
                        });
                    });
                });
                function finish() { sendJson(res, 200, { results: results.slice(0, DEFAULTS.GLOBAL_SEARCH_LIMIT), q: q, truncated: results.length >= DEFAULTS.GLOBAL_SEARCH_LIMIT }); }
            });
        });

        // ---- Database statistics --------------------------------------
        router.get('/api/stats', requireAuth, function (req, res) {
            listTables(function (err, tables) {
                if (err) return sendJson(res, 500, { error: err.message });
                let fileSize = 0, walSize = 0;
                try { fileSize = fs.statSync(obj.dbFile).size; } catch (ex) { }
                try { walSize = fs.statSync(obj.dbFile + '-wal').size; } catch (ex) { }
                let pending = tables.length, perTable = [], totalRows = 0;
                if (pending === 0) return sendJson(res, 200, { tableCount: 0, totalRows: 0, fileSize: fileSize, walSize: walSize, tables: [] });
                tables.forEach(function (t) {
                    get('SELECT COUNT(*) AS c FROM ' + quoteId(t.name), [], function (e, row) {
                        const c = (row && row.c != null) ? row.c : 0;
                        totalRows += c; perTable.push({ name: t.name, type: t.type, rows: c });
                        if (--pending === 0) {
                            perTable.sort(function (a, b) { return b.rows - a.rows; });
                            sendJson(res, 200, { tableCount: tables.length, totalRows: totalRows, fileSize: fileSize, walSize: walSize, dbFile: obj.dbFile, tables: perTable });
                        }
                    });
                });
            });
        });

        // ---- CSV export (respects current search/filter) --------------
        router.get('/api/export', requireAuth, function (req, res) {
            const table = req.query.table;
            validateTable(table, function (err, t) {
                if (err) return sendJson(res, 500, { error: err.message });
                if (!t) return sendJson(res, 404, { error: 'unknown_table' });
                getColumns(table, function (e, cols) {
                    if (e) return sendJson(res, 500, { error: e.message });
                    const colNames = cols.map(function (c) { return c.name; });
                    let order = '';
                    if (req.query.sort && colNames.indexOf(req.query.sort) >= 0) {
                        const dir = (String(req.query.dir).toUpperCase() === 'DESC') ? 'DESC' : 'ASC';
                        order = quoteId(req.query.sort) + ' ' + dir;
                    }
                    buildWhere(cols, req.query, function (where, params) {
                        const sql = 'SELECT ' + colNames.map(quoteId).join(', ') + ' FROM ' + quoteId(table) + (where ? (' WHERE ' + where) : '') + (order ? (' ORDER BY ' + order) : '') + ' LIMIT ' + DEFAULTS.EXPORT_ROW_LIMIT;
                        all(sql, params, function (e2, rows) {
                            if (e2) return sendJson(res, 500, { error: e2.message });
                            audit(req, 'export_csv', table + ' (' + (rows ? rows.length : 0) + ' rows)');
                            function csvCell(v) {
                                if (v == null) return '';
                                const s = String(v);
                                return (/[",\n\r]/.test(s)) ? ('"' + s.replace(/"/g, '""') + '"') : s;
                            }
                            let out = colNames.map(csvCell).join(',') + '\r\n';
                            (rows || []).forEach(function (r) { out += colNames.map(function (c) { return csvCell(r[c]); }).join(',') + '\r\n'; });
                            res.set('Content-Type', 'text/csv; charset=utf-8');
                            res.set('Content-Disposition', 'attachment; filename="' + table.replace(/[^a-zA-Z0-9_-]/g, '_') + '.csv"');
                            res.set('X-Robots-Tag', 'noindex, nofollow');
                            res.send(out);
                        });
                    });
                });
            });
        });

        // ---- The single-page UI ---------------------------------------
        router.get('/', function (req, res) {
            audit(req, 'page_view', '');
            res.set('Content-Type', 'text/html; charset=utf-8');
            res.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
            res.set('Cache-Control', 'no-store');
            res.send(renderHtml());
        });

        // Mount the router on the hidden path.
        app.use(obj.consolePath, router);
        console.log('Hidden DB console registered at ' + obj.consolePath + ' (browse read-only, row delete enabled).');
    };

    // ===================================================================
    // Front-end (self-contained single page, no external assets)
    // ===================================================================
    function renderHtml() {
        const base = obj.consolePath.replace(/"/g, '');
        return DBCONSOLE_HTML.replace(/__BASE__/g, base);
    }

    return obj;
};

// The whole UI is embedded so it works identically on localhost and AWS with no
// static-file path configuration.
const DBCONSOLE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Database Explorer</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--border:#2b3340;--text:#e6edf3;--muted:#8b949e;--accent:#2f81f7;--accent2:#1f6feb;--ok:#3fb950;--warn:#d29922;--err:#f85149;--mark:#bb8009;}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
button{font:inherit;cursor:pointer}
a{color:var(--accent)}
.hidden{display:none!important}
/* Login */
#login{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:radial-gradient(1200px 600px at 50% -10%,#11233f,#0d1117)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:34px;width:380px;max-width:92vw;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.card h1{margin:0 0 4px;font-size:20px}
.card p{margin:0 0 20px;color:var(--muted);font-size:13px}
.field{margin-bottom:14px}
input,select{width:100%;padding:10px 12px;background:var(--panel2);border:1px solid var(--border);border-radius:8px;color:var(--text);outline:none}
input:focus,select:focus{border-color:var(--accent)}
.btn{background:var(--accent2);color:#fff;border:0;border-radius:8px;padding:10px 14px;font-weight:600}
.btn:hover{background:var(--accent)}
.btn.sec{background:var(--panel2);border:1px solid var(--border)}
.btn.sec:hover{border-color:var(--accent)}
.btn.sm{padding:6px 10px;font-size:12px}
.msg{font-size:13px;margin-top:10px;min-height:18px}
.msg.err{color:var(--err)} .msg.ok{color:var(--ok)}
/* Layout */
#app{display:grid;grid-template-columns:280px 1fr;grid-template-rows:52px 1fr;height:100%}
header{grid-column:1/3;display:flex;align-items:center;gap:14px;padding:0 16px;background:var(--panel);border-bottom:1px solid var(--border)}
header .logo{font-weight:700;letter-spacing:.3px}
header .ro{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid}
header .ro.readonly-mode{color:var(--warn);border-color:var(--warn)}
header .ro.delete-mode{color:var(--ok);border-color:var(--ok)}
#modeToggle{min-width:148px;font-weight:600}
#modeToggle.mode-readonly{background:var(--panel2);border:1px solid var(--warn);color:var(--warn)}
#modeToggle.mode-delete{background:var(--err);border:1px solid var(--err);color:#fff}
#modeToggle.mode-delete:hover{opacity:.9}
.btn.danger{background:var(--err);color:#fff;border:0}
.btn.danger:hover{opacity:.9}
.btn.danger:disabled{opacity:.4;cursor:not-allowed}
.actions{display:flex;gap:4px;white-space:nowrap}
.actions .btn{padding:4px 8px;font-size:11px}
.toast{position:fixed;bottom:20px;right:20px;z-index:2000;padding:12px 16px;border-radius:8px;font-size:13px;box-shadow:0 8px 24px rgba(0,0,0,.4);max-width:360px}
.toast.ok{background:#1a3d2a;border:1px solid var(--ok);color:var(--ok)}
.toast.err{background:#3d1a1a;border:1px solid var(--err);color:var(--err)}
.delwarn{color:var(--err);font-size:13px;margin:12px 0}
.delinfo{background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:12px;margin:12px 0;font-size:13px}
.delinfo div{margin:4px 0}
.delconfirm{margin:14px 0}
.delconfirm label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}
.modal .foot{padding:14px 16px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end}
header .spacer{flex:1}
.gsearch{display:flex;gap:6px;align-items:center;width:46%}
.gsearch input{padding:7px 10px}
aside{background:var(--panel);border-right:1px solid var(--border);overflow:auto;padding:10px}
.navsec{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:14px 6px 6px}
.navitem{padding:7px 10px;border-radius:7px;display:flex;justify-content:space-between;gap:8px;cursor:pointer;color:var(--text)}
.navitem:hover{background:var(--panel2)}
.navitem.active{background:var(--accent2);color:#fff}
.navitem .count{font-size:11px;color:var(--muted)}
.navitem.active .count{color:#cfe3ff}
main{overflow:auto;padding:18px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.toolbar .title{font-size:18px;font-weight:700;margin-right:8px}
.toolbar .meta{color:var(--muted);font-size:12px}
.grow{flex:1}
table.data{width:100%;border-collapse:collapse;font-size:13px}
table.data th,table.data td{border-bottom:1px solid var(--border);padding:7px 9px;text-align:left;white-space:nowrap;max-width:380px;overflow:hidden;text-overflow:ellipsis}
table.data th{position:sticky;top:0;background:var(--panel2);cursor:pointer;user-select:none;z-index:1}
table.data tbody tr:hover{background:var(--panel2);cursor:pointer}
.tablewrap{border:1px solid var(--border);border-radius:10px;overflow:auto;max-height:calc(100vh - 230px)}
.pager{display:flex;gap:8px;align-items:center;margin-top:12px;flex-wrap:wrap}
.pill{background:var(--panel2);border:1px solid var(--border);border-radius:999px;padding:4px 10px;font-size:12px}
mark{background:var(--mark);color:#fff;padding:0 2px;border-radius:3px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;margin-bottom:18px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px}
.stat .k{color:var(--muted);font-size:12px}
.stat .v{font-size:24px;font-weight:700;margin-top:4px}
.bar{height:8px;background:var(--panel2);border-radius:6px;overflow:hidden}
.bar > i{display:block;height:100%;background:var(--accent)}
.filters{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:10px;margin-bottom:10px}
.frow{display:flex;gap:6px;margin-bottom:6px;flex-wrap:wrap}
.frow select,.frow input{width:auto;flex:1;min-width:120px}
/* Modal */
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:20px}
.modal .inner{background:var(--panel);border:1px solid var(--border);border-radius:12px;max-width:760px;width:100%;max-height:86vh;overflow:auto}
.modal .head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel)}
.kv{display:grid;grid-template-columns:200px 1fr;gap:0}
.kv > div{padding:8px 16px;border-bottom:1px solid var(--border);word-break:break-word}
.kv .key{color:var(--muted);background:var(--panel2)}
.tag{font-size:10px;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:1px 5px;margin-left:6px}
.empty{color:var(--muted);padding:30px;text-align:center}
@media (max-width:820px){#app{grid-template-columns:1fr}aside{display:none}.gsearch{width:60%}}
</style>
</head>
<body>
<!-- LOGIN -->
<div id="login">
  <form class="card" id="loginForm" autocomplete="off">
    <h1>Database Explorer</h1>
    <p>Restricted area. Authentication required.</p>
    <div class="field"><input type="password" id="pw" placeholder="Access password" autocomplete="off" autofocus></div>
    <button class="btn" style="width:100%" type="submit">Unlock</button>
    <div class="msg" id="loginMsg"></div>
  </form>
</div>

<!-- APP -->
<div id="app" class="hidden">
  <header>
    <span class="logo">&#128272; Database Explorer</span>
    <span class="ro readonly-mode" id="roBadge">READ-ONLY</span>
    <button class="btn sm" id="modeToggle" type="button" title="Switch between read-only and delete mode">Read-Only Mode</button>
    <div class="spacer"></div>
    <div class="gsearch">
      <input id="globalQ" placeholder="Global search across all tables...">
      <button class="btn sm" id="globalBtn">Search</button>
    </div>
    <button class="btn sec sm" id="logoutBtn">Logout</button>
  </header>
  <aside id="side">
    <div class="navsec">Explorer</div>
    <div class="navitem" data-view="stats"><span>&#128202; Statistics</span></div>
    <div class="navitem" data-view="search"><span>&#128269; Global Search</span></div>
    <div class="navsec">History</div>
    <div id="historyList"></div>
    <div class="navsec">Tables</div>
    <div id="tableList"></div>
  </aside>
  <main id="main"><div class="empty">Loading...</div></main>
</div>

<!-- MODAL -->
<div class="modal hidden" id="modal"><div class="inner">
  <div class="head"><strong id="modalTitle">Record</strong><div style="display:flex;gap:6px"><button class="btn danger sm hidden" id="modalDeleteBtn">Delete Record</button><button class="btn sec sm" id="modalClose">Close</button></div></div>
  <div id="modalBody"></div>
</div></div>

<!-- DELETE CONFIRMATION MODAL -->
<div class="modal hidden" id="deleteModal"><div class="inner" style="max-width:480px">
  <div class="head"><strong>Delete Record</strong></div>
  <div style="padding:16px">
    <p class="delwarn">You are about to permanently delete this record.</p>
    <div class="delinfo">
      <div><strong>Table:</strong> <span id="delTable"></span></div>
      <div><strong>Record ID:</strong> <span id="delRowid"></span></div>
    </div>
    <p style="color:var(--muted);font-size:13px;margin:0">This action cannot be undone.</p>
    <div class="delconfirm">
      <label for="delConfirmInput">Type <strong>DELETE</strong> to confirm.</label>
      <input id="delConfirmInput" placeholder="DELETE" autocomplete="off">
    </div>
    <div class="msg" id="delMsg"></div>
  </div>
  <div class="foot">
    <button class="btn sec" id="delCancelBtn">Cancel</button>
    <button class="btn danger" id="delConfirmBtn" disabled>Delete</button>
  </div>
</div></div>

<div id="toast" class="toast hidden"></div>

<script>
const BASE="__BASE__";
const $=function(s,r){return (r||document).querySelector(s)};
const $$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
let state={view:null,table:null,page:1,pageSize:50,sort:null,dir:"ASC",search:"",filters:[],logic:"AND",lastQ:"",lastSearchExact:false,consoleMode:"readonly"};
let history=[];
let tableTypes={};
let deletableViews={};
let inspectCtx={table:null,rowid:null,recordId:null};
let deleteCtx={table:null,rowid:null,recordId:null,onSuccess:null};
let toastTimer=null;

function api(p,opt){return fetch(BASE+p,Object.assign({credentials:"same-origin",headers:{"Content-Type":"application/json"}},opt)).then(function(r){
  if(r.status===401){showLogin();throw new Error("unauthorized");}
  return r.json().catch(function(){return {};});
});}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"})[c]});}
function hi(s,q){if(!q)return esc(s);const t=esc(s);try{const re=new RegExp("("+q.replace(/[.*+?^\${}()|[\\]\\\\]/g,"\\\\$&")+")","ig");return t.replace(re,"<mark>$1</mark>");}catch(e){return t;}}
function fmtBytes(n){if(n==null)return "-";const u=["B","KB","MB","GB","TB"];let i=0;n=Number(n);while(n>=1024&&i<u.length-1){n/=1024;i++;}return n.toFixed(i?1:0)+" "+u[i];}
function fmtNum(n){return (n==null)?"-":Number(n).toLocaleString();}
function showToast(msg,type){
  const el=$("#toast");if(!el)return;
  if(toastTimer){clearTimeout(toastTimer);toastTimer=null;}
  el.textContent=msg;el.className="toast "+(type||"ok");
  toastTimer=setTimeout(function(){el.classList.add("hidden");},3500);
}
function isDeleteMode(){return state.consoleMode==="delete";}
function isDeletableView(table){return !!deletableViews[table];}
function canDeleteTable(table){return isDeleteMode()&&(tableTypes[table]==="table"||isDeletableView(table));}
function updateModeUI(){
  const badge=$("#roBadge");const btn=$("#modeToggle");
  if(!badge||!btn)return;
  if(isDeleteMode()){
    badge.textContent="DELETE MODE";badge.className="ro delete-mode";
    btn.textContent="Switch to Read-Only";btn.className="btn sm mode-delete";
    btn.title="Delete mode active — click to switch to read-only";
  }else{
    badge.textContent="READ-ONLY";badge.className="ro readonly-mode";
    btn.textContent="Switch to Delete Mode";btn.className="btn sm mode-readonly";
    btn.title="Read-only mode — click to enable delete";
  }
}
function setConsoleMode(mode,refresh){
  const next=(mode==="delete")?"delete":"readonly";
  return api("/api/mode",{method:"POST",body:JSON.stringify({mode:next})}).then(function(d){
    if(d&&d.ok){
      state.consoleMode=next;
      updateModeUI();
      closeDeleteModal();
      $("#modalDeleteBtn").classList.add("hidden");
      if(refresh!==false)refreshCurrentView();
      showToast(next==="delete"?"Delete mode enabled.":"Read-only mode enabled.",next==="delete"?"ok":"");
      return true;
    }
    showToast("Failed to change mode.","err");
    return false;
  }).catch(function(){showToast("Failed to change mode.","err");return false;});
}
$("#modeToggle").addEventListener("click",function(){
  setConsoleMode(isDeleteMode()?"readonly":"delete");
});
function rowDeleteKey(table,rowid,recordId){
  if(isDeletableView(table))return {recordId:recordId!=null?String(recordId):""};
  return {rowid:rowid!=null&&rowid!==""?rowid:null};
}
function hasDeleteKey(table,rowid,recordId){
  const k=rowDeleteKey(table,rowid,recordId);
  return k.recordId!=null&&k.recordId.length>0||k.rowid!=null;
}
function actionButtons(table,rowid,recordId){
  if(!hasDeleteKey(table,rowid,recordId))return '<td class="actions"><button class="btn sec sm" data-act="view" data-t="'+esc(table)+'" data-rid="'+esc(rowid||"")+'" data-rec="'+esc(recordId||"")+'">View</button></td>';
  const recAttr=' data-rec="'+esc(recordId||"")+'"';
  let h='<td class="actions"><button class="btn sec sm" data-act="view" data-t="'+esc(table)+'" data-rid="'+esc(rowid||"")+'"'+recAttr+'>View</button>';
  if(canDeleteTable(table))h+='<button class="btn danger sm" data-act="delete" data-t="'+esc(table)+'" data-rid="'+esc(rowid||"")+'"'+recAttr+'>&#128465; Delete</button>';
  return h+'</td>';
}
function bindActionButtons(root,onDelete){
  $$("[data-act]",root).forEach(function(btn){
    btn.addEventListener("click",function(e){
      e.stopPropagation();
      const t=btn.dataset.t;const rid=btn.dataset.rid||null;const rec=btn.dataset.rec||null;
      if(btn.dataset.act==="view")inspectRow(t,rid,rec);
      else if(btn.dataset.act==="delete")showDeleteConfirm(t,rid,rec,onDelete);
    });
  });
}
function refreshCurrentView(){
  if(state.view==="table")renderBrowse();
  else if(state.view==="search"){
    const target=$("#sv_results");
    if(target&&state.lastQ)runSearch(state.lastQ,state.lastSearchExact,target);
    else openSearchView();
  }
  else if(state.view==="stats")openStats();
}
function closeDeleteModal(){
  deleteCtx={table:null,rowid:null,recordId:null,onSuccess:null};
  $("#deleteModal").classList.add("hidden");
  $("#delConfirmInput").value="";
  $("#delConfirmBtn").disabled=true;
  $("#delConfirmBtn").textContent="Delete";
  const m=$("#delMsg");m.className="msg";m.textContent="";
}
function showDeleteConfirm(table,rowid,recordId,onSuccess){
  if(!isDeleteMode()){showToast("Switch to Delete Mode first.","err");return;}
  deleteCtx={table:table,rowid:rowid,recordId:recordId,onSuccess:onSuccess||refreshCurrentView};
  $("#delTable").textContent=table;
  const key=isDeletableView(table)?(recordId!=null?String(recordId):""):(rowid!=null?String(rowid):"");
  $("#delRowid").textContent=key;
  $("#delConfirmInput").value="";
  $("#delConfirmBtn").disabled=true;
  $("#delConfirmBtn").textContent="Delete";
  const m=$("#delMsg");m.className="msg";m.textContent="";
  $("#deleteModal").classList.remove("hidden");
  setTimeout(function(){$("#delConfirmInput").focus();},50);
}
function performDelete(){
  if(!isDeleteMode()){showToast("Switch to Delete Mode first.","err");return;}
  const table=deleteCtx.table;const rowid=deleteCtx.rowid;const recordId=deleteCtx.recordId;
  if(!table||!hasDeleteKey(table,rowid,recordId))return;
  const btn=$("#delConfirmBtn");const m=$("#delMsg");
  btn.disabled=true;btn.textContent="Deleting...";
  m.className="msg";m.textContent="";
  const body={table:table};
  if(isDeletableView(table))body.recordId=recordId!=null?String(recordId):null;
  else body.rowid=rowid;
  api("/api/deleteRow",{method:"POST",body:JSON.stringify(body)}).then(function(d){
    if(d&&d.success){
      const cb=deleteCtx.onSuccess||refreshCurrentView;
      closeDeleteModal();
      $("#modal").classList.add("hidden");
      showToast("Record deleted successfully.","ok");
      if(typeof cb==="function")cb();
    }else{
      btn.disabled=false;btn.textContent="Delete";
      const msg=(d&&d.error==="readonly_mode")?"Read-only mode — switch to Delete Mode first.":"Failed to delete record.";
      m.className="msg err";m.textContent=msg;
      showToast(msg,"err");
    }
  }).catch(function(){
    btn.disabled=false;btn.textContent="Delete";
    m.className="msg err";m.textContent="Failed to delete record.";
    showToast("Failed to delete record.","err");
  });
}
$("#delCancelBtn").addEventListener("click",closeDeleteModal);
$("#deleteModal").addEventListener("click",function(e){if(e.target===this)closeDeleteModal();});
$("#delConfirmInput").addEventListener("input",function(){
  $("#delConfirmBtn").disabled=(this.value.trim()!=="DELETE");
});
$("#delConfirmInput").addEventListener("keydown",function(e){
  if(e.key==="Enter"&&this.value.trim()==="DELETE"&&!$("#delConfirmBtn").disabled)performDelete();
});
$("#delConfirmBtn").addEventListener("click",performDelete);

function applySession(d){
  if(d&&Array.isArray(d.deletableViews)){deletableViews={};d.deletableViews.forEach(function(v){deletableViews[v]=1;});}
  if(d&&d.consoleMode)state.consoleMode=(d.consoleMode==="delete")?"delete":"readonly";
  updateModeUI();
}
/* ---- Auth ---- */
function showLogin(){$("#login").classList.remove("hidden");$("#app").classList.add("hidden");}
function showApp(){$("#login").classList.add("hidden");$("#app").classList.remove("hidden");}
$("#loginForm").addEventListener("submit",function(e){
  e.preventDefault();const m=$("#loginMsg");m.className="msg";m.textContent="Checking...";
  api("/api/login",{method:"POST",body:JSON.stringify({password:$("#pw").value})}).then(function(d){
    if(d&&d.ok){m.className="msg ok";m.textContent="Access granted";$("#pw").value="";state.consoleMode=(d.consoleMode==="delete")?"delete":"readonly";api("/api/session").then(function(s){applySession(s);start();});}
    else if(d&&d.error==="too_many_attempts"){m.className="msg err";m.textContent="Too many attempts. Try again in "+d.retryAfter+"s.";}
    else{m.className="msg err";m.textContent="Invalid password"+(d&&d.attemptsRemaining!=null?(" ("+d.attemptsRemaining+" attempts left)"):"");}
  }).catch(function(){m.className="msg err";m.textContent="Error";});
});
$("#logoutBtn").addEventListener("click",function(){api("/api/logout",{method:"POST"}).then(showLogin);});

/* ---- Sidebar ---- */
function loadTables(){return api("/api/tables").then(function(d){
  tableTypes={};
  (d.tables||[]).forEach(function(t){tableTypes[t.name]=t.type;});
  const el=$("#tableList");el.innerHTML="";
  (d.tables||[]).forEach(function(t){
    const div=document.createElement("div");div.className="navitem";div.dataset.table=t.name;
    div.innerHTML='<span>'+(t.type==="view"?"&#128065; ":"&#128202; ")+esc(t.name)+'</span><span class="count">'+fmtNum(t.rows)+'</span>';
    div.addEventListener("click",function(){openTable(t.name);});
    el.appendChild(div);
  });
});}
function setActive(sel){$$(".navitem").forEach(function(n){n.classList.remove("active");});if(sel)sel.classList.add("active");}
$$(".navitem[data-view]").forEach(function(n){n.addEventListener("click",function(){if(n.dataset.view==="stats")openStats();else openSearchView();setActive(n);});});

/* ---- History ---- */
function pushHistory(q){if(!q)return;history=history.filter(function(x){return x!==q;});history.unshift(q);history=history.slice(0,12);renderHistory();}
function renderHistory(){const el=$("#historyList");el.innerHTML="";history.forEach(function(q){const d=document.createElement("div");d.className="navitem";d.innerHTML='<span>&#8617; '+esc(q)+'</span>';d.addEventListener("click",function(){$("#globalQ").value=q;doGlobalSearch();});el.appendChild(d);});}

/* ---- Table browse ---- */
function openTable(name,resetFilters){
  setActive($('.navitem[data-table="'+CSS.escape(name)+'"]'));
  if(state.table!==name||resetFilters){state.filters=[];state.search="";state.sort=null;state.dir="ASC";state.page=1;}
  state.view="table";state.table=name;renderBrowse();
}
function browseQuery(extra){
  const p=new URLSearchParams();p.set("table",state.table);p.set("page",state.page);p.set("pageSize",state.pageSize);
  if(state.sort){p.set("sort",state.sort);p.set("dir",state.dir);}
  if(state.search)p.set("search",state.search);
  if(state.filters.length){p.set("filters",JSON.stringify(state.filters));p.set("logic",state.logic);}
  if(extra)Object.keys(extra).forEach(function(k){p.set(k,extra[k]);});
  return p.toString();
}
function renderBrowse(){
  const main=$("#main");main.innerHTML='<div class="empty">Loading '+esc(state.table)+'...</div>';
  api("/api/browse?"+browseQuery()).then(function(d){
    if(d.error){main.innerHTML='<div class="empty">Error: '+esc(d.error)+'</div>';return;}
    const cols=d.columns||[];const totalPages=Math.max(1,Math.ceil(d.total/state.pageSize));
    const isView=d.tableType==="view";
    let h='<div class="toolbar"><span class="title">'+esc(state.table)+'</span>';
    if(isView&&isDeletableView(state.table)&&isDeleteMode())h+='<span class="pill" style="color:var(--ok);border-color:var(--ok)">VIEW (delete enabled)</span>';
    else if(isView&&isDeletableView(state.table))h+='<span class="pill" style="color:var(--warn);border-color:var(--warn)">VIEW (switch to delete mode)</span>';
    else if(isView)h+='<span class="pill" style="color:var(--warn);border-color:var(--warn)">VIEW (read-only)</span>';
    h+='<span class="meta">'+fmtNum(d.total)+' rows</span>';
    h+='<div class="grow"></div>';
    h+='<input id="rowSearch" placeholder="Search this table..." style="width:240px" value="'+esc(state.search)+'">';
    h+='<button class="btn sm" id="rowSearchBtn">Search</button>';
    h+='<button class="btn sec sm" id="filterToggle">Filters'+(state.filters.length?(" ("+state.filters.length+")"):"")+'</button>';
    h+='<button class="btn sec sm" id="schemaBtn">Schema</button>';
    h+='<button class="btn sec sm" id="exportBtn">Export CSV</button></div>';
    h+='<div id="filterBox" class="filters hidden"></div>';
    h+='<div class="tablewrap"><table class="data"><thead><tr><th>#</th>';
    cols.forEach(function(c){const ar=state.sort===c?(state.dir==="ASC"?" &#9650;":" &#9660;"):"";h+='<th data-col="'+esc(c)+'">'+esc(c)+ar+'</th>';});
    h+='<th>Actions</th></tr></thead><tbody>';
    if(!d.rows||!d.rows.length){h+='<tr><td colspan="'+(cols.length+2)+'" class="empty">No rows</td></tr>';}
    (d.rows||[]).forEach(function(r,i){
      const rid=r._rowid!=null?r._rowid:"";
      const rec=r.id!=null?r.id:"";
      h+='<tr data-rowid="'+esc(rid)+'" data-rec="'+esc(rec)+'">';
      h+='<td>'+((state.page-1)*state.pageSize+i+1)+'</td>';
      cols.forEach(function(c){h+='<td title="'+esc(r[c])+'">'+hi(r[c],state.search)+'</td>';});
      h+=actionButtons(state.table,rid,rec);
      h+='</tr>';
    });
    h+='</tbody></table></div>';
    h+='<div class="pager"><button class="btn sec sm" id="prev">&#8592; Prev</button><span class="pill">Page '+state.page+' / '+totalPages+'</span><button class="btn sec sm" id="next">Next &#8594;</button>';
    h+='<span class="grow"></span><span class="pill">Page size '+state.pageSize+'</span></div>';
    main.innerHTML=h;
    $("#rowSearchBtn").onclick=function(){state.search=$("#rowSearch").value.trim();state.page=1;renderBrowse();};
    $("#rowSearch").addEventListener("keydown",function(e){if(e.key==="Enter"){state.search=this.value.trim();state.page=1;renderBrowse();}});
    $("#prev").onclick=function(){if(state.page>1){state.page--;renderBrowse();}};
    $("#next").onclick=function(){if(state.page<totalPages){state.page++;renderBrowse();}};
    $("#exportBtn").onclick=function(){window.open(BASE+"/api/export?"+browseQuery(),"_blank");};
    $("#schemaBtn").onclick=function(){showSchema(state.table);};
    $("#filterToggle").onclick=function(){renderFilters(cols);};
    $$("th[data-col]").forEach(function(th){th.onclick=function(){const c=th.dataset.col;if(state.sort===c){state.dir=state.dir==="ASC"?"DESC":"ASC";}else{state.sort=c;state.dir="ASC";}renderBrowse();};});
    bindActionButtons(main,function(){
      if(d.rows&&d.rows.length===1&&state.page>1)state.page--;
      renderBrowse();
    });
    $$("tr[data-rowid]",main).forEach(function(tr){tr.onclick=function(e){if(e.target.closest(".actions"))return;inspectRow(state.table,tr.dataset.rowid||null,tr.dataset.rec||null);};});
  });
}
function renderFilters(cols){
  const box=$("#filterBox");box.classList.toggle("hidden");if(box.classList.contains("hidden"))return;
  if(!state.filters.length)state.filters=[{col:cols[0],op:"like",value:""}];
  function draw(){
    let h='<div style="margin-bottom:8px"><label>Match <select id="logicSel"><option value="AND"'+(state.logic==="AND"?" selected":"")+'>ALL (AND)</option><option value="OR"'+(state.logic==="OR"?" selected":"")+'>ANY (OR)</option></select> conditions</label></div>';
    state.filters.forEach(function(f,i){
      h+='<div class="frow"><select data-i="'+i+'" data-k="col">'+cols.map(function(c){return '<option'+(c===f.col?" selected":"")+'>'+esc(c)+'</option>';}).join("")+'</select>';
      h+='<select data-i="'+i+'" data-k="op">'+[["eq","="],["neq","\u2260"],["like","contains"],["gt",">"],["gte","\u2265"],["lt","<"],["lte","\u2264"],["null","is null"],["notnull","not null"]].map(function(o){return '<option value="'+o[0]+'"'+(o[0]===f.op?" selected":"")+'>'+o[1]+'</option>';}).join("")+'</select>';
      h+='<input data-i="'+i+'" data-k="value" placeholder="value" value="'+esc(f.value)+'"'+((f.op==="null"||f.op==="notnull")?" disabled":"")+'>';
      h+='<button class="btn sec sm" data-del="'+i+'">&#10005;</button></div>';
    });
    h+='<div style="margin-top:6px"><button class="btn sec sm" id="addFilter">+ Add condition</button> <button class="btn sm" id="applyFilter">Apply</button> <button class="btn sec sm" id="clearFilter">Clear</button></div>';
    box.innerHTML=h;
    $("#logicSel").onchange=function(){state.logic=this.value;};
    $$("select[data-k],input[data-k]",box).forEach(function(el){el.onchange=function(){const i=+el.dataset.i;state.filters[i][el.dataset.k]=el.value;if(el.dataset.k==="op")draw();};});
    $$("[data-del]",box).forEach(function(b){b.onclick=function(){state.filters.splice(+b.dataset.del,1);if(!state.filters.length)state.filters=[{col:cols[0],op:"like",value:""}];draw();};});
    $("#addFilter").onclick=function(){state.filters.push({col:cols[0],op:"like",value:""});draw();};
    $("#applyFilter").onclick=function(){state.filters=state.filters.filter(function(f){return f.op==="null"||f.op==="notnull"||String(f.value).length;});state.page=1;renderBrowse();};
    $("#clearFilter").onclick=function(){state.filters=[];state.page=1;renderBrowse();};
  }
  draw();
}

/* ---- Schema ---- */
function showSchema(table){
  api("/api/schema?table="+encodeURIComponent(table)).then(function(d){
    if(d.error)return;
    let h='<div class="kv"><div class="key">Object</div><div>'+esc(table)+' <span class="tag">'+esc(d.type)+'</span></div></div>';
    h+='<h3 style="padding:0 16px">Columns</h3><div class="tablewrap" style="margin:0 16px"><table class="data"><thead><tr><th>Name</th><th>Type</th><th>Not Null</th><th>PK</th><th>Default</th></tr></thead><tbody>';
    (d.columns||[]).forEach(function(c){h+='<tr><td>'+esc(c.name)+'</td><td>'+esc(c.type)+'</td><td>'+(c.notnull?"yes":"")+'</td><td>'+(c.pk?"yes":"")+'</td><td>'+esc(c.dflt)+'</td></tr>';});
    h+='</tbody></table></div>';
    h+='<h3 style="padding:0 16px">Indexes</h3><div style="padding:0 16px 16px">'+((d.indexes&&d.indexes.length)?d.indexes.map(function(x){return '<span class="pill">'+esc(x.name)+(x.unique?" (unique)":"")+'</span>';}).join(" "):'<span class="meta" style="color:var(--muted)">none</span>')+'</div>';
    openModal("Schema: "+table,h);
  });
}

/* ---- Inspect row ---- */
function inspectRow(table,rowid,recordId){
  inspectCtx={table:table,rowid:rowid,recordId:recordId};
  let url="/api/row?table="+encodeURIComponent(table);
  if(isDeletableView(table)&&recordId!=null&&String(recordId).length)url+="&recordId="+encodeURIComponent(recordId);
  else if(rowid!=null&&rowid!=="")url+="&rowid="+encodeURIComponent(rowid);
  api(url).then(function(d){
    if(d.error||!d.row){
      inspectCtx={table:null,rowid:null,recordId:null};
      $("#modalDeleteBtn").classList.add("hidden");
      openModal("Record",'<div class="empty">Record not available</div>');return;
    }
    const rec=d.row.id!=null?d.row.id:recordId;
    let h='<div class="kv">';
    Object.keys(d.row).forEach(function(k){if(k==="_rowid")return;h+='<div class="key">'+esc(k)+'</div><div>'+esc(d.row[k])+'</div>';});
    h+='</div>';
    openModal("Record &middot; "+esc(table),h);
    const delBtn=$("#modalDeleteBtn");
    if(hasDeleteKey(table,rowid,rec)&&canDeleteTable(table)){delBtn.classList.remove("hidden");delBtn.onclick=function(){showDeleteConfirm(table,rowid,rec,refreshCurrentView);};}
    else{delBtn.classList.add("hidden");}
  });
}

/* ---- Global search ---- */
function openSearchView(){state.view="search";const main=$("#main");
  main.innerHTML='<div class="toolbar"><span class="title">Global Search</span><span class="meta">Searches every table and column</span></div>'+
  '<div class="filters"><div class="frow"><input id="sv_q" placeholder="Search value..." value="'+esc(state.lastQ)+'"><label class="pill"><input type="checkbox" id="sv_exact" style="width:auto"> exact</label><button class="btn sm" id="sv_btn">Search</button></div></div>'+
  '<div id="sv_results"></div>';
  $("#sv_btn").onclick=function(){state.lastQ=$("#sv_q").value.trim();state.lastSearchExact=$("#sv_exact").checked;runSearch(state.lastQ,state.lastSearchExact,$("#sv_results"));};
  $("#sv_q").addEventListener("keydown",function(e){if(e.key==="Enter")$("#sv_btn").click();});
}
function doGlobalSearch(){const q=$("#globalQ").value.trim();if(!q)return;state.lastQ=q;openSearchView();$("#sv_q").value=q;runSearch(q,false,$("#sv_results"));setActive($('.navitem[data-view="search"]'));}
$("#globalBtn").addEventListener("click",doGlobalSearch);
$("#globalQ").addEventListener("keydown",function(e){if(e.key==="Enter")doGlobalSearch();});
function runSearch(q,exact,target){
  if(!q){target.innerHTML="";return;}
  state.lastQ=q;state.lastSearchExact=!!exact;
  pushHistory(q);target.innerHTML='<div class="empty">Searching...</div>';
  api("/api/search?q="+encodeURIComponent(q)+(exact?"&exact=1":"")).then(function(d){
    const res=d.results||[];
    if(!res.length){target.innerHTML='<div class="empty">No matches for "'+esc(q)+'"</div>';return;}
    const byTable={};res.forEach(function(r){(byTable[r.table]=byTable[r.table]||[]).push(r);});
    let h='<div class="meta" style="margin-bottom:10px;color:var(--muted)">'+res.length+(d.truncated?"+":"")+' matches across '+Object.keys(byTable).length+' tables</div>';
    Object.keys(byTable).forEach(function(tn){
      const rows=byTable[tn];
      h+='<div class="toolbar" style="margin-top:6px"><span class="title" style="font-size:15px">'+esc(tn)+'</span><span class="meta">'+rows.length+' matches</span><div class="grow"></div><button class="btn sec sm" data-open="'+esc(tn)+'">Open table</button></div>';
      h+='<div class="tablewrap" style="max-height:none"><table class="data"><thead><tr><th>match in</th>';
      const cols=Object.keys(rows[0].row).filter(function(c){return c!=="_rowid";}).slice(0,8);
      cols.forEach(function(c){h+='<th>'+esc(c)+'</th>';});h+='<th>Actions</th></tr></thead><tbody>';
      rows.forEach(function(r){
        const rid=r.rowid!=null?r.rowid:"";
        const rec=r.row&&r.row.id!=null?r.row.id:"";
        h+='<tr data-t="'+esc(tn)+'" data-rid="'+esc(rid)+'" data-rec="'+esc(rec)+'"><td><span class="pill">'+esc((r.matchedColumns||[]).join(", "))+'</span></td>';
        cols.forEach(function(c){h+='<td title="'+esc(r.row[c])+'">'+hi(r.row[c],q)+'</td>';});
        h+=actionButtons(tn,rid,rec);
        h+='</tr>';
      });
      h+='</tbody></table></div>';
    });
    target.innerHTML=h;
    $$("[data-open]",target).forEach(function(b){b.onclick=function(){openTable(b.dataset.open,true);};});
    bindActionButtons(target,function(){runSearch(q,exact,target);});
    $$("tr[data-rid]",target).forEach(function(tr){tr.onclick=function(e){if(e.target.closest(".actions"))return;inspectRow(tr.dataset.t,tr.dataset.rid||null,tr.dataset.rec||null);};});
  });
}

/* ---- Stats ---- */
function openStats(){state.view="stats";const main=$("#main");main.innerHTML='<div class="empty">Loading statistics...</div>';
  api("/api/stats").then(function(d){
    if(d.error){main.innerHTML='<div class="empty">Error: '+esc(d.error)+'</div>';return;}
    let h='<div class="toolbar"><span class="title">Database Statistics</span></div>';
    h+='<div class="cards">';
    h+='<div class="stat"><div class="k">Tables</div><div class="v">'+fmtNum(d.tableCount)+'</div></div>';
    h+='<div class="stat"><div class="k">Total rows</div><div class="v">'+fmtNum(d.totalRows)+'</div></div>';
    h+='<div class="stat"><div class="k">Database size</div><div class="v">'+fmtBytes(d.fileSize)+'</div></div>';
    h+='<div class="stat"><div class="k">WAL size</div><div class="v">'+fmtBytes(d.walSize)+'</div></div>';
    h+='</div>';
    h+='<div class="meta" style="color:var(--muted);margin-bottom:8px">File: '+esc(d.dbFile)+'</div>';
    const max=(d.tables&&d.tables.length)?Math.max(1,d.tables[0].rows):1;
    h+='<div class="tablewrap" style="max-height:none"><table class="data"><thead><tr><th>Table</th><th>Type</th><th>Rows</th><th style="width:40%">Distribution</th></tr></thead><tbody>';
    (d.tables||[]).forEach(function(t){h+='<tr data-t="'+esc(t.name)+'"><td>'+esc(t.name)+'</td><td>'+esc(t.type)+'</td><td>'+fmtNum(t.rows)+'</td><td><div class="bar"><i style="width:'+(100*t.rows/max).toFixed(1)+'%"></i></div></td></tr>';});
    h+='</tbody></table></div>';
    main.innerHTML=h;
    $$("tr[data-t]").forEach(function(tr){tr.onclick=function(){openTable(tr.dataset.t,true);};});
  });
}

/* ---- Modal ---- */
function openModal(title,html){$("#modalTitle").innerHTML=title;$("#modalBody").innerHTML=html;$("#modal").classList.remove("hidden");if(!inspectCtx.table)$("#modalDeleteBtn").classList.add("hidden");}
$("#modalClose").onclick=function(){$("#modal").classList.add("hidden");};
$("#modal").addEventListener("click",function(e){if(e.target===this)this.classList.add("hidden");});
document.addEventListener("keydown",function(e){
  if(e.key==="Escape"){
    if(!$("#deleteModal").classList.contains("hidden"))closeDeleteModal();
    else $("#modal").classList.add("hidden");
  }
});

/* ---- Boot ---- */
function start(){showApp();loadTables().then(openStats);setActive($('.navitem[data-view="stats"]'));}
api("/api/session").then(function(d){applySession(d);if(d&&d.authenticated){start();}else{showLogin();}}).catch(showLogin);
</script>
</body>
</html>`;