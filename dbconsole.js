/**
* @description Hidden developer/admin database console for MeshCentral (SQLite).
* @author Atomic Center
* @license Apache-2.0
*
* Self-contained module. It registers a hidden, password-protected web UI on the
* main MeshCentral Express app (same port, so it works on localhost and AWS with
* no extra ports/Security-Group rules). The console is READ-ONLY: it opens its own
* SQLite connection with OPEN_READONLY and exposes no write endpoints.
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
    obj.readonly = true; // Always read-only by design.

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
    // SQLite read-only access layer
    // ===================================================================
    let sqlite3 = null;
    let roDb = null;
    function getDb(callback) {
        if (roDb) return callback(null, roDb);
        if (!obj.dbFile || !fs.existsSync(obj.dbFile)) { return callback(new Error('SQLite database file not found. The console supports SQLite databases only.')); }
        try { if (sqlite3 == null) { sqlite3 = require('sqlite3'); } } catch (ex) { return callback(new Error('sqlite3 module not available.')); }
        roDb = new sqlite3.Database(obj.dbFile, sqlite3.OPEN_READONLY, function (err) {
            if (err) { roDb = null; return callback(err); }
            callback(null, roDb);
        });
    }
    function all(sql, params, callback) { getDb(function (e, db) { if (e) return callback(e); db.all(sql, params || [], callback); }); }
    function get(sql, params, callback) { getDb(function (e, db) { if (e) return callback(e); db.get(sql, params || [], callback); }); }

    function quoteId(name) { return '"' + String(name).replace(/"/g, '""') + '"'; }

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
                const cookie = obj.cookieName + '=' + createToken() + '; HttpOnly; SameSite=Strict; Path=' + obj.consolePath + '; Max-Age=' + Math.floor(DEFAULTS.SESSION_MS / 1000) + (secure ? '; Secure' : '');
                res.set('Set-Cookie', cookie);
                return sendJson(res, 200, { ok: true });
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
            res.set('Set-Cookie', obj.cookieName + '=; HttpOnly; SameSite=Strict; Path=' + obj.consolePath + '; Max-Age=0');
            sendJson(res, 200, { ok: true });
        });

        router.get('/api/session', function (req, res) {
            sendJson(res, 200, { authenticated: isAuthed(req), readonly: obj.readonly });
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
                                sendJson(res, 200, { table: table, columns: colNames, rows: rows, total: total, page: page, pageSize: pageSize, hasRowid: hasRowid });
                            });
                        });
                    });
                });
            });
        });

        // ---- Inspect a single record ----------------------------------
        router.get('/api/row', requireAuth, function (req, res) {
            const table = req.query.table;
            const rowid = req.query.rowid;
            validateTable(table, function (err, t) {
                if (err) return sendJson(res, 500, { error: err.message });
                if (!t) return sendJson(res, 404, { error: 'unknown_table' });
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
        console.log('Hidden DB console registered at ' + obj.consolePath + ' (read-only).');
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
header .ro{font-size:11px;color:var(--warn);border:1px solid var(--warn);padding:2px 8px;border-radius:999px}
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
    <span class="ro" id="roBadge">READ-ONLY</span>
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
  <div class="head"><strong id="modalTitle">Record</strong><button class="btn sec sm" id="modalClose">Close</button></div>
  <div id="modalBody"></div>
</div></div>

<script>
const BASE="__BASE__";
const $=function(s,r){return (r||document).querySelector(s)};
const $$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
let state={view:null,table:null,page:1,pageSize:50,sort:null,dir:"ASC",search:"",filters:[],logic:"AND",lastQ:""};
let history=[];

function api(p,opt){return fetch(BASE+p,Object.assign({credentials:"same-origin",headers:{"Content-Type":"application/json"}},opt)).then(function(r){
  if(r.status===401){showLogin();throw new Error("unauthorized");}
  return r.json().catch(function(){return {};});
});}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"})[c]});}
function hi(s,q){if(!q)return esc(s);const t=esc(s);try{const re=new RegExp("("+q.replace(/[.*+?^\${}()|[\\]\\\\]/g,"\\\\$&")+")","ig");return t.replace(re,"<mark>$1</mark>");}catch(e){return t;}}
function fmtBytes(n){if(n==null)return "-";const u=["B","KB","MB","GB","TB"];let i=0;n=Number(n);while(n>=1024&&i<u.length-1){n/=1024;i++;}return n.toFixed(i?1:0)+" "+u[i];}
function fmtNum(n){return (n==null)?"-":Number(n).toLocaleString();}

/* ---- Auth ---- */
function showLogin(){$("#login").classList.remove("hidden");$("#app").classList.add("hidden");}
function showApp(){$("#login").classList.add("hidden");$("#app").classList.remove("hidden");}
$("#loginForm").addEventListener("submit",function(e){
  e.preventDefault();const m=$("#loginMsg");m.className="msg";m.textContent="Checking...";
  api("/api/login",{method:"POST",body:JSON.stringify({password:$("#pw").value})}).then(function(d){
    if(d&&d.ok){m.className="msg ok";m.textContent="Access granted";$("#pw").value="";start();}
    else if(d&&d.error==="too_many_attempts"){m.className="msg err";m.textContent="Too many attempts. Try again in "+d.retryAfter+"s.";}
    else{m.className="msg err";m.textContent="Invalid password"+(d&&d.attemptsRemaining!=null?(" ("+d.attemptsRemaining+" attempts left)"):"");}
  }).catch(function(){m.className="msg err";m.textContent="Error";});
});
$("#logoutBtn").addEventListener("click",function(){api("/api/logout",{method:"POST"}).then(showLogin);});

/* ---- Sidebar ---- */
function loadTables(){return api("/api/tables").then(function(d){
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
    let h='<div class="toolbar"><span class="title">'+esc(state.table)+'</span><span class="meta">'+fmtNum(d.total)+' rows</span>';
    h+='<div class="grow"></div>';
    h+='<input id="rowSearch" placeholder="Search this table..." style="width:240px" value="'+esc(state.search)+'">';
    h+='<button class="btn sm" id="rowSearchBtn">Search</button>';
    h+='<button class="btn sec sm" id="filterToggle">Filters'+(state.filters.length?(" ("+state.filters.length+")"):"")+'</button>';
    h+='<button class="btn sec sm" id="schemaBtn">Schema</button>';
    h+='<button class="btn sec sm" id="exportBtn">Export CSV</button></div>';
    h+='<div id="filterBox" class="filters hidden"></div>';
    h+='<div class="tablewrap"><table class="data"><thead><tr><th>#</th>';
    cols.forEach(function(c){const ar=state.sort===c?(state.dir==="ASC"?" &#9650;":" &#9660;"):"";h+='<th data-col="'+esc(c)+'">'+esc(c)+ar+'</th>';});
    h+='</tr></thead><tbody>';
    if(!d.rows||!d.rows.length){h+='<tr><td colspan="'+(cols.length+1)+'" class="empty">No rows</td></tr>';}
    (d.rows||[]).forEach(function(r,i){
      h+='<tr data-rowid="'+(r._rowid!=null?esc(r._rowid):"")+'">';
      h+='<td>'+((state.page-1)*state.pageSize+i+1)+'</td>';
      cols.forEach(function(c){h+='<td title="'+esc(r[c])+'">'+hi(r[c],state.search)+'</td>';});
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
    $$("tr[data-rowid]").forEach(function(tr){tr.onclick=function(){const id=tr.dataset.rowid;if(id!=="")inspectRow(state.table,id);};});
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
function inspectRow(table,rowid){
  api("/api/row?table="+encodeURIComponent(table)+"&rowid="+encodeURIComponent(rowid)).then(function(d){
    if(d.error||!d.row){openModal("Record",'<div class="empty">Record not available</div>');return;}
    let h='<div class="kv">';
    Object.keys(d.row).forEach(function(k){if(k==="_rowid")return;h+='<div class="key">'+esc(k)+'</div><div>'+esc(d.row[k])+'</div>';});
    h+='</div>';
    openModal("Record &middot; "+esc(table),h);
  });
}

/* ---- Global search ---- */
function openSearchView(){state.view="search";const main=$("#main");
  main.innerHTML='<div class="toolbar"><span class="title">Global Search</span><span class="meta">Searches every table and column</span></div>'+
  '<div class="filters"><div class="frow"><input id="sv_q" placeholder="Search value..." value="'+esc(state.lastQ)+'"><label class="pill"><input type="checkbox" id="sv_exact" style="width:auto"> exact</label><button class="btn sm" id="sv_btn">Search</button></div></div>'+
  '<div id="sv_results"></div>';
  $("#sv_btn").onclick=function(){state.lastQ=$("#sv_q").value.trim();runSearch(state.lastQ,$("#sv_exact").checked,$("#sv_results"));};
  $("#sv_q").addEventListener("keydown",function(e){if(e.key==="Enter")$("#sv_btn").click();});
}
function doGlobalSearch(){const q=$("#globalQ").value.trim();if(!q)return;state.lastQ=q;openSearchView();$("#sv_q").value=q;runSearch(q,false,$("#sv_results"));setActive($('.navitem[data-view="search"]'));}
$("#globalBtn").addEventListener("click",doGlobalSearch);
$("#globalQ").addEventListener("keydown",function(e){if(e.key==="Enter")doGlobalSearch();});
function runSearch(q,exact,target){
  if(!q){target.innerHTML="";return;}
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
      cols.forEach(function(c){h+='<th>'+esc(c)+'</th>';});h+='</tr></thead><tbody>';
      rows.forEach(function(r){
        h+='<tr data-t="'+esc(tn)+'" data-rid="'+(r.rowid!=null?esc(r.rowid):"")+'"><td><span class="pill">'+esc((r.matchedColumns||[]).join(", "))+'</span></td>';
        cols.forEach(function(c){h+='<td title="'+esc(r.row[c])+'">'+hi(r.row[c],q)+'</td>';});
        h+='</tr>';
      });
      h+='</tbody></table></div>';
    });
    target.innerHTML=h;
    $$("[data-open]",target).forEach(function(b){b.onclick=function(){openTable(b.dataset.open,true);};});
    $$("tr[data-rid]",target).forEach(function(tr){tr.onclick=function(){const id=tr.dataset.rid;if(id!=="")inspectRow(tr.dataset.t,id);};});
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
function openModal(title,html){$("#modalTitle").innerHTML=title;$("#modalBody").innerHTML=html;$("#modal").classList.remove("hidden");}
$("#modalClose").onclick=function(){$("#modal").classList.add("hidden");};
$("#modal").addEventListener("click",function(e){if(e.target===this)this.classList.add("hidden");});
document.addEventListener("keydown",function(e){if(e.key==="Escape")$("#modal").classList.add("hidden");});

/* ---- Boot ---- */
function start(){showApp();loadTables().then(openStats);setActive($('.navitem[data-view="stats"]'));}
api("/api/session").then(function(d){if(d&&d.authenticated){start();}else{showLogin();}}).catch(showLogin);
</script>
</body>
</html>`;
