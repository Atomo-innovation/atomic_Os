#!/usr/bin/env node
/**
 * Create DB Browser–friendly views on atomic-center.sqlite.
 * Run from MeshCentral-master: npm run db:views
 */
'use strict';

const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'meshcentral-data');
const configPath = path.join(dataDir, 'config.json');
let dbName = 'atomic-center';

try {
  const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const s3 = cfg?.settings?.sqlite3;
  if (typeof s3 === 'string' && s3.trim()) dbName = s3.trim();
  else if (s3 && typeof s3 === 'object' && s3.name) dbName = String(s3.name);
} catch (e) {}

const dbPath = path.join(dataDir, `${dbName}.sqlite`);
const sqlPath = path.join(dataDir, 'atomic-center-views.sql');

if (!fs.existsSync(dbPath)) {
  console.error('Database not found:', dbPath);
  console.error('Start MeshCentral once with settings.sqlite3, or run: node meshcentral.js --nedbtodb');
  process.exit(1);
}

const sql = fs.readFileSync(sqlPath, 'utf8');
const sqlite3 = require('sqlite3');

const db = new sqlite3.Database(dbPath);
db.exec(sql, (err) => {
  db.close();
  if (err) {
    console.error(err.message || err);
    process.exit(1);
  }
  console.log('Applied views on', dbPath);
  console.log('In DB Browser: Browse Data → atomic_center_users');
});
