#!/usr/bin/env node
/**
 * Sets settings.cert and settings.agentaliasdns to the board hostname or LAN IP
 * so TLS and agents match the address users use after the IP changes.
 *
 * Usage:
 *   MESHCENTRAL_BOARD_HOST=192.168.1.17 node scripts/set-meshcentral-board-host.js
 *   node scripts/set-meshcentral-board-host.js 192.168.1.17
 *   node scripts/set-meshcentral-board-host.js --ec2-public-ipv4
 *
 * Optional:
 *   MESHCENTRAL_CONFIG=/path/to/config.json   (default: meshcentral-data/config.json)
 *
 * Then restart MeshCentral. If the browser still warns about the certificate,
 * MeshCentral may need to regenerate certs for the new name (see MeshCentral docs).
 */
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');

function fetchAwsPublicIpv4() {
  return new Promise((resolve, reject) => {
    const req = https.get(
      'https://checkip.amazonaws.com/',
      { timeout: 8000 },
      (res) => {
        let body = '';
        res.on('data', (c) => {
          body += c;
        });
        res.on('end', () => {
          const ip = body.trim();
          if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
            reject(new Error('Unexpected response from checkip.amazonaws.com: ' + JSON.stringify(body)));
            return;
          }
          resolve(ip);
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout contacting checkip.amazonaws.com'));
    });
  });
}

const argv = process.argv.slice(2);
const useEc2Public =
  argv.includes('--ec2-public-ipv4') ||
  argv.includes('--aws-public-ip') ||
  ['1', 'true', 'yes'].includes(String(process.env.MESHCENTRAL_SYNC_AWS_PUBLIC_IP || '').trim().toLowerCase());

let host =
  (process.env.MESHCENTRAL_BOARD_HOST || '').trim() ||
  argv.filter((a) => !a.startsWith('-')).join(' ').trim();

async function main() {
  if (useEc2Public && !host) {
    try {
      host = await fetchAwsPublicIpv4();
      console.log('Detected EC2 public IPv4:', host);
    } catch (e) {
      console.error('Could not detect public IP (run on EC2 with outbound HTTPS, or pass host manually):', e.message);
      process.exit(1);
    }
  }

  if (!host) {
    console.error(
      'Usage: MESHCENTRAL_BOARD_HOST=<ip-or-dns> node scripts/set-meshcentral-board-host.js\n' +
        '   or: node scripts/set-meshcentral-board-host.js <ip-or-dns>\n' +
        '   or: node scripts/set-meshcentral-board-host.js --ec2-public-ipv4'
    );
    process.exit(1);
  }

  const configPath = process.env.MESHCENTRAL_CONFIG
    ? path.resolve(process.env.MESHCENTRAL_CONFIG)
    : path.join(__dirname, '..', 'meshcentral-data', 'config.json');

  if (!fs.existsSync(configPath)) {
    console.error('Config not found:', configPath);
    process.exit(1);
  }

  let raw;
  try {
    raw = fs.readFileSync(configPath, 'utf8');
  } catch (e) {
    console.error('Cannot read config:', configPath, e.message);
    process.exit(1);
  }

  let cfg;
  try {
    cfg = JSON.parse(raw);
  } catch (e) {
    console.error('Invalid JSON in', configPath, e.message);
    process.exit(1);
  }

  if (!cfg.settings || typeof cfg.settings !== 'object') {
    cfg.settings = {};
  }

const prevCert = cfg.settings.cert;
  cfg.settings.cert = host;
  cfg.settings.agentaliasdns = host;

  // Rewrite the host portion of any per-domain nodeLoginUrl so node login keeps
  // working after the IP/DNS changes (scheme and port are preserved).
  let prevNodeLoginUrl;
  let newNodeLoginUrl;
  if (cfg.domains && typeof cfg.domains === 'object') {
    for (const domainName of Object.keys(cfg.domains)) {
      const dom = cfg.domains[domainName];
      if (dom && typeof dom.nodeLoginUrl === 'string' && dom.nodeLoginUrl.length > 0) {
        const rewritten = dom.nodeLoginUrl.replace(
          /^(https?:\/\/)[^/:]+(:\d+)?/i,
          (_m, scheme, port) => scheme + host + (port || '')
        );
        if (rewritten !== dom.nodeLoginUrl) {
          prevNodeLoginUrl = dom.nodeLoginUrl;
          newNodeLoginUrl = rewritten;
          dom.nodeLoginUrl = rewritten;
        }
      }
    }
  }

  try {
    fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2) + '\n', 'utf8');
  } catch (e) {
    console.error('Cannot write config:', configPath, e.message);
    process.exit(1);
  }

  console.log('Updated MeshCentral board host in', configPath);
  console.log('  cert:', prevCert, '->', host);
  console.log('  agentaliasdns:', host);
  if (newNodeLoginUrl) { console.log('  nodeLoginUrl:', prevNodeLoginUrl, '->', newNodeLoginUrl); }
  console.log('Restart the MeshCentral process for changes to take effect.');
  console.log('MeshCentral regenerates the TLS certificate automatically when the cert name changes.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
