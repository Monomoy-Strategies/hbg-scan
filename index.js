#!/usr/bin/env node
/**
 * hbg-scan — HeartbeatGuard Skill Scanner
 * Security scanner for OpenClaw AI agent skills
 * https://heartbeatguard.com
 *
 * Zero external dependencies. Requires Node.js 16+
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

// ─── ANSI Colors (no chalk needed) ───────────────────────────────────────────
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
  gold: '\x1b[33m',   // closest ANSI to #D4A843
  navy: '\x1b[34m',   // closest ANSI to #1B2A4A
};

const clr = (color, text) => `${C[color]}${text}${C.reset}`;
const bold = (text) => `${C.bold}${text}${C.reset}`;

// ─── Detection Check Definitions ─────────────────────────────────────────────
const CHECKS = {
  PROMPT_INJECTION: {
    id: 'CHECK-1',
    name: 'Prompt Injection Templates',
    description: 'Text mimicking system messages, gateway commands, or compaction audit triggers',
    patterns: [
      // System message spoofs
      { pattern: /\[System Message\]/gi, label: 'System message spoof', severity: 'FAIL' },
      { pattern: /\[SYSTEM OVERRIDE\]/gi, label: 'System override command', severity: 'FAIL' },
      { pattern: /\[INST\]/gi, label: 'Instruction injection marker', severity: 'WARN' },
      { pattern: /ignore (all )?(previous|prior) instructions/gi, label: 'Classic prompt injection', severity: 'FAIL' },
      { pattern: /OVERRIDE:\s*you must/gi, label: 'Override instruction injection', severity: 'FAIL' },
      { pattern: /you are now operating in/gi, label: 'Role override attempt', severity: 'WARN' },
      // Post-compaction patterns (the Feb 20 2026 attack vector)
      { pattern: /post-?compaction audit/gi, label: 'Post-compaction audit spoof', severity: 'FAIL' },
      { pattern: /WORKFLOW_AUTO/g, label: 'WORKFLOW_AUTO trigger pattern', severity: 'FAIL' },
      { pattern: /⚠️\s*post-?compaction/gi, label: 'Post-compaction warning spoof', severity: 'FAIL' },
      // Gateway command injection
      { pattern: /openclaw gateway (start|stop|restart|config)/gi, label: 'Gateway command injection', severity: 'FAIL' },
      { pattern: /openclaw skill (install|remove|disable)/gi, label: 'Skill management injection', severity: 'WARN' },
      // Hidden instruction patterns
      { pattern: /<!--\s*(you|your|agent|claude|jasper|assistant)/gi, label: 'Hidden HTML instruction', severity: 'WARN' },
      { pattern: /\u200b|\u200c|\u200d|\ufeff/g, label: 'Zero-width characters (hidden text)', severity: 'WARN' },
    ]
  },

  SENSITIVE_ACCESS: {
    id: 'CHECK-2',
    name: 'Sensitive File Access',
    description: 'Reads targeting agent identity files, credentials, or secrets',
    patterns: [
      // Agent identity files
      { pattern: /['"`]MEMORY\.md['"`]/gi, label: 'MEMORY.md access', severity: 'FAIL' },
      { pattern: /['"`]SOUL\.md['"`]/gi, label: 'SOUL.md access', severity: 'FAIL' },
      { pattern: /['"`]AGENTS\.md['"`]/gi, label: 'AGENTS.md access', severity: 'FAIL' },
      { pattern: /['"`]BILLS-WORDS\.md['"`]/gi, label: 'BILLS-WORDS.md access', severity: 'FAIL' },
      // Credential files
      { pattern: /['"`]\.env['"`]/gi, label: '.env file access', severity: 'FAIL' },
      { pattern: /['"`.\/]\.env\b/gi, label: '.env file reference', severity: 'WARN' },
      { pattern: /id_rsa|id_ed25519|id_ecdsa/gi, label: 'SSH private key reference', severity: 'FAIL' },
      { pattern: /\.pem\b/gi, label: 'PEM certificate/key access', severity: 'WARN' },
      // Credential patterns
      { pattern: /password\s*=\s*['"`][^'"`]{4,}/gi, label: 'Hardcoded password', severity: 'FAIL' },
      { pattern: /api[_-]?key\s*=\s*['"`][^'"`]{8,}/gi, label: 'Hardcoded API key', severity: 'FAIL' },
      { pattern: /secret\s*=\s*['"`][^'"`]{4,}/gi, label: 'Hardcoded secret', severity: 'WARN' },
      { pattern: /token\s*=\s*['"`][a-zA-Z0-9_\-]{16,}/gi, label: 'Hardcoded token', severity: 'FAIL' },
      // File traversal
      { pattern: /\.\.[\/\\]\.\.[\/\\]/g, label: 'Directory traversal attempt', severity: 'FAIL' },
      { pattern: /\/etc\/(passwd|shadow|sudoers)/gi, label: 'System credential file access', severity: 'FAIL' },
      // Windows credential paths
      { pattern: /AppData[\/\\](Roaming|Local)[\/\\].*?(credential|password|secret)/gi, label: 'Windows credential path', severity: 'WARN' },
      { pattern: /HKEY_LOCAL_MACHINE|HKLM:/gi, label: 'Windows registry access', severity: 'WARN' },
    ]
  },

  OUTBOUND_NETWORK: {
    id: 'CHECK-3',
    name: 'Outbound Network Calls',
    description: 'Undeclared HTTP calls to external endpoints',
    patterns: [
      // JavaScript fetch/axios
      { pattern: /fetch\(['"`]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi, label: 'fetch() to external URL', severity: 'WARN' },
      { pattern: /axios\.(get|post|put|delete|request)\(['"`]https?:\/\/(?!localhost)/gi, label: 'axios call to external URL', severity: 'WARN' },
      { pattern: /require\(['"`]node-fetch['"`]\)/gi, label: 'node-fetch import', severity: 'WARN' },
      // Shell/script network calls
      { pattern: /curl\s+(-[a-zA-Z\s]*)?https?:\/\/(?!localhost)/gi, label: 'curl to external URL', severity: 'WARN' },
      { pattern: /wget\s+https?:\/\/(?!localhost)/gi, label: 'wget to external URL', severity: 'WARN' },
      // Suspicious destinations
      { pattern: /https?:\/\/([a-z0-9]+\.)?webhook\.site/gi, label: 'Data exfil to webhook.site', severity: 'FAIL' },
      { pattern: /https?:\/\/([a-z0-9]+\.)?requestbin\.(com|net)/gi, label: 'Data exfil to requestbin', severity: 'FAIL' },
      { pattern: /https?:\/\/([a-z0-9]+\.)?ngrok\.io/gi, label: 'Tunnel via ngrok', severity: 'FAIL' },
      { pattern: /https?:\/\/pastebin\.com/gi, label: 'External data at pastebin', severity: 'WARN' },
      { pattern: /https?:\/\/([a-z0-9]+\.)?burpcollaborator\.net/gi, label: 'Burp Collaborator (pentest tool)', severity: 'FAIL' },
      // Dynamic URL construction (obfuscation)
      { pattern: /eval\s*\(\s*atob\s*\(/gi, label: 'Base64-encoded eval (obfuscation)', severity: 'FAIL' },
      { pattern: /Buffer\.from\([^)]+,\s*['"]base64['"]\)\.toString/gi, label: 'Base64 decode (possible obfuscation)', severity: 'WARN' },
    ]
  },

  PRIVILEGE_ESCALATION: {
    id: 'CHECK-4',
    name: 'Privilege Escalation',
    description: 'Attempts to write to agent identity files or system configs',
    patterns: [
      // Agent config writes
      { pattern: /writeFile[Sync]*\s*\([^)]*SOUL\.md/gi, label: 'Write to SOUL.md', severity: 'FAIL' },
      { pattern: /writeFile[Sync]*\s*\([^)]*AGENTS\.md/gi, label: 'Write to AGENTS.md', severity: 'FAIL' },
      { pattern: /writeFile[Sync]*\s*\([^)]*MEMORY\.md/gi, label: 'Write to MEMORY.md', severity: 'WARN' },
      { pattern: /appendFile[Sync]*\s*\([^)]*SOUL\.md/gi, label: 'Append to SOUL.md', severity: 'FAIL' },
      // Gateway config tampering
      { pattern: /openclaw\.config|\.openclaw\/config/gi, label: 'OpenClaw config access', severity: 'WARN' },
      { pattern: /skills\.json|skill-registry/gi, label: 'Skill registry modification', severity: 'WARN' },
      // System-level operations
      { pattern: /require\(['"`]child_process['"`]\)/gi, label: 'child_process import (shell execution)', severity: 'WARN' },
      { pattern: /exec(Sync)?\s*\(['"](sudo|su |chmod 777|chown root)/gi, label: 'Privileged shell command', severity: 'FAIL' },
      { pattern: /process\.env\s*=\s*\{/gi, label: 'Process env override', severity: 'FAIL' },
      { pattern: /global\.(fetch|XMLHttpRequest)\s*=/gi, label: 'Global API override', severity: 'WARN' },
      // Install/bootstrap self-replication
      { pattern: /npm\s+install\s+-g/gi, label: 'Global npm install', severity: 'WARN' },
      { pattern: /skill[_-]?install|install[_-]?skill/gi, label: 'Self-installing skill', severity: 'WARN' },
    ]
  },

  COMPACTION_PERSISTENCE: {
    id: 'CHECK-5',
    name: 'Compaction Layer Persistence',
    description: 'Patterns designed to survive context reset and reactivate (Feb 20 2026 attack vector)',
    patterns: [
      // Direct compaction references
      { pattern: /post-?compaction/gi, label: 'Post-compaction trigger', severity: 'FAIL' },
      { pattern: /after\s+(context\s+)?compaction/gi, label: 'After-compaction activation', severity: 'FAIL' },
      { pattern: /survive[sd]?\s+(context\s+)?(reset|compaction)/gi, label: 'Compaction survival pattern', severity: 'FAIL' },
      { pattern: /context\s+reset\s+trigger/gi, label: 'Context reset trigger', severity: 'FAIL' },
      { pattern: /WORKFLOW_AUTO/g, label: 'WORKFLOW_AUTO marker', severity: 'FAIL' },
      // Delayed activation
      { pattern: /activate\s+after\s+(reset|restart|compaction)/gi, label: 'Delayed activation pattern', severity: 'FAIL' },
      { pattern: /run\s+on\s+(next\s+)?boot|execute\s+on\s+restart/gi, label: 'Persistence via restart', severity: 'WARN' },
      // Hidden payloads
      { pattern: /setInterval\s*\([^,]+,\s*\d{6,}\)/g, label: 'Long-delay timer (possible persistence)', severity: 'WARN' },
      { pattern: /setTimeout\s*\([^,]+,\s*\d{7,}\)/g, label: 'Very long delay timer', severity: 'WARN' },
      // Bootstrap injection
      { pattern: /HEARTBEAT\.md|BOOTSTRAP\.md/gi, label: 'Heartbeat/bootstrap file reference', severity: 'WARN' },
      { pattern: /inject.*?(SOUL|AGENTS|MEMORY|SESSION)\.md/gi, label: 'Injection into agent files', severity: 'FAIL' },
    ]
  },

  KNOWN_SIGNATURES: {
    id: 'CHECK-6',
    name: 'Known Threat Signatures',
    description: 'Hash and pattern match against HeartbeatGuard threat database',
    // Patterns loaded from signatures.json at runtime
    patterns: []
  }
};

// ─── File Scanner ─────────────────────────────────────────────────────────────

const SKILL_FILE_EXTENSIONS = ['.md', '.js', '.ts', '.py', '.sh', '.json', '.mjs', '.cjs'];
const SKILL_FILE_NAMES = ['SKILL.md', 'skill.json', 'index.js', 'index.ts', 'index.py', 'main.py', 'install.sh'];

function findSkillFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // Recurse into subdirectory (one level for skills)
      const subFiles = findSkillFilesInSkill(fullPath);
      if (subFiles.length > 0) {
        results.push({ skillDir: fullPath, skillName: entry.name, files: subFiles });
      }
    } else if (entry.isFile() && isSkillFile(entry.name)) {
      // Root-level skill file
      results.push({ skillDir: dir, skillName: path.basename(dir), files: [fullPath] });
    }
  }
  return results;
}

function findSkillFilesInSkill(skillDir) {
  const files = [];
  let entries;
  try {
    entries = fs.readdirSync(skillDir, { withFileTypes: true });
  } catch (e) {
    return files;
  }
  for (const entry of entries) {
    if (entry.isFile() && isSkillFile(entry.name)) {
      files.push(path.join(skillDir, entry.name));
    }
  }
  return files;
}

function isSkillFile(filename) {
  const ext = path.extname(filename).toLowerCase();
  return SKILL_FILE_EXTENSIONS.includes(ext) || SKILL_FILE_NAMES.includes(filename);
}

function readFileContent(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 1024 * 1024) return null; // Skip files > 1MB
    return fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return null;
  }
}

function hashContent(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

// ─── Check Runner ─────────────────────────────────────────────────────────────

function runCheck(checkDef, content, filePath, signaturesDB) {
  const findings = [];

  if (checkDef === CHECKS.KNOWN_SIGNATURES) {
    return runSignatureCheck(content, filePath, signaturesDB);
  }

  for (const { pattern, label, severity } of checkDef.patterns) {
    // Reset regex state
    if (pattern.flags.includes('g')) pattern.lastIndex = 0;
    const match = pattern.exec(content);
    if (match) {
      // Find line number
      const lineNum = content.slice(0, match.index).split('\n').length;
      const lineContent = content.split('\n')[lineNum - 1]?.trim().slice(0, 120) || '';
      findings.push({
        severity,
        label,
        line: lineNum,
        excerpt: lineContent,
        file: path.basename(filePath)
      });
    }
  }

  return findings;
}

function runSignatureCheck(content, filePath, signaturesDB) {
  const findings = [];
  const contentHash = hashContent(content);

  for (const sig of signaturesDB.signatures) {
    // Hash match
    if (sig.contentHash && sig.contentHash === contentHash) {
      findings.push({
        severity: sig.severity,
        label: `[${sig.id}] ${sig.name} — exact hash match`,
        line: 0,
        excerpt: `Hash: ${contentHash}`,
        file: path.basename(filePath),
        sigId: sig.id
      });
      continue;
    }

    // Pattern match
    for (const pat of (sig.patterns || [])) {
      const regex = new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      const match = regex.exec(content);
      if (match) {
        const lineNum = content.slice(0, match.index).split('\n').length;
        const lineContent = content.split('\n')[lineNum - 1]?.trim().slice(0, 120) || '';
        findings.push({
          severity: sig.severity,
          label: `[${sig.id}] ${sig.name}`,
          line: lineNum,
          excerpt: lineContent,
          file: path.basename(filePath),
          sigId: sig.id
        });
        break; // One finding per signature per file
      }
    }

    // Suspicious domain check
    for (const domain of (sig.suspiciousDomains || [])) {
      if (content.includes(domain)) {
        const idx = content.indexOf(domain);
        const lineNum = content.slice(0, idx).split('\n').length;
        const lineContent = content.split('\n')[lineNum - 1]?.trim().slice(0, 120) || '';
        findings.push({
          severity: sig.severity,
          label: `[${sig.id}] Suspicious domain: ${domain}`,
          line: lineNum,
          excerpt: lineContent,
          file: path.basename(filePath),
          sigId: sig.id
        });
      }
    }
  }

  return findings;
}

// ─── Skill Scanner ────────────────────────────────────────────────────────────

function scanSkill(skillEntry, signaturesDB) {
  const { skillName, skillDir, files } = skillEntry;
  const result = {
    skillName,
    skillDir,
    files: [],
    checks: {},
    verdict: 'PASS',
    totalFindings: 0,
    criticalCount: 0,
    warnCount: 0
  };

  // Initialize checks
  for (const [key, def] of Object.entries(CHECKS)) {
    result.checks[key] = { name: def.name, id: def.id, status: 'PASS', findings: [] };
  }

  // Scan each file
  for (const filePath of files) {
    const content = readFileContent(filePath);
    if (!content) continue;

    const fileHash = hashContent(content);
    result.files.push({ path: filePath, hash: fileHash, size: content.length });

    for (const [key, checkDef] of Object.entries(CHECKS)) {
      const findings = runCheck(checkDef, content, filePath, signaturesDB);
      result.checks[key].findings.push(...findings);
    }
  }

  // Compute per-check status and overall verdict
  let hasFailure = false;
  let hasWarning = false;

  for (const [key, check] of Object.entries(result.checks)) {
    const hasFail = check.findings.some(f => f.severity === 'FAIL' || f.severity === 'CRITICAL');
    const hasWarn = check.findings.some(f => f.severity === 'WARN' || f.severity === 'HIGH');
    if (hasFail) { check.status = 'FAIL'; hasFailure = true; }
    else if (hasWarn) { check.status = 'WARN'; hasWarning = true; }
    result.criticalCount += check.findings.filter(f => f.severity === 'FAIL' || f.severity === 'CRITICAL').length;
    result.warnCount += check.findings.filter(f => f.severity === 'WARN' || f.severity === 'HIGH').length;
    result.totalFindings += check.findings.length;
  }

  result.verdict = hasFailure ? 'FAIL' : hasWarning ? 'WARN' : 'PASS';
  return result;
}

// ─── Console Reporter ─────────────────────────────────────────────────────────

function verdictBadge(verdict) {
  if (verdict === 'FAIL') return `${C.bgRed}${C.white}${C.bold} FAIL ${C.reset}`;
  if (verdict === 'WARN') return `${C.bgYellow}${C.bold} WARN ${C.reset}`;
  return `${C.bgGreen}${C.white}${C.bold} PASS ${C.reset}`;
}

function checkBadge(status) {
  if (status === 'FAIL') return clr('red', '✗');
  if (status === 'WARN') return clr('yellow', '⚠');
  return clr('green', '✓');
}

function printHeader() {
  console.log('');
  console.log(clr('gold', '╔══════════════════════════════════════════════════════════╗'));
  console.log(clr('gold', '║') + clr('bold', '  💓 HeartbeatGuard — Skill Security Scanner v1.0.0       ') + clr('gold', '║'));
  console.log(clr('gold', '║') + clr('dim', '     https://heartbeatguard.com | #D4A843 / #1B2A4A        ') + clr('gold', '║'));
  console.log(clr('gold', '╚══════════════════════════════════════════════════════════╝'));
  console.log('');
}

function printSkillResult(result) {
  const icon = result.verdict === 'FAIL' ? '🔴' : result.verdict === 'WARN' ? '🟡' : '🟢';
  console.log(`${icon} ${bold(result.skillName)} ${verdictBadge(result.verdict)}`);

  if (result.totalFindings > 0) {
    for (const [key, check] of Object.entries(result.checks)) {
      if (check.findings.length === 0) continue;
      console.log(`   ${checkBadge(check.status)} ${check.name}`);
      for (const f of check.findings.slice(0, 3)) { // Show max 3 findings per check
        const sev = f.severity === 'FAIL' || f.severity === 'CRITICAL'
          ? clr('red', `[${f.severity}]`)
          : clr('yellow', `[${f.severity}]`);
        const loc = f.line > 0 ? clr('dim', ` L${f.line}`) : '';
        console.log(`      ${sev}${loc} ${f.label}`);
        if (f.excerpt) {
          console.log(`        ${clr('dim', '→ ' + f.excerpt.slice(0, 100))}`);
        }
      }
      if (check.findings.length > 3) {
        console.log(`      ${clr('dim', `... and ${check.findings.length - 3} more findings`)}`);
      }
    }
  }
}

function printSummary(results, scanPaths, elapsed) {
  const total = results.length;
  const passed = results.filter(r => r.verdict === 'PASS').length;
  const warned = results.filter(r => r.verdict === 'WARN').length;
  const failed = results.filter(r => r.verdict === 'FAIL').length;

  console.log('');
  console.log(clr('gold', '──────────────────────────────────────────────────────────'));
  console.log(bold('📊 Scan Summary'));
  console.log(`   Skills scanned: ${bold(total)}`);
  console.log(`   ${clr('green', '✓ PASS:')} ${passed}  ${clr('yellow', '⚠ WARN:')} ${warned}  ${clr('red', '✗ FAIL:')} ${failed}`);
  console.log(`   Scan paths: ${scanPaths.join(', ')}`);
  console.log(`   Time: ${elapsed}ms`);
  console.log(clr('gold', '──────────────────────────────────────────────────────────'));
  console.log('');
}

// ─── HTML Reporter ────────────────────────────────────────────────────────────

function generateHTML(results, scanPaths, date, elapsed) {
  const total = results.length;
  const passed = results.filter(r => r.verdict === 'PASS').length;
  const warned = results.filter(r => r.verdict === 'WARN').length;
  const failed = results.filter(r => r.verdict === 'FAIL').length;

  const skillRows = results.map(r => {
    const verdictClass = r.verdict === 'FAIL' ? 'fail' : r.verdict === 'WARN' ? 'warn' : 'pass';
    const checkItems = Object.values(r.checks).map(c => {
      const cls = c.status === 'FAIL' ? 'fail' : c.status === 'WARN' ? 'warn' : 'pass';
      const findingsList = c.findings.length > 0
        ? `<ul class="findings-list">${c.findings.map(f => {
            const sevClass = (f.severity === 'FAIL' || f.severity === 'CRITICAL') ? 'sev-fail' : 'sev-warn';
            const excerpt = f.excerpt ? `<div class="excerpt">${escHtml(f.excerpt.slice(0, 150))}</div>` : '';
            const loc = f.line > 0 ? ` <span class="line-num">L${f.line}</span>` : '';
            return `<li class="${sevClass}">${escHtml(f.label)}${loc}${excerpt}</li>`;
          }).join('')}</ul>`
        : '';
      return `<div class="check-row ${cls}">
        <span class="check-status">${c.status === 'FAIL' ? '✗' : c.status === 'WARN' ? '⚠' : '✓'}</span>
        <span class="check-name">${escHtml(c.name)}</span>
        ${findingsList}
      </div>`;
    }).join('');

    return `<div class="skill-card ${verdictClass}">
      <div class="skill-header">
        <span class="skill-name">${escHtml(r.skillName)}</span>
        <span class="verdict-badge ${verdictClass}">${r.verdict}</span>
        <span class="skill-meta">${r.files.length} file(s) · ${r.totalFindings} finding(s)</span>
      </div>
      ${r.totalFindings > 0 ? `<div class="checks">${checkItems}</div>` : ''}
    </div>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HeartbeatGuard Skill Scan Report — ${date}</title>
  <style>
    :root {
      --navy: #1B2A4A;
      --navy-light: #243659;
      --navy-lighter: #2e4470;
      --gold: #D4A843;
      --gold-light: #e6c068;
      --red: #e05555;
      --red-light: #fdf0f0;
      --yellow: #d4a020;
      --yellow-light: #fdf8e6;
      --green: #4caf6a;
      --green-light: #f0fdf4;
      --text: #e8edf5;
      --text-muted: #8a99b8;
      --border: #2e4470;
      --card-bg: #1e3050;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
      background: var(--navy);
      color: var(--text);
      min-height: 100vh;
    }
    header {
      background: linear-gradient(135deg, var(--navy) 0%, var(--navy-lighter) 100%);
      border-bottom: 2px solid var(--gold);
      padding: 24px 32px;
      display: flex;
      align-items: center;
      gap: 20px;
    }
    .logo-pulse {
      width: 48px; height: 48px;
      background: var(--gold);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 24px;
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { box-shadow: 0 0 0 0 rgba(212,168,67,0.4); }
      50% { box-shadow: 0 0 0 12px rgba(212,168,67,0); }
    }
    header h1 { font-size: 24px; color: var(--gold); font-weight: 700; }
    header .subtitle { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
    .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
    .stats-grid {
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
      margin-bottom: 32px;
    }
    .stat-card {
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 10px; padding: 20px; text-align: center;
    }
    .stat-card .num { font-size: 40px; font-weight: 800; line-height: 1; }
    .stat-card .label { font-size: 13px; color: var(--text-muted); margin-top: 6px; }
    .stat-card.pass .num { color: var(--green); }
    .stat-card.warn .num { color: var(--gold); }
    .stat-card.fail .num { color: var(--red); }
    .stat-card.total .num { color: var(--gold-light); }
    .section-title {
      font-size: 18px; font-weight: 700; color: var(--gold);
      margin-bottom: 16px; padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }
    .scan-meta {
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 10px; padding: 16px; margin-bottom: 24px;
      font-size: 13px; color: var(--text-muted);
    }
    .scan-meta span { color: var(--text); margin-left: 4px; }
    .skill-card {
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 10px; margin-bottom: 12px; overflow: hidden;
    }
    .skill-card.fail { border-left: 4px solid var(--red); }
    .skill-card.warn { border-left: 4px solid var(--gold); }
    .skill-card.pass { border-left: 4px solid var(--green); }
    .skill-header {
      padding: 14px 18px; display: flex; align-items: center; gap: 12px;
      cursor: pointer;
    }
    .skill-name { font-weight: 700; font-size: 15px; flex: 1; }
    .skill-meta { font-size: 12px; color: var(--text-muted); }
    .verdict-badge {
      font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 4px;
      letter-spacing: 0.05em;
    }
    .verdict-badge.pass { background: rgba(76,175,106,0.2); color: var(--green); }
    .verdict-badge.warn { background: rgba(212,168,67,0.2); color: var(--gold); }
    .verdict-badge.fail { background: rgba(224,85,85,0.2); color: var(--red); }
    .checks { padding: 0 18px 14px; border-top: 1px solid var(--border); margin-top: 2px; }
    .check-row {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 8px 0; border-bottom: 1px solid rgba(46,68,112,0.5); font-size: 13px;
      flex-wrap: wrap;
    }
    .check-row:last-child { border-bottom: none; }
    .check-status { width: 18px; text-align: center; flex-shrink: 0; margin-top: 1px; }
    .check-row.pass .check-status { color: var(--green); }
    .check-row.warn .check-status { color: var(--gold); }
    .check-row.fail .check-status { color: var(--red); }
    .check-name { font-weight: 600; color: var(--text); }
    .findings-list {
      width: 100%; margin-top: 6px; margin-left: 28px;
      list-style: none; font-size: 12px;
    }
    .findings-list li {
      padding: 4px 8px; border-radius: 4px; margin-bottom: 3px;
    }
    .sev-fail { background: rgba(224,85,85,0.12); color: #f08080; }
    .sev-warn { background: rgba(212,168,67,0.12); color: #d4a843; }
    .line-num { color: var(--text-muted); font-size: 11px; margin-left: 6px; }
    .excerpt {
      font-family: monospace; font-size: 11px; color: var(--text-muted);
      margin-top: 2px; white-space: pre-wrap; word-break: break-all;
    }
    .filter-bar {
      display: flex; gap: 8px; margin-bottom: 20px;
    }
    .filter-btn {
      padding: 6px 14px; border: 1px solid var(--border); border-radius: 6px;
      background: transparent; color: var(--text-muted); cursor: pointer; font-size: 13px;
      transition: all 0.15s;
    }
    .filter-btn:hover, .filter-btn.active { background: var(--navy-lighter); color: var(--text); }
    footer {
      text-align: center; padding: 32px; color: var(--text-muted); font-size: 12px;
      border-top: 1px solid var(--border); margin-top: 32px;
    }
    footer a { color: var(--gold); text-decoration: none; }
    .ekg-line {
      width: 100%; height: 40px; overflow: hidden;
      background: linear-gradient(90deg, transparent, rgba(212,168,67,0.1), transparent);
    }
    .ekg-svg { animation: ekg-scroll 8s linear infinite; }
    @keyframes ekg-scroll { from { transform: translateX(0); } to { transform: translateX(-50%); } }
  </style>
</head>
<body>
<header>
  <div class="logo-pulse">💓</div>
  <div>
    <h1>HeartbeatGuard Skill Scanner</h1>
    <div class="subtitle">Security scan report · Generated ${date} · ${elapsed}ms · heartbeatguard.com</div>
  </div>
</header>

<div class="container">
  <div class="stats-grid">
    <div class="stat-card total"><div class="num">${total}</div><div class="label">Skills Scanned</div></div>
    <div class="stat-card pass"><div class="num">${passed}</div><div class="label">Clean (PASS)</div></div>
    <div class="stat-card warn"><div class="num">${warned}</div><div class="label">Suspicious (WARN)</div></div>
    <div class="stat-card fail"><div class="num">${failed}</div><div class="label">Malicious (FAIL)</div></div>
  </div>

  <div class="scan-meta">
    📁 Scan paths: <span>${escHtml(scanPaths.join(' | '))}</span>
    &nbsp;&nbsp;|&nbsp;&nbsp;
    🕐 Scan time: <span>${elapsed}ms</span>
    &nbsp;&nbsp;|&nbsp;&nbsp;
    📅 Date: <span>${date}</span>
  </div>

  <div class="section-title">🔍 Skill Results</div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterSkills('all')">All (${total})</button>
    <button class="filter-btn" onclick="filterSkills('fail')" style="color:#f08080">FAIL (${failed})</button>
    <button class="filter-btn" onclick="filterSkills('warn')" style="color:#d4a843">WARN (${warned})</button>
    <button class="filter-btn" onclick="filterSkills('pass')" style="color:#4caf6a">PASS (${passed})</button>
  </div>

  <div id="skills-container">
    ${skillRows}
  </div>
</div>

<footer>
  Generated by <a href="https://heartbeatguard.com">HeartbeatGuard</a> Skill Scanner v1.0.0 &nbsp;·&nbsp;
  <a href="https://heartbeatguard.com">heartbeatguard.com</a> &nbsp;·&nbsp;
  Security for AI Agents
</footer>

<script>
function filterSkills(verdict) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.skill-card').forEach(card => {
    card.style.display = verdict === 'all' || card.classList.contains(verdict) ? '' : 'none';
  });
}
</script>
</body>
</html>`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

function getDefaultScanPaths() {
  const paths = [];
  const home = os.homedir();

  // OpenClaw default skills dir
  const openclawSkills = path.join(home, '.openclaw', 'skills');
  if (fs.existsSync(openclawSkills)) paths.push(openclawSkills);

  // OpenClaw npm global install (Windows)
  const npmGlobalWin = path.join(
    process.env.APPDATA || '',
    'npm', 'node_modules', 'openclaw', 'skills'
  );
  if (fs.existsSync(npmGlobalWin)) paths.push(npmGlobalWin);

  // OpenClaw npm global install (Unix)
  const npmGlobalUnix = '/usr/local/lib/node_modules/openclaw/skills';
  if (fs.existsSync(npmGlobalUnix)) paths.push(npmGlobalUnix);

  return paths;
}

function parseArgs() {
  const args = process.argv.slice(2);
  const paths = [];
  let outputDir = process.cwd();
  let verbose = false;
  let jsonOnly = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' || args[i] === '-o') {
      outputDir = args[++i];
    } else if (args[i] === '--verbose' || args[i] === '-v') {
      verbose = true;
    } else if (args[i] === '--json') {
      jsonOnly = true;
    } else if (!args[i].startsWith('-')) {
      paths.push(args[i]);
    }
  }

  return { paths, outputDir, verbose, jsonOnly };
}

async function main() {
  const startTime = Date.now();
  const { paths: argPaths, outputDir, verbose, jsonOnly } = parseArgs();

  // Load signatures DB
  const sigPath = path.join(__dirname, 'signatures.json');
  let signaturesDB = { signatures: [] };
  if (fs.existsSync(sigPath)) {
    try {
      signaturesDB = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
    } catch (e) {
      console.warn('Warning: Could not load signatures.json');
    }
  }

  // Determine scan paths
  const scanPaths = argPaths.length > 0 ? argPaths : getDefaultScanPaths();
  if (scanPaths.length === 0) {
    console.error('No skill paths found. Pass a path as an argument or install OpenClaw.');
    process.exit(1);
  }

  if (!jsonOnly) {
    printHeader();
    console.log(`${bold('🔍 Scanning paths:')}`);
    scanPaths.forEach(p => console.log(`   ${clr('cyan', p)}`));
    console.log('');
  }

  // Discover and scan all skills
  const allSkills = [];
  for (const scanPath of scanPaths) {
    const skills = findSkillFiles(scanPath);
    allSkills.push(...skills);
  }

  if (allSkills.length === 0) {
    console.log('No skill files found in the specified paths.');
    process.exit(0);
  }

  if (!jsonOnly) {
    console.log(`Found ${bold(allSkills.length)} skills. Running security checks...\n`);
    console.log(clr('gold', '──────────────────────────────────────────────────────────'));
    console.log('');
  }

  const results = [];
  for (const skill of allSkills) {
    const result = scanSkill(skill, signaturesDB);
    results.push(result);
    if (!jsonOnly) {
      printSkillResult(result);
    }
  }

  const elapsed = Date.now() - startTime;

  if (!jsonOnly) {
    printSummary(results, scanPaths, elapsed);
  }

  // Sort results: FAIL first, WARN second, PASS last
  results.sort((a, b) => {
    const order = { FAIL: 0, WARN: 1, PASS: 2 };
    return order[a.verdict] - order[b.verdict];
  });

  // Generate output files
  const dateStr = new Date().toISOString().split('T')[0];
  const outputBase = path.join(outputDir, `hbg-scan-report-${dateStr}`);

  // JSON report
  const jsonReport = {
    meta: {
      scanner: 'hbg-scan',
      version: '1.0.0',
      date: new Date().toISOString(),
      elapsed,
      scanPaths,
      signaturesVersion: signaturesDB.version || '1.0.0'
    },
    summary: {
      total: results.length,
      passed: results.filter(r => r.verdict === 'PASS').length,
      warned: results.filter(r => r.verdict === 'WARN').length,
      failed: results.filter(r => r.verdict === 'FAIL').length
    },
    skills: results
  };

  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(`${outputBase}.json`, JSON.stringify(jsonReport, null, 2));

  // HTML report
  const html = generateHTML(results, scanPaths, dateStr, elapsed);
  fs.writeFileSync(`${outputBase}.html`, html);

  if (!jsonOnly) {
    console.log(`📄 Reports saved:`);
    console.log(`   JSON: ${clr('cyan', `${outputBase}.json`)}`);
    console.log(`   HTML: ${clr('cyan', `${outputBase}.html`)}`);
    console.log('');
  } else {
    // JSON-only mode: print summary to stdout
    console.log(JSON.stringify(jsonReport.summary, null, 2));
  }

  // Exit code: 0=pass, 1=warnings, 2=failures
  const hasFailures = results.some(r => r.verdict === 'FAIL');
  const hasWarnings = results.some(r => r.verdict === 'WARN');
  process.exit(hasFailures ? 2 : hasWarnings ? 1 : 0);
}

main().catch(err => {
  console.error('Scanner error:', err.message);
  process.exit(3);
});
