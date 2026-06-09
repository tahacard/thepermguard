#!/usr/bin/env node
// 🔒 permguard — File Permission Security Scanner

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const GREEN  = '\x1b[32m'; const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m'; const CYAN   = '\x1b[36m';
const BOLD   = '\x1b[1m';  const DIM    = '\x1b[2m';
const NC     = '\x1b[0m';

const SKIP_DIRS = new Set(['.git','node_modules','dist','build','.next','__pycache__']);

const SECRET_PATTERNS = [
  /PRIVATE KEY/i, /BEGIN RSA/i, /BEGIN EC/i,
  /aws_secret/i, /api[_-]?key\s*=/i, /password\s*=/i,
  /token\s*=/i, /secret\s*=/i,
];

const RULES = [
  {
    id: 'P001', level: 'CRITICAL',
    check: (f, s) => s.isFile() && (s.mode & 0o002),
    msg: 'World-writable file',
  },
  {
    id: 'P002', level: 'CRITICAL',
    check: (f, s) => s.isDirectory() && (s.mode & 0o002),
    msg: 'World-writable directory',
  },
  {
    id: 'P003', level: 'CRITICAL',
    check: (f, s) => {
      const base = path.basename(f).toLowerCase();
      if (!['.env', 'id_rsa', 'id_ed25519', '.pem', '.key'].some(x => base.includes(x))) return false;
      return s.isFile() && (s.mode & 0o044);
    },
    msg: 'Sensitive file is group/world-readable',
  },
  {
    id: 'P004', level: 'WARNING',
    check: (f, s) => {
      const ext = path.extname(f).toLowerCase();
      return s.isFile() && ['.json','.yml','.yaml','.env','.config'].includes(ext) && (s.mode & 0o111);
    },
    msg: 'Non-script config file has execute bit set',
  },
  {
    id: 'P005', level: 'WARNING',
    check: (f, s) => s.isFile() && (s.mode & 0o022) && !s.isDirectory(),
    msg: 'File is group/world-writable',
  },
  {
    id: 'P006', level: 'CRITICAL',
    check: (f, s) => {
      if (!s.isFile()) return false;
      const base = path.basename(f).toLowerCase();
      if (!['.env', '.env.local', '.env.production'].includes(base)) return false;
      try {
        const content = fs.readFileSync(f, 'utf8');
        return SECRET_PATTERNS.some(p => p.test(content));
      } catch { return false; }
    },
    msg: 'Secret file contains sensitive values and may be exposed',
  },
];

function octal(mode) {
  return '0' + (mode & 0o777).toString(8);
}

function scanPath(targetPath, maxDepth = 5, depth = 0) {
  if (depth > maxDepth) return [];
  const issues = [];

  let entries;
  try { entries = fs.readdirSync(targetPath); }
  catch { return issues; }

  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;
    const fullPath = path.join(targetPath, entry);
    let stat;
    try { stat = fs.statSync(fullPath); } catch { continue; }

    for (const rule of RULES) {
      if (rule.check(fullPath, stat)) {
        issues.push({
          file: path.relative(process.cwd(), fullPath),
          level: rule.level,
          msg: rule.msg,
          mode: octal(stat.mode),
          id: rule.id,
        });
      }
    }

    if (stat.isDirectory()) {
      issues.push(...scanPath(fullPath, maxDepth, depth + 1));
    }
  }
  return issues;
}

function printResults(issues, target) {
  const crits = issues.filter(i => i.level === 'CRITICAL');
  const warns = issues.filter(i => i.level === 'WARNING');
  const infos = issues.filter(i => i.level === 'INFO');

  console.log(`\n${CYAN}${BOLD}🔒 permguard — ${target}${NC}`);
  console.log('─'.repeat(65));

  if (!issues.length) {
    console.log(`${GREEN}✅ No permission issues found!${NC}\n`);
    return;
  }

  issues.forEach(({ file, level, msg, mode }) => {
    const color = level === 'CRITICAL' ? RED : level === 'WARNING' ? YELLOW : DIM;
    const icon  = level === 'CRITICAL' ? '❌' : level === 'WARNING' ? '⚠️ ' : 'ℹ️ ';
    console.log(`${color}${icon} ${level.padEnd(8)}${NC}  ${file.padEnd(30)} ${DIM}(${mode})${NC}`);
    console.log(`           ${DIM}${msg}${NC}`);
  });

  console.log(`\n${RED}${crits.length} critical${NC}  ${YELLOW}${warns.length} warnings${NC}  ${DIM}${infos.length} info${NC}\n`);
  if (crits.length > 0) process.exit(1);
}

function runDemo() {
  console.log(`\n${CYAN}${BOLD}🔒 permguard — Demo Mode${NC}\n`);
  const mockIssues = [
    { file: '.env',              level: 'CRITICAL', msg: 'Secret file contains sensitive values and may be exposed', mode: '0644' },
    { file: 'id_rsa',           level: 'CRITICAL', msg: 'Sensitive file is group/world-readable',                  mode: '0644' },
    { file: 'scripts/deploy.sh',level: 'WARNING',  msg: 'File is group/world-writable',                            mode: '0775' },
    { file: 'uploads/',         level: 'WARNING',  msg: 'World-writable directory',                                mode: '0777' },
    { file: 'config.json',      level: 'WARNING',  msg: 'Non-script config file has execute bit set',              mode: '0755' },
  ];
  printResults(mockIssues, 'demo project');
}

const args   = process.argv.slice(2);
const cmd    = args[0] || 'demo';
const target = args[1] || '.';

console.log(`\n${CYAN}${BOLD}🔒 permguard${NC}\n`);

if (cmd === 'demo') {
  runDemo();
} else if (cmd === 'scan') {
  const issues = scanPath(path.resolve(target));
  printResults(issues, target);
} else {
  console.log(`Usage:`);
  console.log(`  node src/scanner.js demo`);
  console.log(`  node src/scanner.js scan .`);
  console.log(`  node src/scanner.js scan /path/to/project\n`);
}
