# 🔒 permguard

> Audits file and directory permissions in a project and flags insecure settings before they reach production.

[![CI](https://img.shields.io/github/actions/workflow/status/yourusername/permguard/ci.yml?style=for-the-badge)](https://github.com/yourusername/permguard/actions)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](./LICENSE)
[![Codespace Ready](https://img.shields.io/badge/Codespace-Ready-green?style=for-the-badge&logo=github)](https://codespaces.new/yourusername/permguard)

---

## 🚀 What is permguard?

`permguard` scans your project directory for dangerous file and folder permission settings — world-writable files, executable configs, private key exposure, and more. Catch misconfigurations before deployment.

```bash
permguard scan .                     # Scan current directory
permguard scan /etc --depth 3        # Scan with depth limit
permguard scan . --fix               # Auto-fix safe issues
permguard scan . --format json       # JSON output for CI
permguard demo                       # Run built-in demo
```

## ✨ Features
- 🔍 Detects world-writable files (777, 666)
- 🔑 Flags exposed private keys and secrets
- 📋 Reports executable non-scripts (.env, .json)
- 🗂️ Checks directory traversal risks
- 🔧 Auto-fix mode for common issues
- 📊 JSON and Markdown report export
- 🚦 CI-friendly exit codes

## 📊 Sample Output
```
🔒 permguard — scan results
────────────────────────────────────────────
❌ CRITICAL  .env              World-readable (644) — contains secrets
❌ CRITICAL  id_rsa            Private key is world-readable (644)
⚠️  WARNING   scripts/deploy.sh  Executable bit on non-owner (755 → 744)
⚠️  WARNING   uploads/          World-writable directory (777)
ℹ️  INFO      config.json       Executable bit set unnecessarily

2 critical  2 warnings  1 info
```

## 🏆 Achievement Scripts
```bash
bash scripts/setup.sh && bash scripts/unlock-all.sh
```

## 🤝 Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md)
