# secure-install 🛡️

**Secure npm package installer with risk analysis, dependency scanning, and vulnerability detection.**

Instead of scanning for vulnerabilities *after* installation (like `npm audit`), `secure-install` actively evaluates the risk of a package **before** installation, acting as a proactive firewall for your supply chain.

## 🚀 Features

- **Typosquatting Protection** - Detects malicious misspelled packages (e.g., `react-domm` vs `react-dom`)
- **OSV Vulnerability Checks** - Queries OSV.dev database for known CVEs before installation
- **Malicious Package Detection** - Checks against npm security advisories database
- **Suspicious Script Detection** - Analyzes preinstall/postinstall scripts for obfuscation, network calls, env exfiltration
- **Dependency Infiltration Check** - Scans dependencies for suspicious patterns
- **License & Repository Verification** - Validates package metadata
- **Rate Limiting & Caching** - Fast API calls with intelligent caching

## 📦 Installation

### Global Installation (Linux/macOS/Windows)
```bash
npm install -g secure-install
```

### Local Installation (as dev dependency)
```bash
npm install --save-dev secure-install
```

### Without Installing (using npx)
```bash
npx secure-install <package>
```

> **Note for Windows**: If `secure-install` command is not found after global install, restart your terminal or use `npx secure-install` instead.

## ⚙️ Usage

### Global Installation
```bash
secure-install lodash
secure-install axios
```

### Using npx (no install needed)
```bash
npx secure-install lodash
npx secure-install axios express
```

### Using locally installed package
```bash
npm install --save-dev secure-install
npx secure-install lodash
# Or run directly
./node_modules/.bin/secure-install lodash
```

### Security Report Only (No Installation)

```bash
secure-install <package> --report
secure-install <package> -r
```

### Multiple Packages

```bash
secure-install lodash axios express
```

### CI/CD Mode

```bash
secure-install <package> --ci --json --dry-run
```

## 📋 Options

| Flag | Short | Description |
|------|-------|-------------|
| `--safe` | `-s` | Run in safe mode (--ignore-scripts) |
| `--force` | `-f` | Force installation even on high risk |
| `--quick` | `-q` | Quick install (--prefer-offline --legacy-peer-deps) |
| `--verbose` | `-v` | Show verbose npm output |
| `--json` | | Output results as JSON |
| `--quiet` | `-Q` | Quiet mode (no prompts, minimal output) |
| `--report` | `-r` | Generate HTML security report (no install) |
| `--dry-run` | | Analyze package without installing |
| `--skip-deps` | | Skip dependency scanning for faster analysis |
| `--ci` | | CI/CD mode (quiet + no prompts) |
| `--output=<file>` | `-o` | Custom report output path |
| `--threshold=<n>` | | Set risk threshold (default: 70) |
| `--version` | `-V` | Show version |
| `--help` | `-h` | Show help message |

## 📊 Example Output

### Security Report

```
🔒 secure-install: Analyzing axios...

📊 Security Report
Risk Score: 50/100

📋 Analysis Details:
 - ⚠️ Only 1 maintainer listed (lower bus factor)
 - 📄 License: MIT
 - 📦 Repository: https://github.com/axios/axios

📦 Package Info:
   Version: 1.15.0
   Maintainers: 1
   Dependencies: 3
   License: MIT
   Repo: https://github.com/axios/axios
```

### HTML Report

Generates a styled HTML report when using `--report`:

```bash
secure-install axios --report
# Creates: security-report-axios-1234567890.html
```

### CI/CD Mode (JSON)

```bash
secure-install lodash axios --ci --json --dry-run
```

```json
[
  {
    "score": 0,
    "details": ["📄 License: MIT", "📦 Repository: git+github.com/lodash/lodash"],
    "metadata": { "name": "lodash", "version": "4.18.1", "maintainers": 3 }
  },
  {
    "score": 50,
    "details": ["⚠️ Only 1 maintainer listed", "📄 License: MIT"],
    "metadata": { "name": "axios", "version": "1.15.0", "maintainers": 1 }
  }
]
```

## 🎯 Risk Score Interpretation

| Score | Status | Action |
|-------|--------|--------|
| 0-39 | Safe | Proceeds automatically |
| 40-69 | Medium Risk | Prompts for confirmation |
| 70-100 | High Risk | Blocks installation (use `--force` to bypass) |

## 🔐 Security Checks

1. **Malicious Package Database** - Checks npm security advisories
2. **Typosquatting Detection** - Compares against popular packages
3. **Vulnerability Scan** - Queries OSV.dev for CVEs
4. **Suspicious Scripts** - Detects obfuscation, network calls, env exfiltration
5. **Dependency Analysis** - Scans dependencies for risks
6. **Maintainer Check** - Flags single-maintainer packages
7. **Package Age** - Detects newly published packages with no maintainers
8. **License Verification** - Validates package license

## 🔧 Configuration

Create a `.secure-install.json` config file in your project:

```json
{
  "threshold": 70,
  "skipDeps": false
}
```

Config file locations (in order of priority):
1. `.secure-install.json`
2. `secure-install.config.json`
3. `.config/secure-install.json`
4. `~/.secure-install.json`

## 📝 Examples

```bash
# With global installation
secure-install lodash

# With npx (no install needed)
npx secure-install lodash

# With local installation
npm install --save-dev secure-install
npm run secure-install lodash
# Or using npx in local project
npx secure-install lodash

# Install with safe mode
secure-install sketchy-package --safe

# Generate HTML report
secure-install express --report --output=security.html

# Quick scan (skip deps)
secure-install lodash --skip-deps --report

# CI/CD pipeline
secure-install package1 package2 --ci --json --dry-run

# Custom threshold
secure-install axios --threshold=50 --force
```

## License

MIT
