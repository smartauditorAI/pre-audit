# pre-audit.sh - Code Analysis & Security Audit AI Agent

## Two modes of operation:

DIFF MODE (default):
* Compares HEAD against a reference and audits the changes

FULL MODE (-f):
* Performs a complete audit of the entire codebase (no diffs)

# Steps performed:
1. AI Code Summary - highlights key features and structure
2. AI Security Audit - identifies security-relevant issues
3. npm audit - checks for vulnerable npm dependencies
4. `semgrep ci` - full CI-style security scan
5. `semgrep --config=p/owasp-top-ten .` - OWASP Top 10 scan
6. Runs Slither on Solidity files
7. Saves comprehensive report to pre-audit-report-YYYY-MM-DD.md

# Prerequisites:
* LM Studio running with local server enabled (default: http://localhost:1234/v1)
* LM Studio Model loaded: `qwen/qwen3-vl-8b`
* On LM Studio -> Load -> Context Length change value to 16384 at least!
* semgrep installed          →  `pip install semgrep`
* slither-analyzer installed →  `pip install slither-analyzer`
* jq installed               →  `brew install jq` / `apt install jq`

# Usage:
```
./pre-audit.sh                    # Diff mode: auto-detect reference
./pre-audit.sh <branch>           # Diff mode: compare HEAD against branch
./pre-audit.sh <tag>              # Diff mode: compare HEAD against tag
./pre-audit.sh -f                 # Full mode: audit entire current repo
./pre-audit.sh -f <branch/tag>    # Full mode: checkout & audit that ref
```

# Examples:
```
./pre-audit.sh main               # Audit changes since main branch
./pre-audit.sh v2.0.0             # Audit changes since tag v2.0.0
./pre-audit.sh -f                 # Full audit of current codebase
./pre-audit.sh -f v1.0.0          # Full audit of v1.0.0 tag
./pre-audit.sh -f develop         # Full audit of develop branch
```
