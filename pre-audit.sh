#!/usr/bin/env bash

# =============================================================================
# pre-audit.sh - Code Analysis & Security Audit
# 
# Two modes of operation:
#
# DIFF MODE (default):
#   Compares HEAD against a reference and audits the changes
#
# FULL MODE (-f):
#   Performs a complete audit of the entire codebase (no diffs)
#
# Steps performed:
#   1. AI Code Summary - highlights key features and structure
#   2. AI Security Audit - identifies security-relevant issues
#   3. npm audit - checks for vulnerable npm dependencies
#   4. semgrep ci - full CI-style security scan
#   5. semgrep --config=p/owasp-top-ten . - OWASP Top 10 scan
#   6. Runs Slither on Solidity files
#   7. Saves comprehensive report to pre-audit-report-YYYY-MM-DD.md
#
# Prerequisites:
#   - LM Studio running with local server enabled (default: http://localhost:1234/v1)
#   - LM Studio Model loaded: qwen/qwen3-vl-8b
#   - On LM Studio -> Load -> Context Length change value to 16384 at least!
#   - semgrep installed          →  pip install semgrep
#   - slither-analyzer installed →  pip install slither-analyzer
#   - jq installed               →  brew install jq / apt install jq
#   - scc installed              →  brew install scc / go install github.com/boyter/scc/v3@latest
#
# Usage:
#   ./pre-audit.sh                    # Diff mode: auto-detect reference
#   ./pre-audit.sh <branch>           # Diff mode: compare HEAD against branch
#   ./pre-audit.sh <tag>              # Diff mode: compare HEAD against tag
#   ./pre-audit.sh -f                 # Full mode: audit entire current repo
#   ./pre-audit.sh -f <branch/tag>    # Full mode: checkout & audit that ref
#
# Examples:
#   ./pre-audit.sh main               # Audit changes since main branch
#   ./pre-audit.sh v2.0.0             # Audit changes since tag v2.0.0
#   ./pre-audit.sh -f                 # Full audit of current codebase
#   ./pre-audit.sh -f v1.0.0          # Full audit of v1.0.0 tag
#   ./pre-audit.sh -f develop         # Full audit of develop branch
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# 1. Parse arguments
# ─────────────────────────────────────────────────────────────────────────────

FULL_MODE=false
TARGET_REF=""
PREV_REF=""
ORIGINAL_BRANCH=""

# Parse -f flag
while getopts "fh" opt; do
    case $opt in
        f)
            FULL_MODE=true
            ;;
        h)
            echo "Usage: ./pre-audit.sh [-f] [branch/tag]"
            echo ""
            echo "Options:"
            echo "  -f          Full mode: audit entire codebase (no diffs)"
            echo "  -h          Show this help message"
            echo ""
            echo "Arguments:"
            echo "  branch/tag  Reference to compare against (diff mode)"
            echo "              or checkout and audit (full mode with -f)"
            exit 0
            ;;
        *)
            echo "Usage: ./pre-audit.sh [-f] [branch/tag]"
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# Get optional branch/tag argument
if [ $# -ge 1 ]; then
    TARGET_REF="$1"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. Determine mode and setup
# ─────────────────────────────────────────────────────────────────────────────

if [ "$FULL_MODE" = true ]; then
    echo "🔍 FULL AUDIT MODE"
    echo "══════════════════════════════════════"
    
    if [ -n "$TARGET_REF" ]; then
        # Checkout the specified branch/tag
        ORIGINAL_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || git rev-parse --short HEAD)
        
        # Validate the reference
        if git rev-parse --verify "$TARGET_REF" >/dev/null 2>&1; then
            echo "Checking out: $TARGET_REF"
            git checkout "$TARGET_REF" --quiet 2>/dev/null || {
                echo "Error: Could not checkout '$TARGET_REF'"
                exit 1
            }
        elif git rev-parse --verify "origin/$TARGET_REF" >/dev/null 2>&1; then
            echo "Checking out: origin/$TARGET_REF"
            git checkout "origin/$TARGET_REF" --quiet 2>/dev/null || {
                echo "Error: Could not checkout 'origin/$TARGET_REF'"
                exit 1
            }
            TARGET_REF="origin/$TARGET_REF"
        else
            echo "Error: '$TARGET_REF' is not a valid branch, tag, or commit."
            echo ""
            echo "Available branches:"
            git branch -a | head -15
            echo ""
            echo "Available tags:"
            git tag | tail -10
            exit 1
        fi
        AUDIT_TARGET="$TARGET_REF"
    else
        AUDIT_TARGET="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'HEAD')"
        echo "Auditing current branch: $AUDIT_TARGET"
    fi
    
    # Get all source files for full audit
    ALL_FILES=$(find . -type f \( -name "*.ts" -o -name "*.js" -o -name "*.tsx" -o -name "*.jsx" \
        -o -name "*.py" -o -name "*.sol" -o -name "*.go" -o -name "*.java" \
        -o -name "*.rs" -o -name "*.rb" -o -name "*.php" \) \
        ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" ! -path "*/build/*" \
        2>/dev/null | head -100)
    
    FILE_COUNT=$(echo "$ALL_FILES" | grep -c . || echo "0")
    
    echo ""
    echo "📊 Audit Summary:"
    echo "   Target:    $AUDIT_TARGET ($(git rev-parse --short HEAD))"
    echo "   Files:     $FILE_COUNT source files found"
    echo ""
    
    # For full mode, create a summary of the codebase instead of diff
    CODE_SUMMARY=""
    for file in $ALL_FILES; do
        if [ -f "$file" ]; then
            LINES=$(wc -l < "$file" | tr -d ' ')
            CODE_SUMMARY="${CODE_SUMMARY}
- $file ($LINES lines)"
        fi
    done
    
    # Truncate if too long
    CODE_SUMMARY=$(echo "$CODE_SUMMARY" | head -50)
    
    DIFF="FULL AUDIT MODE - Analyzing entire codebase

Files in repository:
$CODE_SUMMARY

(Showing first 50 files)

Sample code from key files:"
    
    # Add snippets from a few key files
    for file in $(echo "$ALL_FILES" | head -5); do
        if [ -f "$file" ]; then
            DIFF="${DIFF}

--- $file ---
$(head -30 "$file" 2>/dev/null || echo "(could not read)")"
        fi
    done
    
    # Truncate for LLM
    DIFF="${DIFF:0:6000}"
    
    CHANGED_FILES="$ALL_FILES"
    PREV_REF="(full audit)"
    
else
    echo "📋 DIFF AUDIT MODE"
    echo "══════════════════════════════════════"
    
    if [ -n "$TARGET_REF" ]; then
        # Validate the reference
        if git rev-parse --verify "$TARGET_REF" >/dev/null 2>&1; then
            PREV_REF="$TARGET_REF"
            echo "Comparing HEAD against: $TARGET_REF"
        elif git rev-parse --verify "origin/$TARGET_REF" >/dev/null 2>&1; then
            PREV_REF="origin/$TARGET_REF"
            echo "Comparing HEAD against: origin/$TARGET_REF"
        else
            echo "Error: '$TARGET_REF' is not a valid branch, tag, or commit."
            echo ""
            echo "Available branches:"
            git branch -a | head -20
            echo ""
            echo "Available tags:"
            git tag | tail -10
            exit 1
        fi
    else
        # No argument: auto-detect reference
        echo "No reference specified, auto-detecting..."
        
        PREV_BRANCH=$(git rev-parse --abbrev-ref @{-1} 2>/dev/null || echo "")

        if [ -n "$PREV_BRANCH" ] && git rev-parse --verify "$PREV_BRANCH" >/dev/null 2>&1; then
            PREV_REF="$PREV_BRANCH"
            echo "Comparing against previous branch: $PREV_BRANCH"
        else
            if git rev-parse --verify "origin/main" >/dev/null 2>&1; then
                PREV_REF="origin/main"
            elif git rev-parse --verify "main" >/dev/null 2>&1; then
                PREV_REF="main"
            elif git rev-parse --verify "origin/master" >/dev/null 2>&1; then
                PREV_REF="origin/master"
            elif git rev-parse --verify "master" >/dev/null 2>&1; then
                PREV_REF="master"
            else
                PREV_REF="HEAD^"
            fi
            echo "Comparing against: $PREV_REF"
        fi
    fi

    # Get the diff
    DIFF=$(git diff "$PREV_REF" HEAD)
    CHANGED_FILES=$(git diff --name-only "$PREV_REF" HEAD 2>/dev/null || echo "")

    # Check if there are any changes
    if [ -z "$DIFF" ]; then
        echo ""
        echo "No changes detected between $PREV_REF and HEAD."
        echo ""
        echo "This could mean:"
        echo "  - You're already on the same commit as $PREV_REF"
        echo "  - Try specifying a different branch/tag: ./pre-audit.sh <branch-or-tag>"
        echo "  - Or use full mode: ./pre-audit.sh -f"
        exit 0
    fi

    # Show summary
    COMMIT_COUNT=$(git rev-list --count "$PREV_REF"..HEAD 2>/dev/null || echo "?")
    FILE_COUNT=$(echo "$CHANGED_FILES" | grep -c . || echo "0")
    echo ""
    echo "📊 Comparison Summary:"
    echo "   Reference: $PREV_REF"
    echo "   Target:    HEAD ($(git rev-parse --short HEAD))"
    echo "   Commits:   $COMMIT_COUNT"
    echo "   Files:     $FILE_COUNT changed"
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2.5. Lines of Code Analysis
# ─────────────────────────────────────────────────────────────────────────────

LOC_REPORT=""

if [ "$FULL_MODE" = true ]; then
    echo "📊 Lines of Code (scc) ..."
    if command -v scc >/dev/null 2>&1; then
        LOC_REPORT=$(scc --exclude-dir=node_modules,dist,build,.git,vendor,out --no-cocomo 2>/dev/null)
        echo "$LOC_REPORT"
    else
        echo "→ scc not installed (brew install scc / go install github.com/boyter/scc/v3@latest)"
        LOC_REPORT="(scc skipped - not installed)"
    fi
    echo ""
else
    echo "📊 Diff Line Statistics ..."
    
    # Count lines added and removed from the diff
    LINES_ADDED=$(echo "$DIFF" | grep -c '^+[^+]' 2>/dev/null || echo "0")
    LINES_REMOVED=$(echo "$DIFF" | grep -c '^-[^-]' 2>/dev/null || echo "0")
    LINES_TOTAL=$((LINES_ADDED + LINES_REMOVED))
    
    # Get per-file stats
    DIFF_STAT=$(git diff --stat "$PREV_REF" HEAD 2>/dev/null | tail -1)
    
    echo "   Lines added:   +$LINES_ADDED"
    echo "   Lines removed: -$LINES_REMOVED"
    echo "   Total changed: $LINES_TOTAL lines"
    echo ""
    echo "   $DIFF_STAT"
    
    LOC_REPORT="Lines added:   +$LINES_ADDED
Lines removed: -$LINES_REMOVED
Total changed: $LINES_TOTAL lines

$DIFF_STAT"
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. Configuration & Helper Function
# ─────────────────────────────────────────────────────────────────────────────

LMSTUDIO_URL="http://127.0.0.1:1234/v1/chat/completions"
MODEL_NAME="qwen/qwen3-vl-8b"               # ← change only if the name in LM Studio is different

if [ -z "$DIFF" ]; then
    echo "Error: DIFF is empty, nothing to analyze."
    exit 1
fi

# Truncate diff if too large for model context window
MAX_DIFF_CHARS=6000
DIFF_LEN=${#DIFF}

if [ "$DIFF_LEN" -gt "$MAX_DIFF_CHARS" ]; then
    echo "Warning: Diff is too large ($DIFF_LEN chars). Truncating to $MAX_DIFF_CHARS chars..."
    DIFF="${DIFF:0:$MAX_DIFF_CHARS}"
    DIFF="${DIFF}

... [DIFF TRUNCATED - showing first $MAX_DIFF_CHARS characters] ..."
fi

# Helper function to query LM Studio
query_llm() {
    local system_prompt="$1"
    local user_prompt="$2"
    local description="$3"
    
    echo "→ Querying LM Studio: $description ..."
    
    # Build JSON payload using jq to properly escape special characters
    local json_payload=$(jq -n \
      --arg model "$MODEL_NAME" \
      --arg system "$system_prompt" \
      --arg user "$user_prompt" \
      '{
        model: $model,
        messages: [
          {role: "system", content: $system},
          {role: "user", content: $user}
        ],
        temperature: 0.15,
        max_tokens: 2000,
        stream: false
      }')

    # Make request and capture both response and HTTP status code
    local http_response=$(curl -s -w "\n__HTTP_CODE__:%{http_code}" \
      -X POST "$LMSTUDIO_URL" \
      -H "Content-Type: application/json" \
      -d "$json_payload" 2>&1)

    local curl_exit=$?

    # Extract HTTP code and body
    local http_code=$(echo "$http_response" | grep -o '__HTTP_CODE__:[0-9]*' | cut -d: -f2)
    local ai_json=$(echo "$http_response" | sed '/__HTTP_CODE__:/d')

    if [[ $curl_exit -ne 0 ]]; then
        echo "Error: Could not reach LM Studio (curl exit code: $curl_exit)" >&2
        echo "(LLM query failed)"
    elif [[ "$http_code" != "200" ]]; then
        echo "Error: LM Studio returned HTTP $http_code" >&2
        echo "Response: $ai_json" >&2
        echo "(LLM query failed)"
    elif ! echo "$ai_json" | jq . >/dev/null 2>&1; then
        echo "Error: Invalid JSON response" >&2
        echo "(LLM query failed)"
    elif echo "$ai_json" | jq -e '.error' >/dev/null 2>&1; then
        echo "Error: $(echo "$ai_json" | jq -r '.error')" >&2
        echo "(LLM query failed)"
    else
        echo "$ai_json" | jq -r '.choices[0].message.content // "(no content)"'
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. AI Code/Changes Summary
# ─────────────────────────────────────────────────────────────────────────────

if [ "$FULL_MODE" = true ]; then
    CHANGES_SYSTEM="You are a senior software engineer who excels at analyzing and summarizing codebases."
    
    CHANGES_PROMPT=$(cat << 'EOF'
Analyze the following codebase structure and sample code.

Report in markdown using this structure:

## 🏗️ Project Overview

Brief description of what this project does based on the file structure and code.

## 🚀 Key Features

List the main features or capabilities of this codebase:

1. **[Feature]**: Brief description
2. **[Feature]**: Brief description
...

## 📁 Project Structure

- `folder/`: What this folder contains
...

## 💡 Summary

One paragraph summarizing the project purpose, architecture, and tech stack.

Codebase:
EOF
    )
else
    CHANGES_SYSTEM="You are a senior software engineer who excels at summarizing code changes clearly and concisely."

    CHANGES_PROMPT=$(cat << 'EOF'
Analyze the following git diff and provide a clear summary of the changes.

Report in markdown using this structure:

## 🚀 Key Changes

List the most important changes, new features, or improvements (prioritize by impact):

1. **[Feature/Fix/Improvement]**: Brief description
2. **[Feature/Fix/Improvement]**: Brief description
...

## 📁 Files Modified

- `filename.ext`: What changed in this file (one line)
...

## 💡 Summary

One paragraph summarizing the overall purpose and impact of these changes.

Focus on WHAT changed and WHY it matters. Be concise but comprehensive.

Diff:
EOF
    )
fi

CHANGES_PROMPT="${CHANGES_PROMPT}${DIFF}"

CHANGES_SUMMARY=$(query_llm "$CHANGES_SYSTEM" "$CHANGES_PROMPT" "Code Summary")

echo ""
echo "📋 Changes Summary:"
echo "──────────────────────────────────────"
echo "$CHANGES_SUMMARY"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 5. AI Security Audit
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_SYSTEM="You are a senior smart contract and application security auditor. Focus only on security-relevant findings."

if [ "$FULL_MODE" = true ]; then
    SECURITY_PROMPT=$(cat << 'EOF'
Analyze the following codebase for security issues.

Report in markdown using this structure:

## 🔴 High-Impact Security Findings

- **File**: `path/to/file.ext`  
  **Issue**: description of the security issue  
  **Risk**: OWASP category / CWE / blockchain-specific issue  
  **Severity**: Critical / High / Medium  
  **Recommendation**: short fix suggestion

(If no security issues found, write "No significant security issues detected.")

## 🟡 Potential Concerns

List any patterns or practices that could be improved for security.

## Summary

One-paragraph summary of the overall security posture of this codebase.

Codebase:
EOF
    )
else
    SECURITY_PROMPT=$(cat << 'EOF'
Analyze the following git diff for security issues.

Report in markdown using this structure:

## 🔴 High-Impact Security Findings

- **File**: `path/to/file.ext`  
  **Change**: one-line description  
  **Risk**: OWASP category / CWE / blockchain-specific issue  
  **Severity**: Critical / High / Medium  
  **Recommendation**: short fix suggestion

(If no security issues found, write "No significant security issues detected.")

## Summary

One-paragraph summary of the security implications of these changes.

Be concise. Ignore refactorings, comments, tests, formatting unless they introduce or fix security issues.

Diff:
EOF
    )
fi

SECURITY_PROMPT="${SECURITY_PROMPT}${DIFF}"

SECURITY_RESPONSE=$(query_llm "$SECURITY_SYSTEM" "$SECURITY_PROMPT" "Security Audit")

echo ""
echo "🔒 AI Security Audit:"
echo "──────────────────────────────────────"
echo "$SECURITY_RESPONSE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 6. npm audit – Check for vulnerable dependencies
# ─────────────────────────────────────────────────────────────────────────────

echo "📦 npm audit (dependency vulnerabilities) ..."
NPM_AUDIT_REPORT=""
if command -v npm >/dev/null 2>&1 && [ -f "package.json" ]; then
    NPM_AUDIT_REPORT=$(npm audit 2>&1) || true
    echo "$NPM_AUDIT_REPORT" | head -50
    if echo "$NPM_AUDIT_REPORT" | grep -q "found 0 vulnerabilities"; then
        echo "→ No npm vulnerabilities found"
    fi
else
    echo "→ npm not found or no package.json"
    NPM_AUDIT_REPORT="(npm audit skipped - no package.json or npm not installed)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 7. Semgrep CI – Full CI-style scan
# ─────────────────────────────────────────────────────────────────────────────

echo "🔍 Semgrep CI scan ..."
SEMGREP_CI_REPORT=""
if command -v semgrep >/dev/null 2>&1; then
    SEMGREP_CI_REPORT=$(semgrep ci --dry-run 2>&1) || true
    echo "$SEMGREP_CI_REPORT" | tail -30
else
    echo "→ Semgrep not installed (pip install semgrep)"
    SEMGREP_CI_REPORT="(semgrep ci skipped - semgrep not installed)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 8. Semgrep – OWASP Top 10 (full repo scan)
# ─────────────────────────────────────────────────────────────────────────────

echo "🛡️  Semgrep OWASP Top 10 (full repo) ..."
if command -v semgrep >/dev/null 2>&1; then
    semgrep --config=p/owasp-top-ten . \
        --output owasp-semgrep-report.txt 2>/dev/null || true

    if [ -s owasp-semgrep-report.txt ]; then
        cat owasp-semgrep-report.txt
    else
        echo "→ No OWASP Top 10 findings"
    fi
else
    echo "→ Semgrep not installed (pip install semgrep)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 9. Slither – Solidity audit
# ─────────────────────────────────────────────────────────────────────────────

if [ "$FULL_MODE" = true ]; then
    # Full mode: scan all .sol files
    SOL_FILES=$(find . -name "*.sol" ! -path "*/node_modules/*" 2>/dev/null || true)
else
    # Diff mode: scan only changed .sol files
    SOL_FILES=$(echo "$CHANGED_FILES" | grep -E '\.sol$' || true)
fi

if [ -n "$SOL_FILES" ] && command -v slither >/dev/null 2>&1; then
    echo "⚡ Running Slither on Solidity files ..."
    echo ""

    while IFS= read -r file; do
        [ -z "$file" ] && continue
        echo "→ Slither: $file"
        slither "$file" --checklist --json - 2>/dev/null > "slither-${file//\//_}.json" || true
        slither "$file" --print human-summary 2>/dev/null | head -n 20
        echo ""
    done <<< "$SOL_FILES"
else
    if command -v slither >/dev/null 2>&1; then
        echo "→ No .sol files to analyze"
    else
        echo "→ Slither not installed (pip install slither-analyzer)"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 10. Build final markdown report
# ─────────────────────────────────────────────────────────────────────────────

REPORT="pre-audit-report-$(date +%Y-%m-%d-%H%M%S).md"

{
    if [ "$FULL_MODE" = true ]; then
        echo "# Full Codebase Security Audit Report"
    else
        echo "# Pre-Pull Code Analysis Report"
    fi
    echo ""
    echo "## Date"
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    echo ""
    
    if [ "$FULL_MODE" = true ]; then
        echo "## Audit Target"
        echo "- Branch/Tag: ${AUDIT_TARGET:-HEAD}"
        echo "- Commit: $(git rev-parse --short HEAD)"
        echo "- Mode: **Full Audit** (entire codebase)"
    else
        echo "## Compared"
        echo "- From: $PREV_REF"
        echo "- To:   $(git rev-parse --short HEAD)"
        echo "- Mode: **Diff Audit** (changes only)"
    fi
    echo ""

    echo "## 📊 Lines of Code"
    echo ""
    echo '```text'
    echo "$LOC_REPORT"
    echo '```'
    echo ""

    if [ "$FULL_MODE" = true ]; then
        echo "## 🏗️ Code Summary"
    else
        echo "## 📋 Changes Summary"
    fi
    echo ""
    echo "$CHANGES_SUMMARY"
    echo ""

    echo "## 🔒 Security Audit"
    echo ""
    echo "$SECURITY_RESPONSE"
    echo ""

    echo "## 📦 npm audit"
    echo '```text'
    echo "$NPM_AUDIT_REPORT"
    echo '```'
    echo ""

    if [ -n "$SEMGREP_CI_REPORT" ]; then
        echo "## 🔍 Semgrep CI"
        echo '```text'
        echo "$SEMGREP_CI_REPORT"
        echo '```'
        echo ""
    fi

    if [ -s owasp-semgrep-report.txt ]; then
        echo "## 🛡️ Semgrep – OWASP Top 10 Findings"
        echo '```text'
        cat owasp-semgrep-report.txt
        echo '```'
        echo ""
    fi

    if ls slither-*.json >/dev/null 2>&1; then
        echo "## Slither Solidity Audits"
        for f in slither-*.json; do
            echo "### $(basename "${f%.json}")"
            echo '```text'
            slither "${f%.json}" --print human-summary 2>/dev/null || echo "(summary not available)"
            echo '```'
            echo ""
        done
    fi

} > "$REPORT"

echo ""
echo "Report saved → $REPORT"
echo "You can open it with:  code \"$REPORT\"   or cursor \"$REPORT\""
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup: Return to original branch if we checked out a different one
# ─────────────────────────────────────────────────────────────────────────────

if [ "$FULL_MODE" = true ] && [ -n "$ORIGINAL_BRANCH" ]; then
    echo "Returning to original branch: $ORIGINAL_BRANCH"
    git checkout "$ORIGINAL_BRANCH" --quiet 2>/dev/null || true
fi

# Optional: clean up temporary files (comment out if you want to keep them)
# rm -f owasp-semgrep-report.txt slither-*.json 2>/dev/null
