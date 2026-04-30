<p align="center">
  <img src="assets/logo.png" alt="UNPWNED" width="200" />
</p>

<h1 align="center">slopsquat-guard</h1>

<p align="center">
  Block AI-hallucinated and freshly-squatted packages before they reach <code>npm install</code> or <code>pip install</code>.
  <br/>
  A pre-tool-use hook for <strong>Claude Code</strong>, by <a href="https://unpwned.io">UNPWNED</a>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-22c55e" alt="MIT" />
  <img src="https://img.shields.io/badge/python-3.8+-blue" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/by-UNPWNED-22c55e" alt="UNPWNED" />
</p>

---

```
┌──────────────────────────────────────────────────────────────────┐
│ Slopsquatting guard - install BLOCKED                            │
│                                                                  │
│   [npm:react-codeshyft] package does not exist on npm            │
│   [npm:react-codeshyft] name is 2 character(s) off from 'react'  │
│                                                                  │
│ If this is a real package you trust, run the install yourself.   │
└──────────────────────────────────────────────────────────────────┘
```

## What is slopsquatting?

[Slopsquatting](https://en.wikipedia.org/wiki/Slopsquatting) is when an LLM (Cursor, Claude, Copilot, ChatGPT) confidently recommends a package name that does not exist. Attackers have started monitoring common AI hallucinations and registering those names on npm or PyPI with malware inside.

A 2025 USENIX Security study found that **19.7%** of LLM-suggested packages are hallucinated, and **43%** of those names are repeated across runs - perfect targets for attackers. Documented incidents in 2026 include `react-codeshift` (an LLM mashup of `jscodeshift` + `react-codemod`) propagating through 237 repositories before anyone noticed.

This hook intercepts package install commands proposed by Claude Code, runs six checks against the public registries, and blocks anything that smells like slopsquatting before the install runs.

## What it catches

| # | Layer | Action |
|---|---|---|
| 1 | **Existence** | Block if the package is not in the registry |
| 2 | **Age** | Block if created within the last 7 days |
| 3 | **Downloads** | Block if < 30 days old AND fewer than 1,000 weekly downloads |
| 4 | **Typosquat** | Warn if the name is within Levenshtein distance 2 of a popular package |
| 5 | **Single-maintainer-new** | Warn on a new package with one solo maintainer |
| 6 | **Deprecation** | Warn if the package version is marked deprecated or yanked |

The script intercepts `npm install`, `pnpm add`, `yarn add`, and `pip install` commands. Local paths, git URLs, and non-install commands are skipped.

## Install (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/razazu/slopsquat-guard/main/install.sh | bash
```

Or, to inspect first (recommended for a security tool):

```bash
git clone https://github.com/razazu/slopsquat-guard.git
cd slopsquat-guard
./install.sh
```

The installer:

1. Copies `slopsquat-guard.py` to `~/.claude/hooks/`
2. Registers the hook under `PreToolUse` in `~/.claude/settings.json`
3. Backs up your existing `settings.json` first

## Test it

```bash
# 1. Try to install a package that does not exist
echo '{"tool_name":"Bash","tool_input":{"command":"npm install fake-pkg-12345"}}' \
  | python3 ~/.claude/hooks/slopsquat-guard.py
# -> exit 2, BLOCKED

# 2. A real package
echo '{"tool_name":"Bash","tool_input":{"command":"npm install react"}}' \
  | python3 ~/.claude/hooks/slopsquat-guard.py
# -> exit 0, allowed
```

## Configuration

Tweak the constants at the top of `slopsquat-guard.py`:

```python
TIMEOUT_SECONDS       = 5      # registry call timeout
MIN_WEEKLY_DOWNLOADS  = 1000   # threshold for "obscure" packages
NEW_PACKAGE_DAYS      = 30     # cutoff for "new" packages
DANGER_DAYS           = 7      # cutoff for "high-risk new" (auto-block)
TYPOSQUAT_DISTANCE    = 2      # max edit distance to flag a typosquat
```

The popular-package allowlists for typosquat similarity (`POPULAR_NPM`, `POPULAR_PYPI`) live in the same file. Add your own internal package names there if you want them protected.

## Limitations

- npm maintainer account-age check requires a dedicated API that npm does not expose publicly. Currently we approximate with "single maintainer + new package" as a softer signal.
- Damerau-Levenshtein (transposition cost = 1) is not implemented; current implementation is plain Levenshtein with distance 2 to catch most adjacent-character swaps.
- Local installs (`npm install ./local-pkg`), git URLs, and tarballs are not analyzed. The hook silently skips them.

## License

MIT. See [LICENSE](LICENSE).

## About

Built and maintained by [Raz Azulay](https://github.com/razazu) at [UNPWNED](https://unpwned.io) - passive web security scanner for indie hackers, vibe coders, and developers shipping AI-built apps.

If this saved your `.env`, throw a star.
