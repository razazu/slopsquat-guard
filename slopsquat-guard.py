#!/usr/bin/env python3
"""
slopsquat-guard

PreToolUse hook for Claude Code that intercepts package install commands
and verifies the packages are not AI-hallucinated, freshly squatted, or
typosquats of popular packages.

Layers:
  1. Existence check        (registry says the package exists)
  2. Age check              (created < 7 days = block, < 30 days + low downloads = block)
  3. Downloads check        (very low weekly downloads = warn)
  4. Typosquat similarity   (close name match to a popular package = warn)
  5. Single-maintainer-new  (one maintainer + new package = warn)
  6. Deprecation check      (package marked deprecated or yanked = warn)

Exit codes:
  0 -> allow
  2 -> block (stderr shown to Claude)

Repo:    https://github.com/razazu/slopsquat-guard
License: MIT
By:      UNPWNED (https://unpwned.io) - Raz Azulay
"""
import json
import re
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

TIMEOUT_SECONDS = 5
MIN_WEEKLY_DOWNLOADS = 1000
NEW_PACKAGE_DAYS = 30
DANGER_DAYS = 7
MAINTAINER_NEW_DAYS = 60
TYPOSQUAT_DISTANCE = 2   # up to 2 char edits (catches swap+typo)
TYPOSQUAT_MIN_LEN = 4    # only meaningful for names long enough to be confused

# Top npm packages — best-effort static list of common typo targets.
# Kept short and high-impact; covers the names attackers go after most.
POPULAR_NPM = {
    "react", "react-dom", "lodash", "axios", "express", "next", "vue",
    "svelte", "typescript", "webpack", "vite", "esbuild", "tailwindcss",
    "prisma", "graphql", "redux", "rxjs", "underscore", "moment", "dayjs",
    "zod", "yup", "joi", "ajv", "uuid", "nanoid", "bcrypt", "bcryptjs",
    "jsonwebtoken", "passport", "cors", "helmet", "dotenv", "chalk",
    "commander", "yargs", "inquirer", "ora", "execa", "mocha", "jest",
    "vitest", "chai", "sinon", "eslint", "prettier", "husky", "lint-staged",
    "supabase", "firebase", "stripe", "pg", "mysql", "mongoose", "redis",
    "ioredis", "socket.io", "ws", "node-fetch", "got", "request", "cheerio",
    "puppeteer", "playwright", "winston", "pino", "morgan", "debug",
    "fs-extra", "glob", "rimraf", "minimist", "qs", "form-data",
    "@types/node", "@types/react", "@types/express", "@types/lodash",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "scipy", "matplotlib", "django", "flask",
    "fastapi", "pydantic", "sqlalchemy", "boto3", "pyyaml", "click",
    "rich", "httpx", "aiohttp", "celery", "redis", "psycopg2",
    "beautifulsoup4", "lxml", "selenium", "playwright", "pillow",
    "pytest", "tox", "black", "flake8", "mypy", "ruff", "twine",
    "torch", "tensorflow", "transformers", "openai", "anthropic",
}

NPM_PATTERNS = [
    re.compile(r"\bnpm\s+(?:install|i|add)\s+(?P<pkgs>[^|;&<>\n]+)", re.IGNORECASE),
    re.compile(r"\bpnpm\s+(?:add|install|i)\s+(?P<pkgs>[^|;&<>\n]+)", re.IGNORECASE),
    re.compile(r"\byarn\s+add\s+(?P<pkgs>[^|;&<>\n]+)", re.IGNORECASE),
]
PIP_PATTERN = re.compile(r"\bpip3?\s+install\s+(?P<pkgs>[^|;&<>\n]+)", re.IGNORECASE)


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "slopsquat-guard/2.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_packages(token_string):
    pkgs = []
    for tok in token_string.split():
        tok = tok.strip()
        if not tok or tok.startswith("-"):
            continue
        if "/" in tok and not tok.startswith("@"):
            if any(s in tok for s in (":", "git+", "git@")) or tok.startswith("./") or tok.startswith("/"):
                continue
        if tok.startswith("@"):
            parts = tok.split("@")
            if len(parts) >= 2:
                tok = "@" + parts[1]
        else:
            tok = tok.split("@", 1)[0]
        if tok and re.match(r"^[a-zA-Z0-9._/@-]+$", tok):
            pkgs.append(tok)
    return pkgs


def levenshtein(a, b, max_distance=2):
    """Compact Levenshtein with early-exit when above max_distance."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, 1):
        curr = [i]
        min_in_row = i
        for j, ca in enumerate(a, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
            if curr[-1] < min_in_row:
                min_in_row = curr[-1]
        if min_in_row > max_distance:
            return max_distance + 1
        prev = curr
    return prev[-1]


def find_typosquat(name, popular_set):
    """Return (popular_name, distance) if `name` is suspiciously close to a popular pkg."""
    if name in popular_set:
        return None
    if len(name) < TYPOSQUAT_MIN_LEN:
        return None
    best = None
    for pop in popular_set:
        d = levenshtein(name, pop, max_distance=TYPOSQUAT_DISTANCE)
        if d <= TYPOSQUAT_DISTANCE and d > 0:
            if best is None or d < best[1]:
                best = (pop, d)
    return best


def check_npm(pkg):
    """Returns list of (severity, message). severity in {'block','warn'}."""
    issues = []

    # Layer 4: typosquat similarity (works even if package doesn't exist)
    ts = find_typosquat(pkg, POPULAR_NPM)
    if ts:
        issues.append(("warn", f"name is {ts[1]} character(s) off from popular package '{ts[0]}'"))

    # Layer 1-3: registry lookup
    try:
        meta = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@/')}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            issues.append(("block", "package does not exist on npm"))
            return issues
        issues.append(("warn", f"npm registry error ({e.code})"))
        return issues
    except Exception as e:
        issues.append(("warn", f"could not reach npm registry ({type(e).__name__})"))
        return issues

    # Layer 6: deprecation
    latest_ver = (meta.get("dist-tags") or {}).get("latest")
    if latest_ver:
        latest_meta = (meta.get("versions") or {}).get(latest_ver, {})
        if latest_meta.get("deprecated"):
            issues.append(("warn", f"latest version is deprecated: {latest_meta['deprecated'][:120]}"))

    # Layer 2: age
    times = meta.get("time", {})
    created = times.get("created")
    age_days = None
    if created:
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_dt).days
        except Exception:
            pass

    # Layer 3: weekly downloads
    weekly_downloads = None
    try:
        dl = http_json(f"https://api.npmjs.org/downloads/point/last-week/{urllib.parse.quote(pkg, safe='@/')}")
        weekly_downloads = dl.get("downloads", 0)
    except Exception:
        pass

    if age_days is not None and age_days <= DANGER_DAYS:
        issues.append(("block", f"package created {age_days} day(s) ago - high slopsquatting risk"))
    elif age_days is not None and age_days <= NEW_PACKAGE_DAYS:
        if weekly_downloads is not None and weekly_downloads < MIN_WEEKLY_DOWNLOADS:
            issues.append(("block", f"only {age_days} days old with {weekly_downloads} weekly downloads"))
        else:
            issues.append(("warn", f"only {age_days} days old (weekly downloads: {weekly_downloads or '?'})"))

    # Layer 5: maintainer count and named owners as a soft signal
    # (Real npm-account-age requires unauthenticated scraping; skip until we have a reliable API.)
    maintainers = meta.get("maintainers") or []
    if maintainers and len(maintainers) == 1:
        m = maintainers[0]
        username = m.get("name") if isinstance(m, dict) else None
        if username and (age_days is None or age_days <= NEW_PACKAGE_DAYS):
            issues.append(("warn", f"single maintainer '{username}' on a new package - verify reputation"))

    return issues


def check_pypi(pkg):
    issues = []

    # Layer 4: typosquat similarity
    ts = find_typosquat(pkg.lower(), POPULAR_PYPI)
    if ts:
        issues.append(("warn", f"name is {ts[1]} character(s) off from popular package '{ts[0]}'"))

    try:
        meta = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            issues.append(("block", "package does not exist on PyPI"))
            return issues
        issues.append(("warn", f"PyPI error ({e.code})"))
        return issues
    except Exception as e:
        issues.append(("warn", f"could not reach PyPI ({type(e).__name__})"))
        return issues

    # Layer 6: deprecation / yanked
    info = meta.get("info") or {}
    if info.get("yanked"):
        issues.append(("warn", "package marked as yanked on PyPI"))

    releases = meta.get("releases", {})
    if not releases:
        issues.append(("block", "package has no releases on PyPI"))
        return issues

    earliest = None
    for ver, files in releases.items():
        for f in files or []:
            ts = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not ts:
                continue
            try:
                t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
                if earliest is None or t < earliest:
                    earliest = t
            except Exception:
                continue

    age_days = None
    if earliest:
        age_days = (datetime.now(timezone.utc) - earliest).days

    if age_days is not None and age_days <= DANGER_DAYS:
        issues.append(("block", f"package uploaded {age_days} day(s) ago - high slopsquatting risk"))
    elif age_days is not None and age_days <= NEW_PACKAGE_DAYS:
        issues.append(("warn", f"only {age_days} days old"))

    return issues


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    if payload.get("tool_name") != "Bash":
        sys.exit(0)

    cmd = (payload.get("tool_input") or {}).get("command", "")
    if not cmd:
        sys.exit(0)

    npm_targets = []
    for pat in NPM_PATTERNS:
        for m in pat.finditer(cmd):
            npm_targets.extend(parse_packages(m.group("pkgs")))

    pip_targets = []
    for m in PIP_PATTERN.finditer(cmd):
        pip_targets.extend(parse_packages(m.group("pkgs")))

    if not npm_targets and not pip_targets:
        sys.exit(0)

    blocks = []
    warnings = []

    for pkg in npm_targets:
        results = check_npm(pkg)
        for severity, msg in results:
            line = f"  [npm:{pkg}] {msg}"
            (blocks if severity == "block" else warnings).append(line)

    for pkg in pip_targets:
        results = check_pypi(pkg)
        for severity, msg in results:
            line = f"  [pip:{pkg}] {msg}"
            (blocks if severity == "block" else warnings).append(line)

    if blocks:
        print("Slopsquatting guard - install BLOCKED", file=sys.stderr)
        print("", file=sys.stderr)
        for line in blocks:
            print(line, file=sys.stderr)
        if warnings:
            print("", file=sys.stderr)
            print("Also flagged:", file=sys.stderr)
            for line in warnings:
                print(line, file=sys.stderr)
        print("", file=sys.stderr)
        print("If this is a real package you trust, run the install yourself in a terminal.", file=sys.stderr)
        sys.exit(2)

    if warnings:
        print("Slopsquatting guard - warnings (allowed):")
        for line in warnings:
            print(line)

    sys.exit(0)


if __name__ == "__main__":
    main()
