<div align="center">

# 🎯 IDOR Tester

### AI-Assisted IDOR / BOLA Hunting for Burp Suite

Automatically learns object IDs from live traffic, swaps attacker ↔ victim,
fires the request, and tells you what's worth a closer look — live, as you
browse, with zero configuration required to get started.

[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white)](https://portswigger.net/burp)
[![Jython](https://img.shields.io/badge/Jython-2.7-306998?style=for-the-badge&logo=python&logoColor=white)](https://www.jython.org/)
[![Version](https://img.shields.io/badge/version-1.0-orange?style=for-the-badge)](#-changelog)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](#-license)

<img src="https://img.shields.io/badge/status-active-success?style=flat-square" />
<img src="https://img.shields.io/badge/AI-Groq%20%7C%20OpenRouter%20%7C%20Anthropic%20%7C%20Kimi-blueviolet?style=flat-square" />
<img src="https://img.shields.io/badge/works%20offline-regex--only%20mode-lightgrey?style=flat-square" />
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" />

</div>

---

<div align="center">
<i>⚠️ For authorized security testing only. See <a href="#%EF%B8%8F-legal--disclaimer">Legal &amp; Disclaimer</a>.</i>
</div>

<br>

<br>

## 📋 Table of Contents

- [Why this exists](#-why-this-exists)
- [Features](#-features)
- [How it works](#-how-it-works)
- [How detection is scored](#-how-detection-is-scored)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick start](#-quick-start)
- [Manual mode](#%EF%B8%8F-manual-mode)
- [AI Skills](#-ai-skills)
- [Configuration reference](#%EF%B8%8F-configuration-reference)
- [Testing modes explained](#-testing-modes-explained)
- [Privacy & data handling](#-privacy--data-handling)
- [Limitations](#%EF%B8%8F-limitations--things-to-know)
- [FAQ](#-faq)
- [Publishing / BApp Store](#-publishing--bapp-store)
- [Legal & Disclaimer](#%EF%B8%8F-legal--disclaimer)
- [Contributing](#-contributing)
- [Changelog](#-changelog)
- [License](#-license)

---

## 🤔 Why this exists

Manually testing IDOR means: find an ID in a request → note the field → swap
it for another user's ID → resend → compare the response → repeat, **for
every parameter, on every request, for the whole engagement.**

**IDOR Tester** turns that into a background process. Give it an attacker ID
and a victim ID (or tag browser tabs with [Pwnfox](https://github.com/lorenzog/pwnfox)),
browse the target normally, and every request that passes through Burp Proxy
is automatically checked, re-sent with the ID swapped, and scored for you.

```
  You browse normally
         │
         ▼
  Extension learns candidate ID fields    (URL, body, JSON, XML, path params)
         │
         ▼
  Swaps attacker's ID → victim's ID       (respects scope, dedupes, skips OPTIONS)
         │
         ▼
  Compares response to a clean baseline   (status code + sequence-diff similarity)
         │
         ▼
  CONFIRMED / HIGH / MEDIUM  ──────────▶  Burp Scanner issue (matching confidence)
```

---

## ✨ Features

| | |
|---|---|
| 🔴 **Live passive testing** | Every in-scope request through Burp Proxy is auto-tested — browse the app, get results. Repeater/Intruder/Scanner traffic is deliberately ignored. |
| 🧠 **Smart ID learning** | Structured + regex extraction from the URL path, query string, form body, JSON *(nested objects/arrays, numeric values)*, XML *(tags **and** attributes)*, and matrix/path parameters (`;id=555;status=paid`). |
| 🎯 **Field-name aware** | A value like `"4337"` is only accepted as a candidate ID when the field name actually looks like one (`*_id`, `*_pk`, `*_key`, ...) — cutting down on noise from generic short numbers. |
| 🤖 **AI-assisted extraction** | Let an LLM identify candidate ID fields in a request instead of relying on regex alone. |
| 🧩 **AI Skills** | Reusable, prompt-driven test strategies (boundary values, off-by-one, UUID mutations, ...) that generate *and run* a batch of targeted tests against any loaded request. |
| 🦊 **Pwnfox integration** | Tag browser tabs by role (attacker / victim) and requests are auto-classified and tested in the correct direction. |
| 🎛️ **Multiple testing modes** | Pwnfox + selected keys, manual attacker/victim IDs, per-key ID overrides, and pool-based swapping between any two previously observed IDs of the same key. |
| 📊 **Confidence-scored results** | `CONFIRMED` / `HIGH` / `MEDIUM` labels backed by sequence-based response diffing — not naive character-by-character comparison, which breaks the moment two IDs have different digit lengths. |
| 🚦 **Honest Scanner issues** | Severity/confidence registered in Burp Scanner match the actual confidence level — a `MEDIUM` heuristic guess is never reported as `Certain`. |
| 🖍️ **Highlighted results table** | Vulnerable rows are colour-highlighted; click any row for a side-by-side original vs. modified request/response. |
| 🔒 **Scope-respecting by default** | Both extraction *and* testing honour Burp's target scope, so background noise (ads, trackers, unrelated tabs) never pollutes your ID pool. |

---

## ⚙️ How it works

1. **Extraction** — as requests pass through Proxy (or when you manually load one), the extension walks the URL, body, and any JSON/XML structure looking for fields that are (a) not in a generic-name skip list (`page`, `limit`, `token`, `sort`, ...) and (b) shaped like an identifier — a run of digits, a UUID, a Mongo ObjectId, a hex hash, or a short number whose field name explicitly says it's an id.
2. **Swap** — once an attacker id is seen in a request, the extension builds a modified copy with that id replaced by the configured victim id (or vice-versa, depending on the active mode — see [Testing modes explained](#-testing-modes-explained)).
3. **Baseline + test** — both the original and the modified request are sent, and the two responses are compared: same status code? similar body (via `difflib`-based sequence matching, which tolerates length differences instead of breaking on them)? does the response echo back the injected id?
4. **Score** — the result is labelled `CONFIRMED`, `HIGH`, `MEDIUM`, or left unflagged, and (for hits) a Burp Scanner issue is raised with the original/modified request-response pair attached as evidence.

---

## 🔍 How detection is scored

<table>
<tr><td>🟥</td><td><b>CONFIRMED</b></td><td>The swapped-in value was found echoed back in the response body.</td></tr>
<tr><td>🟧</td><td><b>HIGH</b></td><td>Same status code as baseline + high body similarity. Worth a manual look.</td></tr>
<tr><td>🟨</td><td><b>MEDIUM</b></td><td>Partial similarity. Lower confidence, still worth a manual look.</td></tr>
<tr><td>⬜</td><td><i>not flagged</i></td><td>Deny-keywords, an HTTP error status, or an error-shaped JSON body were detected — treated as access denied.</td></tr>
</table>

> Burp Scanner issues inherit this same confidence level — a `MEDIUM`
> heuristic hit is registered as `Tentative`, never as `Certain`. **All
> findings are leads for manual verification, not proof of a vulnerability.**

---

## 🧰 Requirements

- **[Burp Suite](https://portswigger.net/burp)** (Community or Professional)
- **Jython** configured under `Extender ▸ Options ▸ Python Environment`
  (point it at a `jython-standalone-2.7.x.jar`, [download here](https://www.jython.org/download))
- *(optional)* An API key from one of the supported AI providers — only
  needed for **AI Extract** and **AI Skills**:

  <div align="left">
  <a href="https://console.groq.com/"><img src="https://img.shields.io/badge/Groq-F55036?style=flat-square&logo=groq&logoColor=white"></a>
  <a href="https://openrouter.ai/"><img src="https://img.shields.io/badge/OpenRouter-000000?style=flat-square"></a>
  <a href="https://console.anthropic.com/"><img src="https://img.shields.io/badge/Anthropic-191919?style=flat-square"></a>
  <a href="https://platform.moonshot.cn/"><img src="https://img.shields.io/badge/Kimi%20(Moonshot)-6236FF?style=flat-square"></a>
  </div>

  Everything else — regex/structured extraction, manual testing, passive
  listening, Burp Scanner integration — works with **zero API keys**.

---

## 📦 Installation

<table>
<tr><td width="40" align="center">1️⃣</td><td>Download <code>idor_tester.py</code> from this repository (or clone it).</td></tr>
<tr><td align="center">2️⃣</td><td>In Burp: <b>Extender ▸ Options</b> → under <i>Python Environment</i>, select your <code>jython-standalone-2.7.x.jar</code>.</td></tr>
<tr><td align="center">3️⃣</td><td><b>Extender ▸ Extensions ▸ Add</b> → Extension type: <code>Python</code> → Extension file: <code>idor_tester.py</code>.</td></tr>
<tr><td align="center">4️⃣</td><td>A new <b>"IDOR Tester"</b> tab appears in Burp's top-level tab bar. 🎉</td></tr>
</table>

---

## 🚀 Quick start

1. **Set your identity pair** — enter the attacker account's ID and the
   victim ID you should *not* be able to reach.
2. **Turn on `Auto-Extract IDs`** — starts passively learning `key=value`
   ID pairs from traffic.
3. **Turn on `Scope-Only`** *(on by default)* — restricts extraction *and*
   testing to your defined Burp target scope, not every ad/tracker/unrelated
   tab your browser happens to touch.
4. **Browse the app** as the attacker account. Matching requests are
   auto-tested as they pass through Proxy.
5. **Turn on `Auto-Test`** to actually fire the swapped requests —
   `Auto-Extract` alone only builds the ID pool, it never sends anything.
6. **Check the results table.** Vulnerable rows are highlighted — click one
   for the full before/after request & response, or check the linked Burp
   Scanner issue.

---

## 🖱️ Manual mode

Right-click any request anywhere in Burp → **`Send to IDOR Tester`**, then:

| Button | Does |
|---|---|
| `Analyze Loaded Request` | Structured + regex-based field discovery |
| `AI Analyze` | Ask your configured AI provider to find candidate ID fields |
| ☑️ select fields → `Test Checked Fields` | Run the swap tests on exactly the fields you pick |

---

## 🧩 AI Skills

Skills are reusable prompts that ask an LLM to generate a batch of targeted
tests for a loaded request — then the extension executes and scores every
one of them automatically.

- **`Skill Manager`** — create / edit / enable / disable skills
- **`Run AI Skills`** — run every enabled skill against the currently loaded request

<details>
<summary><b>📄 Example skill — "IDOR Boundary Testing" (click to expand)</b></summary>

<br>

**Prompt:**

> You are an expert API security tester. Given the HTTP request below,
> generate a JSON array of 5 to 8 IDOR boundary tests. For each test,
> specify: `test_name`, `field`, `location` (URL/Body/Header),
> `original_value`, `new_value`, `reason`. Test ideas: replace numeric IDs
> with `0`, `-1`, `999999999`, an off-by-one value, another random ID of the
> same length, or a mutated UUID segment. Only return a valid JSON array. No
> markdown. No explanations outside JSON.

Each generated test is automatically applied to the request, sent, compared
against the baseline, and scored exactly like a normal manual/auto test.

</details>

---

## ⚙️ Configuration reference

| Control | Does |
|---|---|
| `Auto-Extract IDs` | Passively learn ID fields from traffic |
| `AI Extract` | Use the configured AI provider for extraction instead of regex |
| `Auto-Test` | Automatically fire IDOR swap tests on matching in-scope requests |
| `Scope-Only` | Restrict extraction *and* testing to Burp's defined target scope |
| `HTML Skip Issue` | Don't auto-register a Scanner issue when the response is a generic HTML page (cuts noise) |
| `View ID Pool` | See every learned ID, grouped by key |
| `Select Keys` | Choose which learned keys are actually used for passive auto-testing |
| `Clear Test Cache` | Forget which URLs were already tested, so they're retested on next sight |
| `AI Verify` | After each test, ask the AI to double-check whether a finding looks like a real vulnerability |

---

## 🎛️ Testing modes explained

| Mode | When it applies | Direction |
|---|---|---|
| **Pwnfox (red tab)** | Browser tab tagged as attacker | attacker id → victim id |
| **Pwnfox (blue tab)** | Browser tab tagged as victim | victim id → attacker id |
| **Manual IDs (default)** | No Pwnfox tag, IDs set manually | attacker id → victim id **only** |
| **Per-key override** | Specific key mapped to its own attacker/victim pair | attacker id → victim id |
| **Pool swap** | No labelled pair available for that key | swaps between any two previously observed ids for that key |

> In the default (no-Pwnfox) mode, only the attacker's own id is ever
> replaced with the victim's — never the reverse. That direction proves
> nothing (it's just the attacker accessing their own resource) and used to
> create noisy, meaningless test results in earlier versions.

---

## 🔐 Privacy & data handling

- AI features (**AI Extract**, **AI Skills**, **AI Verify**) send the loaded
  request to your configured third-party provider (Groq / OpenRouter /
  Anthropic / Kimi). `Cookie` and `Authorization` headers are stripped
  before sending — but the body itself is not otherwise redacted, so review
  your provider's data-handling policy before pointing this at sensitive
  targets.
- The API key field is masked (`•••••`) with an explicit `Show`/`Hide`
  toggle, and the key is **never written to disk** — it's held in memory
  for the session only.
- With AI features turned off, **nothing ever leaves your machine** except
  the requests you already intended to send to the target.

---

## ⚠️ Limitations / things to know

- 🎯 This is a **heuristic** tool. `HIGH`/`MEDIUM` findings are leads, not
  proof — always verify manually before reporting.
- 🐢 Similarity comparison is capped at a few KB per response for
  performance; extremely large responses are compared on their prefix only.
- 🎯 Passive testing only ever looks at traffic that passed through
  **Burp Proxy** (`toolFlag == TOOL_PROXY`) — Repeater/Intruder/Scanner
  traffic is ignored by design.
- 🧵 Every auto-test spawns a background thread; on very high-traffic
  targets with `Auto-Test` on, expect a burst of concurrent requests.

---

## ❓ FAQ

<details>
<summary><b>It's picking up IDs even though I'm not actively testing the target — why?</b></summary>
<br>
Make sure <code>Scope-Only</code> is turned on and your target is added to
Burp's Target scope. With it off, any request that passes through Burp's
proxy port — including background browser traffic to unrelated sites — is
scanned.
</details>

<details>
<summary><b>Do I need an API key to use this?</b></summary>
<br>
No. Regex/structured extraction, manual testing, and passive auto-testing
all work with zero API keys. AI keys only unlock <b>AI Extract</b>,
<b>AI Skills</b>, and <b>AI Verify</b>.
</details>

<details>
<summary><b>Why didn't it catch a short numeric ID like <code>"4337"</code>?</b></summary>
<br>
Short numeric values are only accepted as candidate IDs when the field name
itself looks like an identifier (ends in <code>_id</code>, <code>_pk</code>,
<code>_key</code>, etc.). A bare number with no such context (e.g. a page
count) needs to be at least 5 digits to avoid false positives.
</details>

<details>
<summary><b>Can I use this without Pwnfox?</b></summary>
<br>
Yes — Pwnfox is entirely optional. Just fill in the Attacker ID / Victim ID
fields manually and everything works the same way.
</details>

---


## ⚖️ Legal & Disclaimer

This tool is intended for **authorized security testing and research only**.
Use it exclusively against systems you own or have explicit, written
permission to test. You are solely responsible for complying with all
applicable laws and your engagement's rules of engagement. The authors
accept no liability for misuse or damage caused by this tool.

---

## 🤝 Contributing

Issues and PRs are welcome! When reporting a bug, please include:

- A minimal request/response that reproduces it
- What you expected vs. what actually happened
- Whether `Auto-Extract`, `Auto-Test`, and `Scope-Only` were on or off

---

## 📝 Changelog

**v1.0** — First public release.
- Live passive IDOR testing with scope-aware extraction
- Structured + regex ID learning (URL, body, JSON, XML, matrix params)
- AI-assisted extraction and prompt-driven AI Skills
- Sequence-diff based response similarity scoring
- Confidence-matched Burp Scanner issue registration
- Pwnfox integration and multiple testing modes

---

## 📄 License

Released under the [MIT License](LICENSE).

<br>

<div align="center">
<sub>Built for pentesters, by pentesters. Happy hunting. 🕵️</sub>
</div>
