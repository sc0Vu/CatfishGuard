# CatfishGuard

A Manifest V3 Chrome extension that flags **recruiter/job-scam and phishing risk
signals on LinkedIn**, and always shows **why**.

It reads the conversation, profile or job post in view, scores it **locally**, and
shows what it found, scaled to the risk level:

- **a thin banner above the open conversation** (caution/high only). It can be
  dismissed per conversation and comes back only if things escalate;
- **dots in the conversation list** for triage;
- **a corner badge** that's always available. Click it, or the banner's
  "Why?", to see every signal that fired.

The result is a prompt to look closer, never a verdict about a person.

## Install (unpacked)
1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this folder.
3. Open LinkedIn (reload tabs that were already open).

No build step, no dependencies.

## What it looks at
| Page | Scanned |
|---|---|
| `/messaging/…` | the open thread |
| `/in/…` | the profile |
| `/jobs/…` | the job details |
| anywhere | open (non-minimised) message overlays |

Each open conversation is scored on its own. In conversations, **only messages
from the other person are scored** when LinkedIn marks senders
(`msg-s-event-listitem--other`). Otherwise it falls back to the whole thread
and the panel says so. The feed is deliberately not scored, since it would just
be noise. Your own drafts, form fields and `You: …` list previews are never
read. LinkedIn selectors live in `SEL` at the top of `src/content.js`.

## How scoring works
Two kinds of signal, matched to how easy each is to evade:

**1. Keywords (bundled in `src/analyzer.js` → `RULES`).** Each distinct term
adds its category's weight once, and each category is capped.

| Category | Per term | Cap | Notes |
|---|---|---|---|
| credentials | 40 | 60 | seed phrase, connect wallet, passport copy, bank login… **alone → high** |
| offplatform | 15 | 30 | Telegram / WhatsApp / `t.me/` pushes |
| money | 15 | 40 | fees, deposits, USDT, gift cards, task payments |
| crypto | 5 | 20 | web3/defi bait; **3+ distinct terms → +20** |
| toogood | 10 | 30 | no interview, guaranteed income, pay over $150/h, $800/day, $4k/week or $20k/month |
| pressure | 8 | 24 | urgency, secrecy |
| counter | −10 | −20 | ATS hosts, "interview process"… only applied when nothing near-certain fired |

Bands: **0–29 low · 30–59 caution · 60–100 high.**

Text is NFKC-normalised and stripped of zero-width characters before
matching. Terms are matched as literal strings with word boundaries.

Keywords are the *most evadable* signal (a public list is a cheat sheet), so
they are compiled into each release and never fetched at runtime.

**2. Infrastructure blocklist (remote, optional).** Domains, URLs, handles,
wallet addresses and throwaway emails. A hit adds +60 and on its own puts the
score in the high band. LinkedIn's `/redir/redirect?url=` wrapper is unwrapped
first, and subdomains match their parent domain.

## Blocklist
Set a URL in the popup (GitHub raw or gist only). It is fetched by the service
worker, validated, cached for 6 h in `chrome.storage.local`, and merged over the
bundled seed (`data/blocklist.seed.json`). On failure, the last good list stays in
use. Two schemas are accepted:

**This project's schema**
```json
{
  "schema": "catfishguard-blocklist",
  "version": 1,
  "domains": ["careers-acme.xyz"],
  "urls":    ["evil.example/apply"],
  "handles": ["t.me/hr_jane_web3", "@hr_desk", "+15550100199"],
  "wallets": ["0xabc…", "bc1q…", "T…"],
  "emails":  ["hr@throwaway.io", "@mailinator.com"]
}
```
Entries may also be `{"value": "…", "note": "…"}`. **Infrastructure only:
never names of people.**

**MetaMask [`eth-phishing-detect`](https://github.com/MetaMask/eth-phishing-detect)**
(`blacklist` / `fuzzylist` / `whitelist` / `tolerance`). The popup has a
one-click preset for it. `fuzzylist` entries flag lookalike domains within
`tolerance` edits (e.g. `metamusk.io`).

Lists are treated as hostile. The checks are: an https GitHub host only,
no redirects, a 16 MB cap and a 20 s timeout, JSON must parse, the schema must
be recognised, every entry is validated, list sizes are capped
(300k per list, 500k total, 500 fuzzy), and `tolerance` is clamped to 0–3.
Nothing in a list is ever compiled as a regex.

## Tuning
Edit `RULES` in `src/analyzer.js`, then add a test case in
`test/analyzer.test.js` whose expected score you work out **by hand** from the
weights.

## Tests
```sh
npm test            # unit: analyzer (vm sandbox with only self + URL) + service worker
npm run test:e2e    # real Chrome: loads the extension, fake LinkedIn + GitHub over local HTTPS
```
The e2e run needs Chrome and `openssl`. It loads the unpacked extension through
CDP `Extensions.loadUnpacked` and asserts that the only outbound request is the
blocklist GET, with no cookies, referrer or body. Set
`CFG_METAMASK_JSON=path/to/config.json` to also run the unit test against the
real MetaMask list. Set `CFG_SHOTS=dir` to save e2e screenshots.

## Honest limits
- It's a heuristic. False positives and false negatives both happen. The
  reasons are the useful part, not the number.
- Keyword lists are evadable by construction. The blocklist and (planned)
  domain-impersonation checks are the harder signals to dodge.
- LinkedIn changes its DOM. The selectors were built against fixtures that mimic
  LinkedIn's class names and need checking on the live site. Fallbacks: `<main>`
  for the page, and the whole thread when senders can't be told apart.
- List dots for unopened conversations score only the short preview, so they are
  a triage hint, not a full check.
- The real control is behavioural: verify the recruiter through the company's
  own site, and never enter keys, codes, logins or ID documents on a page reached
  from a message.

## Privacy
See [PRIVACY.md](PRIVACY.md). In short: everything runs locally, and the only
network request is the optional blocklist GET.
