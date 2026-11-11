# CatfishGuard privacy policy

_Last updated: 2026-11-11_

CatfishGuard is a browser extension with a single purpose: flagging possible
recruiter/job scams and phishing on LinkedIn by showing you which risk signals
appear on the page you are viewing.

## What it accesses
- **The visible text and links of LinkedIn pages you open** (on `*.linkedin.com`
  only): the open conversation, a profile, a job post, or an open message
  overlay. This is read **only to compute a risk score locally in your
  browser**. Text you are typing (message drafts and form fields) is skipped.

## What leaves your device
- **Nothing about you or the pages you view.** Page text, links, scores and
  results are never sent anywhere.
- The **only** network request the extension makes is a `GET` to the **public
  blocklist URL you configure** in the popup (restricted to
  `raw.githubusercontent.com` or `gist.githubusercontent.com`). No URL is set by
  default, so by default the extension makes **no network requests at all**.
  The request carries no page content, no cookies and no referrer. Like any web
  request it unavoidably exposes standard request metadata (such as your IP
  address) to that host (GitHub).

## Storage
- Your settings (on/off, blocklist URL) and the downloaded blocklist are kept in
  `chrome.storage.local`, **on your device**. They are not synced and never
  transmitted.
- The last score for a tab exists only in that page's memory and disappears when
  you close or reload it.

## What it does not do
- No analytics, telemetry, tracking, advertising, or profiling.
- No selling, sharing or transferring of any data to anyone.
- No list of named people. The blocklist contains scam *infrastructure* only
  (domains, URLs, off-platform handles, wallet addresses, throwaway email
  addresses).
- Its use of data is limited to the single purpose above.

## Permissions and why
| Permission | Why |
|---|---|
| `storage` | Save your settings and cache the blocklist on your device. |
| Host access to `raw.githubusercontent.com`, `gist.githubusercontent.com` | Download the public blocklist you chose. |
| Content script on `*.linkedin.com` | Read the page you are viewing so it can be scored locally. |

## Changes
If a future version adds any feature that sends data off your device (for
example an optional URL-reputation lookup), it will be **off by default and
opt-in**, and this policy will be updated **before** that version ships.

## Contact
Open an issue on the project's GitHub repository.
