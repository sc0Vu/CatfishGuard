# CatfishGuard privacy policy

_Last updated: 2026-11-11 (local custom rules)_

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
  `raw.githubusercontent.com` or `gist.githubusercontent.com`; these serve
  public files to anyone, so no extra permission is needed). No URL is set by
  default, so by default the extension makes **no network requests at all**.
  The request carries no page content, no cookies and no referrer. Like any web
  request it unavoidably exposes standard request metadata (such as your IP
  address) to that host (GitHub).
- **Reverse image search, only when you click it.** The panel can offer
  "Google Lens" and "TinEye" links for the other person's LinkedIn profile
  photo. Nothing is sent unless you click one. If you do, your browser opens
  that service in a new tab with **only the photo's public LinkedIn image
  address**, without a referrer, so the service does not learn which page you
  were on. That service's own privacy policy then applies. Only images hosted
  by LinkedIn (`licdn.com`) are ever offered. You can hide these links in the
  popup ("Profile photos").

## Storage
- Your settings (on/off, blocklist URL, photo-search links on/off) and the downloaded blocklist are kept in
  `chrome.storage.local`, **on your device**. They are not synced and never
  transmitted.
- When you dismiss a conversation's banner, a **short hash of that
  conversation's internal LinkedIn id** (not the id itself) plus the risk level and time is saved on your device (at
  most 500, oldest dropped), so the banner stays dismissed. No names, message
  text or profile data are stored. It is never synced or transmitted.
- If you customise the rules (weights, your own phrases, brands, trusted
  domains), they are saved in `chrome.storage.local` on your device and are
  never synced or transmitted. **Export** writes them to a file on your
  computer only when you click it.
- Scores exist only in the page's memory and disappear when you close or reload
  it. That includes the corner panel's list of conversations with risk signals
  in the current tab: it shows the display name LinkedIn already shows you, so
  you can find the conversation again, but it is never saved, synced or
  transmitted. To keep a conversation's list dot after you leave it, only a
  short hash of the sender's display name is held, also in memory only.

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
| `storage` | Save your settings, custom rules, dismissed-banner hashes and the blocklist cache on your device. |
| Content script on `*.linkedin.com` | Read the page you are viewing so it can be scored locally. |

## Changes
If a future version adds any feature that sends data off your device (for
example an optional URL-reputation lookup), it will be **off by default and
opt-in**, and this policy will be updated **before** that version ships.

## Contact
Open an issue on the project's GitHub repository.
