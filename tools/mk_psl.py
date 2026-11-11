#!/usr/bin/env python3
"""Vendor the Public Suffix List into src/psl.js as pure data.

The PSL is bundled (never fetched at runtime) so `google.com.evil.ru`
resolves to its registrable domain `evil.ru`, and `evil.vercel.app` stays its
own site rather than collapsing to `vercel.app`.

Output is a single JS string literal (newline-separated rules), punycoded and
validated here, so the shipped file contains data only.

Usage:
  python3 tools/mk_psl.py                 # download from publicsuffix.org
  python3 tools/mk_psl.py path/to/list.dat
"""
import datetime
import json
import os
import re
import sys
import urllib.request

URL = 'https://publicsuffix.org/list/public_suffix_list.dat'
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'psl.js')
RULE_RE = re.compile(r'^(?:!|\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*$')


def to_ascii(label):
    if label == '*' or all(ord(c) < 128 for c in label):
        return label
    return 'xn--' + label.encode('punycode').decode('ascii')


def convert(line):
    prefix = ''
    if line.startswith('!'):
        prefix, line = '!', line[1:]
    labels = line.lower().split('.')
    if '*' in labels[1:]:
        return None  # only leading wildcards are meaningful to our matcher
    rule = prefix + '.'.join(to_ascii(lb) for lb in labels)
    return rule if RULE_RE.match(rule) else None


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding='utf-8') as f:
            text = f.read()
    else:
        req = urllib.request.Request(URL, headers={'User-Agent': 'psl-vendor-script'})
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode('utf-8')

    rules, skipped = [], 0
    for raw in text.splitlines():
        line = raw.strip().split()[0] if raw.strip() else ''
        if not line or line.startswith('//'):
            continue
        r = convert(line)
        if r:
            rules.append(r)
        else:
            skipped += 1
    rules = sorted(set(rules))
    if len(rules) < 5000:
        sys.exit('refusing to write: only %d rules parsed' % len(rules))

    body = json.dumps('\n'.join(rules))  # one string literal: data, not code
    header = (
        '/* Public Suffix List, vendored as data by tools/mk_psl.py on %s.\n'
        ' * Source: %s\n'
        ' * License: Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/).\n'
        ' * %d rules (ICANN + private), punycoded. Do not edit by hand; regenerate. */\n'
        % (datetime.date.today().isoformat(), URL, len(rules)))
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write('(typeof self !== "undefined" ? self : globalThis).HRScamPSL = ' + body + ';\n')
    print('wrote %s: %d rules (%d skipped), %d bytes' % (OUT, len(rules), skipped, os.path.getsize(OUT)))


if __name__ == '__main__':
    main()
