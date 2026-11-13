#!/usr/bin/env python3
"""Build the Chrome Web Store upload: dist/catfishguard-<version>.zip

Only what the extension loads ships: manifest.json, src/, data/, icons/,
plus LICENSE.
Tests, tools, notes (CLAUDE.md, PROGRESS.md) and package.json stay out.
Fails loudly if the manifest points at a file that isn't packaged, if the
manifest and package.json versions disagree, or if anything unexpected
(dotfiles, editor backups, source maps) would ship.

Standard library only. Usage: python3 tools/package.py   (npm run package)
"""
import json
import os
import sys
import zipfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
SHIP_DIRS = ('src', 'data', 'icons')
ALLOWED_EXT = {'.js', '.html', '.css', '.json', '.png'}
FIXED_TIME = (2026, 1, 1, 0, 0, 0)  # reproducible zips: same input, same bytes


def fail(msg):
    print('package: ' + msg, file=sys.stderr)
    sys.exit(1)


def manifest_refs(m):
    refs = set()
    for cs in m.get('content_scripts', []):
        refs.update(cs.get('js', []))
        refs.update(cs.get('css', []))
    if m.get('background', {}).get('service_worker'):
        refs.add(m['background']['service_worker'])
    if m.get('options_ui', {}).get('page'):
        refs.add(m['options_ui']['page'])
    action = m.get('action', {})
    if action.get('default_popup'):
        refs.add(action['default_popup'])
    refs.update(action.get('default_icon', {}).values())
    refs.update(m.get('icons', {}).values())
    return refs


def main():
    with open(os.path.join(ROOT, 'manifest.json'), encoding='utf-8') as f:
        manifest = json.load(f)
    with open(os.path.join(ROOT, 'package.json'), encoding='utf-8') as f:
        pkg = json.load(f)
    version = manifest.get('version')
    if not version:
        fail('manifest.json has no version')
    if pkg.get('version') != version:
        fail('version mismatch: manifest %s vs package.json %s' % (version, pkg.get('version')))

    files = ['manifest.json', 'LICENSE']  # Apache-2.0 §4: copies carry the licence
    for d in SHIP_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, d)):
            dirnames.sort()
            for name in sorted(filenames):
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, '/')
                if name.startswith('.'):
                    continue  # .DS_Store and friends never ship
                if os.path.splitext(name)[1] not in ALLOWED_EXT:
                    fail('unexpected file type would ship: ' + rel)
                files.append(rel)

    missing = sorted(r for r in manifest_refs(manifest) if r not in files)
    if missing:
        fail('manifest references files that are not packaged: ' + ', '.join(missing))

    out_dir = os.path.join(ROOT, 'dist')
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, 'catfishguard-%s.zip' % version)
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel in files:
            info = zipfile.ZipInfo(rel, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(os.path.join(ROOT, rel), 'rb') as f:
                z.writestr(info, f.read())
    size = os.path.getsize(out)
    print('wrote %s (%d files, %.1f KB)' % (os.path.relpath(out, ROOT), len(files), size / 1024))
    for rel in files:
        print('  ' + rel)


if __name__ == '__main__':
    main()
