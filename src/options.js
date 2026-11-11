/* CatfishGuard options: local rule overrides (roadmap #5).
 * Everything stays in chrome.storage.local. Validation lives in the analyzer
 * (HRScam.normalizeOverrides) so the page, the content script and the tests
 * share one implementation. */
'use strict';

const A = self.HRScam;
const $ = (id) => document.getElementById(id);
const CATS = Object.keys(A.RULES);
const LOCKED = new Set(['credentials']);
const MAX_IMPORT_BYTES = 1024 * 1024;

function el(tag, attrs, text) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'className') e.className = v; else e.setAttribute(k, v);
  }
  if (text != null) e.textContent = text;
  return e;
}

const lines = (id) => $(id).value.split('\n').map((s) => s.trim()).filter(Boolean);

function buildForm() {
  const tbody = $('cats');
  const terms = $('terms');
  for (const id of CATS) {
    const r = A.RULES[id];
    const tr = el('tr');
    const name = el('td');
    name.appendChild(document.createTextNode(r.label));
    name.appendChild(el('small', null, id));
    tr.appendChild(name);
    tr.appendChild(el('td', { className: 'num' }, r.weight + ' / ' + r.cap));
    const w = el('input', { type: 'number', id: 'w-' + id, step: '1', placeholder: String(r.weight), 'aria-label': r.label + ': points per phrase' });
    const c = el('input', { type: 'number', id: 'c-' + id, step: '1', placeholder: String(r.cap), 'aria-label': r.label + ': maximum' });
    const tw = el('td', { className: 'num' }); tw.appendChild(w); tr.appendChild(tw);
    const tc = el('td', { className: 'num' }); tc.appendChild(c); tr.appendChild(tc);
    const off = el('input', { type: 'checkbox', id: 'off-' + id, 'aria-label': 'Turn off ' + r.label });
    if (LOCKED.has(id)) { off.disabled = true; off.title = 'Always on: safety floor'; }
    const to = el('td'); to.appendChild(off); tr.appendChild(to);
    tbody.appendChild(tr);

    const box = el('div');
    box.appendChild(el('label', { for: 'add-' + id }, r.label));
    box.appendChild(el('textarea', { id: 'add-' + id, rows: '2' }));
    terms.appendChild(box);
  }
}

function readForm() {
  const raw = { categories: {}, addTerms: {}, muteTerms: lines('mute'), brands: [], trustedDomains: lines('trusted') };
  for (const id of CATS) {
    const c = {};
    if ($('w-' + id).value !== '') c.weight = $('w-' + id).value;
    if ($('c-' + id).value !== '') c.cap = $('c-' + id).value;
    if ($('off-' + id).checked) c.disabled = true;
    if (Object.keys(c).length) raw.categories[id] = c;
    const add = lines('add-' + id);
    if (add.length) raw.addTerms[id] = add;
  }
  for (const l of lines('brands')) {
    const i = l.indexOf('=');
    const name = (i < 0 ? l : l.slice(0, i)).trim();
    const domains = i < 0 ? [] : l.slice(i + 1).split(/[,\s]+/).filter(Boolean);
    raw.brands.push({ name, domains });
  }
  return raw;
}

function fillForm(o) {
  for (const id of CATS) {
    const c = o.categories[id] || {};
    $('w-' + id).value = c.weight !== undefined ? c.weight : '';
    $('c-' + id).value = c.cap !== undefined ? c.cap : '';
    $('off-' + id).checked = !!c.disabled;
    $('add-' + id).value = (o.addTerms[id] || []).join('\n');
  }
  $('mute').value = o.muteTerms.join('\n');
  $('brands').value = o.brands.map((b) => b.name + ' = ' + b.domains.join(', ')).join('\n');
  $('trusted').value = o.trustedDomains.join('\n');
  preview();
}

function status(msg, kind, warnings) {
  $('status').textContent = msg;
  $('status').className = kind || '';
  const ul = $('warnings');
  ul.textContent = '';
  for (const w of warnings || []) ul.appendChild(el('li', null, w));
}

async function load() {
  let stored = null;
  try { ({ overrides: stored } = await chrome.storage.local.get('overrides')); } catch (_) { /* ignore */ }
  const { overrides, warnings } = A.normalizeOverrides(stored || null);
  fillForm(overrides);
  if (warnings.length) status('Some saved settings were invalid and are ignored.', 'err', warnings);
}

async function save() {
  const { overrides, warnings } = A.normalizeOverrides(readForm());
  try {
    await chrome.storage.local.set({ overrides });
  } catch (e) {
    status('Could not save: ' + String((e && e.message) || e), 'err');
    return;
  }
  fillForm(overrides);
  status(warnings.length ? 'Saved, with some entries ignored:' : 'Saved. Open LinkedIn tabs update automatically.',
    warnings.length ? 'err' : 'ok', warnings);
}

let resetArmed = false;
async function reset() {
  if (!resetArmed) {
    resetArmed = true;
    $('reset').textContent = 'Click again to reset';
    setTimeout(() => { resetArmed = false; $('reset').textContent = 'Reset to defaults'; }, 4000);
    return;
  }
  resetArmed = false;
  $('reset').textContent = 'Reset to defaults';
  try { await chrome.storage.local.remove('overrides'); } catch (_) { /* ignore */ }
  fillForm(A.normalizeOverrides(null).overrides);
  status('Reset to the built-in rules.', 'ok');
}

function exportJson() {
  const { overrides } = A.normalizeOverrides(readForm());
  const blob = new Blob([JSON.stringify(overrides, null, 2)], { type: 'application/json' });
  const a = el('a', { href: URL.createObjectURL(blob), download: 'catfishguard-rules.json' });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  status('Exported to a file on this computer.', 'ok');
}

function importJson(file) {
  if (!file) return;
  if (file.size > MAX_IMPORT_BYTES) { status('That file is too large (max 1 MB).', 'err'); return; }
  const reader = new FileReader();
  reader.onload = () => {
    let parsed;
    try { parsed = JSON.parse(String(reader.result)); } catch (_) { status('That file is not valid JSON.', 'err'); return; }
    const { overrides, warnings } = A.normalizeOverrides(parsed);
    fillForm(overrides);
    status('Imported. Review it, then press Save.', warnings.length ? 'err' : 'ok', warnings);
  };
  reader.readAsText(file);
}

let previewTimer = null;
function preview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(() => {
    const text = $('sample').value;
    const show = (id, r) => {
      const b = $(id);
      b.textContent = text.trim() ? r.score + ' (' + r.band + ')' : '–';
      b.className = text.trim() ? 'band-' + r.band : '';
      const ul = $(id + '-r');
      ul.textContent = '';
      if (!text.trim()) return;
      for (const x of r.reasons.filter((y) => y.points !== 0).slice(0, 8)) {
        ul.appendChild(el('li', null, x.label + ' (' + (x.points > 0 ? '+' : '') + x.points + '): ' +
          x.matches.slice(0, 3).map((m) => m.term).join(', ')));
      }
    };
    show('pv-stock', A.analyze(text, []));
    show('pv-custom', A.analyze(text, [], { overrides: readForm() }));
  }, 150);
}

buildForm();
document.querySelector('main').addEventListener('input', preview);
document.querySelector('main').addEventListener('change', preview);
$('save').addEventListener('click', save);
$('reset').addEventListener('click', reset);
$('export').addEventListener('click', exportJson);
$('import').addEventListener('click', () => $('importFile').click());
$('importFile').addEventListener('change', (e) => { importJson(e.target.files[0]); e.target.value = ''; });
load();
