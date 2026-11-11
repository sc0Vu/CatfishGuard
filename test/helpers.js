'use strict';
// Load src/analyzer.js into a vm sandbox that provides only `self` + `URL`,
// exactly as CLAUDE.md describes, so the engine is proven dependency-free.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'src');

function loadAnalyzer() {
  const sandbox = { URL };
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  // Same order as the manifest: the bundled Public Suffix List (data), then the engine.
  vm.runInContext(fs.readFileSync(path.join(SRC, 'psl.js'), 'utf8'), sandbox, { filename: 'psl.js' });
  vm.runInContext(fs.readFileSync(path.join(SRC, 'analyzer.js'), 'utf8'), sandbox, { filename: 'analyzer.js' });
  return sandbox.HRScam;
}

// vm objects come from another realm; round-trip through JSON for deepStrictEqual.
const plain = (v) => JSON.parse(JSON.stringify(v));

module.exports = { SRC, loadAnalyzer, plain };
