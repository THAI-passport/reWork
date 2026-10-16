---
name: dbug-web-static
description: Static analysis of web/Electron applications. asar unpacking, Node module survey, bundled Chromium DevTools protocol inspection, endpoint/URL extraction from JS bundles, and package.json inspection. Gate G2 surface map for web/Electron targets.
---

# dbug-web-static (Gate G2: Web/Electron)

Web and Electron applications bundle JavaScript, HTML, CSS, and Node modules. Electron apps additionally package an `asar` archive and a Chromium renderer. Static analysis proceeds without running the app (AGENTS.md ground rule 2).

## 1. Application structure
- **Web app:** HTML/JS/CSS bundles, service workers, webpack/vite/rollup output, package.json.
- **Electron app:** `app.asar` (zipped archive), `package.json`, `main.js` (main process), `preload.js`, renderer JS, `node_modules/`, native `.node` modules.

## 2. Static analysis steps
1. **asar unpacking:** extract `app.asar` (zip-like format) to inspect bundled source.
2. **package.json inspection:** name, version, dependencies, `main` entry, `scripts`, Electron-specific fields (`electronVersion`, `nodeIntegration`, `contextIsolation`).
3. **Node module survey:** list `node_modules/`; identify networking (axios, request, ws, socket.io), crypto (crypto-js, jsencrypt), storage (localStorage, IndexedDB wrappers), and native modules (`.node` addons).
4. **Endpoint/URL extraction:** scan JS bundles for `fetch`, `XMLHttpRequest`, `WebSocket`, `axios`, `socket.io`, `https://` URLs, API paths, GraphQL endpoints.
5. **DevTools protocol inspection:** look for `--remote-debugging-port`, `webPreferences` (`nodeIntegration: true`, `contextIsolation: false` = `[H]` risk), `enableRemoteModule`.
6. **String extraction:** hardcoded API keys, tokens, URLs, credentials, staging vs production flags.
7. **Source maps:** check for `.map` files (expose original source = `[C]` finding).

## 3. Output
Write into PROTOCOL.md a surface map: app type, entry point, dependencies, endpoints, security-relevant preferences (`nodeIntegration`, `contextIsolation`), source maps, hardcoded secrets. Every row tagged `[C]` (confirmed in bundle) or `[U]` (unknown).

## 4. Evidence tags
- `[C]` confirmed in app bundle/source
- `[U]` unknown (server-side config, obfuscated code)
- Never `[H]` without running the app (user-provided host only).

## 5. Dependencies
- Stdlib-only: `asar` format is zip-like, parseable with Python `zipfile`
- Optional: `asar` npm package, `electron` binary