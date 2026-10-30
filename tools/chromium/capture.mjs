// Independent CDP capture. Each sample has a fresh process/profile; no retries.
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import {X509Certificate, createHash} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';

const root = path.resolve(process.argv[2]);
const count = Number(process.argv[3] || 5);
if (!Number.isInteger(count) || count < 5 || count > 20) throw Error('Expected 5..20 samples');
const save = (name, value) => fs.writeFileSync(path.join(root, name), JSON.stringify(value, null, 2));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function ready(fn) {
  let last;
  for (let i = 0; i < 150; i++) {
    try { return await fn(); } catch (error) { last = error; await pause(100); }
  }
  throw last;
}
function kill(child) {
  if (child?.pid) spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], {windowsHide: true, stdio: 'ignore'});
}
function pin(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.hostname !== '127.0.0.1' || u.protocol !== 'https:') return reject(Error('Collector must be local HTTPS'));
    // Only read this independent collector's leaf key; browser bypass is scoped
    // to this exact SPKI and fresh process. No persistent trust store changes.
    const socket = tls.connect({host: u.hostname, port: u.port, rejectUnauthorized: false}, () => {
      try {
        const cert = new X509Certificate(socket.getPeerCertificate().raw);
        resolve(createHash('sha256').update(cert.publicKey.export({type: 'spki', format: 'der'})).digest('base64'));
      } catch (error) { reject(error); } finally { socket.end(); }
    });
    socket.setTimeout(10000, () => socket.destroy(Error('Collector certificate timeout')));
    socket.on('error', reject);
  });
}
async function start(suffix) {
  const output = path.join(root, 'capture' + suffix);
  if (fs.existsSync(output)) throw Error('Collector directory must be fresh');
  const child = spawn(path.join(root, 'lab' + suffix + '.exe'), ['-output', output], {windowsHide: true, stdio: 'ignore'});
  try {
    const manifest = await ready(() => JSON.parse(fs.readFileSync(path.join(output, 'lab-manifest.json'), 'utf8')));
    return {child, manifest, pin: await pin(manifest.https), events: async () => {
      const response = await fetch(manifest.management + '/events', {signal: AbortSignal.timeout(10000)});
      if (!response.ok) throw Error('Collector read failed');
      return response.json();
    }};
  } catch (error) { kill(child); throw error; }
}
function rpc(ws) {
  let sequence = 0;
  const pending = new Map();
  ws.addEventListener('message', event => {
    const message = JSON.parse(String(event.data));
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id); clearTimeout(request.timer);
    message.error ? request.reject(Error(JSON.stringify(message.error))) : request.resolve(message.result);
  });
  return (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(Error(method + ' timeout')); }, 15000);
    pending.set(id, {resolve, reject, timer}); ws.send(JSON.stringify({id, method, params}));
  });
}

const samples = [], labs = [];
try {
  const builds = JSON.parse(fs.readFileSync(path.join(root, 'downloads/builds.json'), 'utf8'));
  for (const suffix of ['12', '13']) labs.push(await start(suffix));
  for (const build of builds) {
    if (createHash('sha256').update(fs.readFileSync(build.executable)).digest('hex') !== build.executable_sha256) throw Error('Executable digest drift');
    for (const scenario of [
      {id: 'tls12-h1', lab: labs[0], key: 'https', version: 771, alpn: 'http/1.1'},
      {id: 'tls13-h1', lab: labs[1], key: 'https', version: 772, alpn: 'http/1.1'},
      {id: 'tls13-h2', lab: labs[1], key: 'https2', version: 772, alpn: 'h2'},
    ]) for (let i = 0; i < count; i++) {
      const token = `${build.browser}-${build.version}-${scenario.id}-${i}`;
      const profile = path.join(root, 'profiles', token);
      if (fs.existsSync(profile)) throw Error('Refusing reused profile');
      const args = ['--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--no-proxy-server', '--lang=en-US',
        '--window-position=-32000,-32000', '--start-minimized', '--user-data-dir=' + profile,
        '--remote-debugging-port=0', '--ignore-certificate-errors-spki-list=' + scenario.lab.pin, 'about:blank'];
      const child = spawn(build.executable, args, {windowsHide: true, stdio: 'ignore'});
      const row = {browser: build.browser, version: build.version, scenario: scenario.id, sample: i, time: new Date().toISOString(),
        mode: 'headed-minimized', args, executable_sha256: build.executable_sha256, status: 'error'};
      let ws;
      try {
        const port = await ready(() => {
          const lines = fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').split('\n');
          if (!/^\d+$/.test(lines[0])) throw Error('Invalid DevTools port');
          return Number(lines[0]);
        });
        const response = await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', {method: 'PUT', signal: AbortSignal.timeout(10000)});
        if (!response.ok) throw Error('Cannot create browser target');
        const target = await response.json();
        ws = await new Promise((resolve, reject) => {
          const socket = new WebSocket(target.webSocketDebuggerUrl);
          const timer = setTimeout(() => { socket.close(); reject(Error('CDP connection timeout')); }, 10000);
          socket.addEventListener('open', () => { clearTimeout(timer); resolve(socket); }, {once: true});
          socket.addEventListener('error', e => { clearTimeout(timer); reject(e); }, {once: true});
        });
        const call = rpc(ws);
        row.browser_identity = await call('Browser.getVersion');
        const product = (build.browser === 'edge' ? 'Edg/' : 'Chrome/') + build.version;
        if (row.browser_identity.product !== product) throw Error('Wrong browser/full version: ' + row.browser_identity.product);
        row.browser_version = build.version;
        const url = scenario.lab.manifest[scenario.key].replace('127.0.0.1', 'localhost') + '/inspect?sample=' + token;
        row.navigation = await call('Page.navigate', {url});
        if (row.navigation.errorText) throw Error(row.navigation.errorText);
        row.events = await ready(async () => {
          const all = await scenario.lab.events();
          const head = all.find(e => e.type === 'http1.headers' && e.data.request_line?.includes('/inspect?sample=' + token + ' ') ||
            e.type === 'http2.headers' && e.data.headers.some(h => h.name === ':path' && h.value === '/inspect?sample=' + token));
          if (!head) throw Error('Target request not captured');
          return all.filter(e => e.run_id === head.run_id && e.connection_id === head.connection_id);
        });
        const negotiated = row.events.find(e => e.type === 'tls.negotiated')?.data;
        if (negotiated?.version !== scenario.version || negotiated?.alpn !== scenario.alpn || negotiated?.resumed !== false ||
            !row.events.some(e => e.type === 'tls.client_hello') || row.events.some(e => e.type.endsWith('.error') || e.type === 'capture.incomplete')) throw Error('Invalid/incomplete cold connection');
        row.status = 'observed';
      } catch (error) { row.error = String(error.message || error); }
      finally { ws?.close(); kill(child); }
      samples.push(row); save('browser-samples.json', samples);
      console.log(token, row.status, row.error || '');
      if (row.status !== 'observed') throw Error('Sample failed; raw row retained');
    }
  }
} finally {
  for (const lab of labs) {
    try { save(lab.manifest.run_id + '/management-events.json', await lab.events()); } finally { kill(lab.child); }
  }
  save('run.json', {samples: samples.length, expected_samples_per_scenario: count, mode: 'headed-minimized',
    scope: 'Windows x64 en-US; fresh cold process/profile; exact local SPKI exception; no certificate-validation, resumption or other-mode equivalence claim'});
}
