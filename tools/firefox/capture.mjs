// Node 22+: independent WebDriver BiDi browser collection, no npm dependencies.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { createHash } from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';

const root = path.resolve(process.argv[2] || '.');
const count = Number(process.argv[3] || 5);
const headed = process.argv.includes('--headed');
if (!Number.isInteger(count) || count < 1 || count > 20) throw Error('Invalid sample count');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = (name, data) => fs.writeFileSync(path.join(root, name), JSON.stringify(data, null, 2));
async function retry(fn, attempts = 200) {
  let error;
  for (let i = 0; i < attempts; i++) {
    try { return await fn(); } catch (e) { error = e; await pause(100); }
  }
  throw error;
}
function kill(child) {
  if (child?.pid) spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], {windowsHide: true, stdio: 'ignore'});
}
async function start(name, exe) {
  const output = path.join(root, name);
  if (fs.existsSync(output)) throw Error('Use a fresh output directory: ' + output);
  const child = spawn(path.join(root, exe), ['-output', output], {windowsHide: true, stdio: 'ignore'});
  try {
    const manifest = await retry(() => JSON.parse(fs.readFileSync(path.join(output, 'lab-manifest.json'), 'utf8')));
    return {child, manifest, events: async () => (await fetch(manifest.management + '/events')).json()};
  } catch (e) { kill(child); throw e; }
}
async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function connect(url) {
  return retry(() => new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener('open', () => resolve(ws), {once: true});
    ws.addEventListener('error', reject, {once: true});
  }));
}
function rpc(ws) {
  let counter = 0;
  const pending = new Map();
  ws.addEventListener('message', event => {
    const message = JSON.parse(String(event.data));
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id); clearTimeout(request.timer);
    message.type === 'error' ? request.reject(Error(JSON.stringify(message))) : request.resolve(message.result);
  });
  return (method, params) => new Promise((resolve, reject) => {
    const id = ++counter;
    const timer = setTimeout(() => { pending.delete(id); reject(Error(method + ' timeout')); }, 25000);
    pending.set(id, {resolve, reject, timer});
    ws.send(JSON.stringify({id, method, params}));
  });
}

let lab12, lab13;
const samples = [];
try {
  const builds = JSON.parse(fs.readFileSync(path.join(root, 'downloads/builds.json'), 'utf8'));
  const discovery = JSON.parse(fs.readFileSync(path.join(root, 'downloads/discovery.json'), 'utf8'));
  if (builds.length !== discovery.versions.length) throw Error('Downloads incomplete');
  lab12 = await start('capture12', 'lab12.exe'); lab13 = await start('capture13', 'lab13.exe');
  for (const build of builds) {
    if (createHash('sha256').update(fs.readFileSync(build.executable)).digest('hex') !== build.executable_sha256) throw Error('Browser executable digest mismatch');
    for (const scenario of [
      {id: 'tls12-h1', lab: lab12, key: 'https', version: 771, alpn: 'http/1.1'},
      {id: 'tls13-h1', lab: lab13, key: 'https', version: 772, alpn: 'http/1.1'},
      {id: 'tls13-h2', lab: lab13, key: 'https2', version: 772, alpn: 'h2'},
    ]) for (let i = 0; i < count; i++) {
      const token = `firefox-${build.version}-${scenario.id}-${i}`;
      const profile = path.join(root, 'profiles', token);
      if (fs.existsSync(profile)) throw Error('Refusing reused browser profile: ' + profile);
      fs.mkdirSync(profile, {recursive: true});
      fs.writeFileSync(path.join(profile, 'user.js'), 'user_pref("browser.shell.checkDefaultBrowser",false);\nuser_pref("browser.startup.homepage_override.mstone","ignore");\n');
      const port = await freePort();
      const args = [...(headed ? [] : ['--headless']), '--no-remote', '--profile', profile, '--remote-debugging-port', String(port), 'about:blank'];
      const child = spawn(build.executable, args, {windowsHide: true, stdio: 'ignore'});
      const sample = {version: build.version, scenario: scenario.id, sample: i, time: new Date().toISOString(), mode: headed ? 'headed' : 'headless', args, status: 'error'};
      const url = scenario.lab.manifest[scenario.key].replace('127.0.0.1', 'localhost') + '/inspect?sample=' + token;
      let ws;
      try {
        ws = await connect(`ws://127.0.0.1:${port}/session`);
        const call = rpc(ws);
        const session = await call('session.new', {capabilities: {alwaysMatch: {acceptInsecureCerts: true}}});
        sample.browser_version = session.capabilities.browserVersion;
        if (sample.browser_version !== build.version) throw Error('Executable version mismatch');
        const {context} = await call('browsingContext.create', {type: 'tab'});
        await call('browsingContext.navigate', {context, url, wait: 'complete'});
        sample.events = await retry(async () => {
          const all = await scenario.lab.events();
          const head = all.find(e => (e.type === 'http1.headers' && e.data.request_line?.includes('/inspect?sample=' + token + ' ')) || (e.type === 'http2.headers' && e.data.headers.some(h => h.name === ':path' && h.value === '/inspect?sample=' + token)));
          if (!head) throw Error('Target request not captured');
          return all.filter(e => e.connection_id === head.connection_id);
        });
        const negotiated = sample.events.find(e => e.type === 'tls.negotiated')?.data;
        if (negotiated?.version !== scenario.version || negotiated?.alpn !== scenario.alpn || negotiated?.resumed !== false) throw Error('Unexpected negotiation or resumed connection');
        if (!sample.events.some(e => e.type === 'tls.client_hello')) throw Error('ClientHello missing');
        sample.status = 'observed';
        await call('session.end', {}).catch(() => {});
      } catch (e) { sample.error = String(e.message || e); }
      finally { ws?.close(); kill(child); }
      samples.push(sample); save('browser-samples.json', samples);
      console.log(token, sample.status, sample.error || '');
    }
  }
} finally {
  for (const lab of [lab12, lab13]) if (lab) {
    try { save(lab.manifest.run_id + '/management-events.json', await lab.events()); } finally { kill(lab.child); }
  }
  save('run.json', {samples: samples.length, expected_samples_per_scenario: count, scope: 'Windows x64 zh-CN; fresh process/profile; isolated BiDi certificate exception; certificate validation and opaque random ECH/key material excluded', mode: headed ? 'headed' : 'headless'});
}
if (samples.some(s => s.status !== 'observed')) process.exitCode = 1;
