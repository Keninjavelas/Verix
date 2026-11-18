// ==============================================================================
// Verix Automated Product Demonstration Generator (`scripts/generate_demo.js`)
// ==============================================================================
// Boots an isolated multi-node Verix fleet (`verix-node-aws-1`, `verix-node-gcp-1`,
// `verix-node-edge-1`), launches headless Chromium against the live Visual Trust
// Intelligence UI, simulates autonomous AI Agent PQC transactions (`POST /verify-action`)
// with real-time WebSocket (`/ws`) graph updates, queries the AI Trust Copilot,
// opens the Cryptographic Proof Dossier, and encodes both:
//   - `assets/demo.gif` & `public/demo.gif` (inline autoplay in GitHub README.md)
//   - `assets/demo.mp4` & `public/demo.mp4` (1080p H.264 MP4 video)
// ==============================================================================

import { spawn, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, rm, writeFile, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import WebSocket from 'ws';
import { loadConfig } from '../src/config.js';
import { executionFingerprint } from '../src/crypto/identity.js';
import { startVerix } from '../src/index.js';

const BROWSER_CANDIDATES = [
  process.env.CHROME_BIN,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium',
].filter(Boolean);

function findBrowserExecutable() {
  for (const candidate of BROWSER_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error('No Chromium/Chrome/Edge binary found. Set CHROME_BIN or install Playwright/Puppeteer.');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class CdpSession {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.nextId = 1;
    this.pending = new Map();
    this.ready = new Promise((resolveReady, rejectReady) => {
      this.ws.once('open', resolveReady);
      this.ws.once('error', rejectReady);
    });
    this.ws.on('message', (raw) => {
      const msg = JSON.parse(String(raw));
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve: res, reject: rej } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) rej(new Error(msg.error.message));
        else res(msg.result);
      }
    });
  }

  async send(method, params = {}) {
    await this.ready;
    const id = this.nextId++;
    return new Promise((res, rej) => {
      this.pending.set(id, { resolve: res, reject: rej });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    this.ws.close();
  }
}

async function seedInitialFleet(platform) {
  const specs = [
    {
      name: 'Agent-7',
      scopes: [
        { action: 'deploy:*', resource: 'infra:*' },
        { action: 'read:*', resource: '*' },
      ],
      role: 'autonomous release engineer',
    },
    {
      name: 'Agent-Ops',
      scopes: [{ action: 'read:logs', resource: 'svc:*' }],
      role: 'sre telemetry observer',
    },
    {
      name: 'Agent-Rogue',
      scopes: [{ action: 'read:*', resource: 'safe:*' }],
      role: 'unverified automation',
    },
  ];

  const agents = new Map();
  for (const spec of specs) {
    const issued = await platform.issueAgent({
      name: spec.name,
      scopes: spec.scopes,
      subject: { role: spec.role },
    });
    agents.set(spec.name, issued);
  }

  const fp = executionFingerprint({
    modelVersion: 'verix-demo-pqc-1',
    promptHash: 'a'.repeat(64),
    codeVersion: 'v1.0.0',
    toolset: ['terraform', 'kubectl', 'cosign'],
  });

  const initialActions = [
    { who: 'Agent-7', action: 'deploy:infra', resource: 'infra:prod-us-east-1', context: { costUsd: 14, destructive: false } },
    { who: 'Agent-Ops', action: 'read:logs', resource: 'svc:audit-ledger', context: {} },
    { who: 'Agent-7', action: 'deploy:infra', resource: 'infra:prod-eu-west-1', context: { costUsd: 18, destructive: false } },
  ];

  for (const item of initialActions) {
    const agent = agents.get(item.who);
    await platform.service.verifyAction({
      identity: agent.identity,
      keyPair: agent.keyPair,
      action: item.action,
      resource: item.resource,
      executionFingerprint: fp,
      context: item.context,
    });
  }

  await platform.reindex();
  return { agents, fp };
}

export async function generateDemo() {
  const workDir = join(tmpdir(), `verix-demo-${Date.now()}`);
  const framesDir = join(workDir, 'frames');
  const profileDir = join(workDir, 'chrome-profile');
  await mkdir(framesDir, { recursive: true });
  await mkdir(profileDir, { recursive: true });

  console.log('[1/6] Starting ephemeral Verix multi-cloud fleet in memory...');
  const config = loadConfig(process.env, {
    VERIX_BACKEND: 'memory',
    VERIX_PORT: 4399,
    VERIX_HOST: '127.0.0.1',
  });
  const running = await startVerix({ config });
  const { agents, fp } = await seedInitialFleet(running.platform);

  const browserBin = findBrowserExecutable();
  const debugPort = 9345;
  console.log(`[2/6] Launching headless Chromium (${browserBin})...`);
  const chrome = spawn(
    browserBin,
    [
      `--remote-debugging-port=${debugPort}`,
      `--user-data-dir=${profileDir}`,
      '--headless=new',
      '--window-size=1920,1080',
      '--hide-scrollbars',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      running.origin,
    ],
    { stdio: 'ignore' },
  );

  let frameIndex = 0;
  const captureHold = async (cdp, count = 12) => {
    const shot = await cdp.send('Page.captureScreenshot', { format: 'png' });
    const pngBytes = Buffer.from(shot.data, 'base64');
    for (let i = 0; i < count; i += 1) {
      frameIndex += 1;
      const padded = String(frameIndex).padStart(4, '0');
      await writeFile(join(framesDir, `frame-${padded}.png`), pngBytes);
    }
  };

  try {
    let targets = null;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        targets = await fetch(`http://127.0.0.1:${debugPort}/json/list`).then((r) => r.json());
        if (targets?.length) break;
      } catch {
        // wait for DevTools endpoint
      }
      await sleep(250);
    }

    const pageTarget = targets.find((t) => t.type === 'page') ?? targets[0];
    const cdp = new CdpSession(pageTarget.webSocketDebuggerUrl);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1920,
      height: 1080,
      deviceScaleFactor: 1,
      mobile: false,
    });

    await sleep(1500);
    console.log('[3/6] Scene 1: Capturing initial Trust Topology & Multi-Cloud Witness Fleet...');
    await captureHold(cdp, 18);

    console.log('[4/6] Scene 2 & 3: Live AI Agent PQC transactions & Rogue Agent Rejection over WebSocket...');
    const agent7 = agents.get('Agent-7');
    await running.platform.service.verifyAction({
      identity: agent7.identity,
      keyPair: agent7.keyPair,
      action: 'deploy:infra',
      resource: 'infra:prod-gcp-us-central1',
      executionFingerprint: fp,
      context: { costUsd: 24, changeTicket: 'CHG-4092' },
    });
    await sleep(900);
    await captureHold(cdp, 18);

    // Simulate unauthorized rogue agent action rejected by policy & quorum
    const rogue = agents.get('Agent-Rogue');
    await running.platform.service.verifyAction({
      identity: rogue.identity,
      keyPair: rogue.keyPair,
      action: 'deploy:infra',
      resource: 'infra:prod-aws-us-east-1',
      executionFingerprint: fp,
      context: { destructive: true },
    });
    await running.platform.reindex();
    await sleep(1000);
    await captureHold(cdp, 22);

    console.log('[5/6] Scene 4, 5 & 6: AI Trust Copilot RAG Query, Timeline & Cryptographic Proof Dossier...');
    // Open Copilot tab and submit live forensic query
    await cdp.send('Runtime.evaluate', {
      expression: `
        document.getElementById('paneTabCopilot')?.click();
        const input = document.getElementById('chatInput');
        const form = document.getElementById('chatForm');
        if (input && form) {
          input.value = 'Why was the deployment flagged for Agent-Rogue?';
          form.requestSubmit();
        }
      `,
    });
    await sleep(1200);
    await captureHold(cdp, 24);

    // Switch to Execution Timeline view while keeping Copilot open
    await cdp.send('Runtime.evaluate', {
      expression: `document.getElementById('tabTimeline')?.click();`,
    });
    await sleep(900);
    await captureHold(cdp, 20);

    // Switch to Ledger Records view and open the top rejected proof in the Cryptographic Dossier
    await cdp.send('Runtime.evaluate', {
      expression: `
        document.getElementById('tabRecords')?.click();
        document.getElementById('paneTabDossier')?.click();
        setTimeout(() => {
          document.querySelector('#recordsBody tbody tr')?.click();
        }, 150);
      `,
    });
    await sleep(1100);
    await captureHold(cdp, 26);

    // Return to Topology view with the proof Dossier open on the right rail
    await cdp.send('Runtime.evaluate', {
      expression: `document.getElementById('tabTopology')?.click();`,
    });
    await sleep(900);
    await captureHold(cdp, 22);

    cdp.close();

    console.log('[6/6] Encoding 1080p MP4 (`demo.mp4`) and inline-autoplay GIF (`demo.gif`)...');
    const assetsDir = resolve('assets');
    await mkdir(assetsDir, { recursive: true });
    const outputMp4 = join(assetsDir, 'demo.mp4');
    const publicMp4 = resolve('public', 'demo.mp4');
    const outputGif = join(assetsDir, 'demo.gif');
    const publicGif = resolve('public', 'demo.gif');
    const palettePath = join(workDir, 'palette.png');

    execFileSync(
      'ffmpeg',
      [
        '-y',
        '-framerate',
        '15',
        '-i',
        join(framesDir, 'frame-%04d.png'),
        '-c:v',
        'libx264',
        '-pix_fmt',
        'yuv420p',
        '-movflags',
        '+faststart',
        outputMp4,
      ],
      { stdio: 'ignore' },
    );

    // Two-pass high-DPI Lanczos palette generation for crisp dark-mode UI text in GitHub README
    execFileSync(
      'ffmpeg',
      [
        '-y',
        '-framerate',
        '15',
        '-i',
        join(framesDir, 'frame-%04d.png'),
        '-vf',
        'fps=10,scale=1280:-1:flags=lanczos,palettegen=stats_mode=diff',
        palettePath,
      ],
      { stdio: 'ignore' },
    );

    execFileSync(
      'ffmpeg',
      [
        '-y',
        '-framerate',
        '15',
        '-i',
        join(framesDir, 'frame-%04d.png'),
        '-i',
        palettePath,
        '-lavfi',
        'fps=10,scale=1280:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle',
        outputGif,
      ],
      { stdio: 'ignore' },
    );

    await copyFile(outputMp4, publicMp4);
    await copyFile(outputGif, publicGif);
    console.log(`[SUCCESS] Generated ${outputMp4} and ${outputGif} (${frameIndex} frames).`);
  } finally {
    chrome.kill();
    await running.close();
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

if (process.argv[1] && resolve(process.argv[1]).endsWith('generate_demo.js')) {
  generateDemo().catch((error) => {
    console.error(`[ERROR] Demo generation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
