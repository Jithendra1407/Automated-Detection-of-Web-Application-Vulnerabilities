/* =============================================

   CYBERSCAN PRO — App Logic

   js/app.js

   ============================================= */
 
'use strict';
 
/* ── Utilities ───────────────────────────────── */

const $ = (sel, ctx = document) => ctx.querySelector(sel);

const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

const sleep = ms => new Promise(r => setTimeout(r, ms));
 
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function padStart(n, len = 2) { return String(n).padStart(len, '0'); }
 
function now() {

  const d = new Date();

  return `${padStart(d.getHours())}:${padStart(d.getMinutes())}:${padStart(d.getSeconds())}`;

}
 
/* ── Animated counter ────────────────────────── */

function animateCounter(el, target, duration = 1200, suffix = '') {

  const start = parseInt(el.textContent) || 0;

  const range = target - start;

  const startTime = performance.now();
 
  function step(ts) {

    const progress = Math.min((ts - startTime) / duration, 1);

    const eased = 1 - Math.pow(1 - progress, 3);

    el.textContent = Math.round(start + range * eased) + suffix;

    if (progress < 1) requestAnimationFrame(step);

  }

  requestAnimationFrame(step);

}
 
/* ── SVG Ring progress ───────────────────────── */

function setRing(svgEl, percent, color = '#00ffe0') {

  const circle = svgEl.querySelector('.ring-progress');

  if (!circle) return;

  const r = parseFloat(circle.getAttribute('r'));

  const circ = 2 * Math.PI * r;

  circle.style.strokeDasharray = circ;

  circle.style.strokeDashoffset = circ * (1 - percent / 100);

  circle.style.stroke = color;

}
 
/* ── Log terminal ────────────────────────────── */

class LogTerminal {

  constructor(el, maxLines = 80) {

    this.el = el;

    this.maxLines = maxLines;

    this.lines = [];

  }
 
  add(level, text) {

    const classes = { ok: 'log-ok', warn: 'log-warn', err: 'log-err', info: 'log-info' };

    const cls = classes[level] || 'log-info';

    const prefixes = { ok: '[  OK  ]', warn: '[ WARN ]', err: '[ FAIL ]', info: '[ INFO ]' };

    const prefix = prefixes[level] || '[ .... ]';
 
    const line = document.createElement('div');

    line.className = 'log-line';

    line.innerHTML = `<span class="log-time">${now()}</span><span class="${cls}">${prefix}</span><span>${text}</span>`;

    this.el.appendChild(line);

    this.lines.push(line);
 
    if (this.lines.length > this.maxLines) {

      this.lines.shift().remove();

    }

    this.el.scrollTop = this.el.scrollHeight;

  }
 
  clear() {

    this.el.innerHTML = '';

    this.lines = [];

  }

}
 
/* ── Scan Engine ─────────────────────────────── */

const SCAN_PHASES = [

  { name: 'DNS Enumeration',     weight: 8,  logLevel: 'info' },

  { name: 'Port Discovery',      weight: 12, logLevel: 'info' },

  { name: 'Service Detection',   weight: 10, logLevel: 'info' },

  { name: 'OS Fingerprinting',   weight: 8,  logLevel: 'info' },

  { name: 'SSL/TLS Analysis',    weight: 10, logLevel: 'info' },

  { name: 'Vulnerability Scan',  weight: 20, logLevel: 'warn' },

  { name: 'CVE Correlation',     weight: 12, logLevel: 'warn' },

  { name: 'Exploit Check',       weight: 10, logLevel: 'err'  },

  { name: 'Web App Scan',        weight: 10, logLevel: 'warn' },

  { name: 'Generating Report',   weight: 0,  logLevel: 'ok'   },

];
 
const SAMPLE_LOGS = {

  info: [

    'Resolving hostname to IP…',

    'Querying WHOIS records…',

    'Checking SPF/DMARC records…',

    'Probing TCP/UDP ports…',

    'Banner grabbing on open ports…',

    'Detected Apache/2.4.54 on port 80',

    'SSH service on port 22 (OpenSSH 8.9)',

    'Analyzing TLS certificate chain…',

    'Certificate expires in 47 days',

  ],

  warn: [

    'Outdated library detected: OpenSSL 1.1.x',

    'Missing security header: Content-Security-Policy',

    'Missing header: X-Frame-Options',

    'CVE-2023-44487 (HTTP/2 Rapid Reset) — potential match',

    'Weak cipher suite: TLS_RSA_WITH_RC4_128_SHA',

    'Directory listing enabled on /uploads/',

    'Cross-origin resource sharing too permissive',

    'Session cookies missing Secure flag',

  ],

  err: [

    'CVE-2024-1234 CRITICAL — Remote Code Execution',

    'SQL injection vector found in query parameter',

    'Authentication bypass possible via header injection',

    'Exposed admin panel at /wp-admin',

    'Default credentials accepted on port 2082',

  ],

  ok: [

    'DNS lookups complete',

    'Port scan finished — 12 open ports',

    'SSL handshake analysis complete',

    'Vulnerability correlation done',

    'Exploit database cross-check complete',

    'Report compiled successfully',

  ],

};
 
function pickLog(level) {

  const pool = SAMPLE_LOGS[level] || SAMPLE_LOGS.info;

  return pool[rand(0, pool.length - 1)];

}
 
class Scanner {

  constructor({ progressBar, progressText, phaseText, logTerminal, onComplete }) {

    this.progressBar = progressBar;

    this.progressText = progressText;

    this.phaseText = phaseText;

    this.terminal = logTerminal;

    this.onComplete = onComplete;

    this.running = false;

    this.abortCtrl = null;

  }
 
  async start(target) {

    if (this.running) return;

    this.running = true;

    this.abortCtrl = new AbortController();

    const { signal } = this.abortCtrl;
 
    let totalProgress = 0;
 
    try {

      this.terminal.clear();

      this.terminal.add('info', `Starting scan on: ${target}`);

      await sleep(400);
 
      for (const phase of SCAN_PHASES) {

        if (signal.aborted) break;
 
        if (this.phaseText) this.phaseText.textContent = phase.name;

        this.terminal.add(phase.logLevel, `Phase: ${phase.name}`);
 
        const logCount = rand(2, 5);

        const phaseTime = rand(600, 1800);

        const step = phase.weight / logCount;
 
        for (let i = 0; i < logCount; i++) {

          if (signal.aborted) break;

          await sleep(phaseTime / logCount);

          totalProgress = Math.min(totalProgress + step, 100);

          this._setProgress(totalProgress);

          this.terminal.add(phase.logLevel, pickLog(phase.logLevel));

        }

      }
 
      if (!signal.aborted) {

        this._setProgress(100);

        if (this.phaseText) this.phaseText.textContent = 'Complete';

        this.terminal.add('ok', 'Scan complete.');

        await sleep(300);

        this.onComplete && this.onComplete(this._generateResults(target));

      }

    } catch (e) {

      console.error(e);

    } finally {

      this.running = false;

    }

  }
 
  stop() {

    if (this.abortCtrl) this.abortCtrl.abort();

    this.running = false;

  }
 
  _setProgress(pct) {

    if (this.progressBar) this.progressBar.style.width = pct + '%';

    if (this.progressText) this.progressText.textContent = Math.round(pct) + '%';

  }
 
  _generateResults(target) {

    const critical = rand(1, 4);

    const high     = rand(2, 8);

    const medium   = rand(5, 14);

    const low      = rand(4, 12);

    const info     = rand(8, 20);

    const total    = critical + high + medium + low + info;
 
    const riskScore = Math.min(

      Math.round(critical * 25 + high * 10 + medium * 4 + low * 1.5),

      100

    );
 
    const vulns = [];

    const vuln_templates = [

      { id: 'CVE-2024-1234', name: 'Remote Code Execution via Deserialization', sev: 'critical', cvss: '9.8', port: '8080' },

      { id: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset Attack', sev: 'high', cvss: '7.5', port: '443' },

      { id: 'CVE-2023-5678', name: 'SQL Injection in Login Form', sev: 'critical', cvss: '9.1', port: '80' },

      { id: 'CVE-2023-2222', name: 'Reflected XSS in Search', sev: 'medium', cvss: '6.1', port: '80' },

      { id: 'CVE-2022-9999', name: 'Weak TLS Cipher Suite', sev: 'medium', cvss: '5.3', port: '443' },

      { id: 'CVE-2022-3333', name: 'Directory Traversal', sev: 'high', cvss: '7.8', port: '80' },

      { id: 'CVE-2021-1111', name: 'Open Redirect', sev: 'low', cvss: '3.1', port: '80' },

      { id: 'CVE-2024-5555', name: 'Authentication Bypass', sev: 'critical', cvss: '9.4', port: '22' },

      { id: 'MISC-001', name: 'Missing Content-Security-Policy', sev: 'medium', cvss: '5.0', port: '80' },

      { id: 'MISC-002', name: 'Session Cookie Missing Secure Flag', sev: 'low', cvss: '3.7', port: '80' },

      { id: 'MISC-003', name: 'Exposed Admin Panel', sev: 'high', cvss: '8.1', port: '80' },

    ];
 
    const shuffled = [...vuln_templates].sort(() => Math.random() - 0.5);

    vulns.push(...shuffled.slice(0, Math.min(total, shuffled.length)));
 
    return {

      target, riskScore, total, critical, high, medium, low, info, vulns,

      openPorts: rand(8, 20),

      scannedAt: new Date().toLocaleString(),

    };

  }

}
 
/* ── Dashboard UI ────────────────────────────── */

class Dashboard {

  constructor() {

    this.terminal = null;

    this.scanner  = null;

    this.results  = null;

    this._init();

  }
 
  _init() {

    const termEl = $('#scan-terminal');

    if (termEl) this.terminal = new LogTerminal(termEl);
 
    this.scanner = new Scanner({

      progressBar:  $('#scan-progress-bar'),

      progressText: $('#scan-progress-pct'),

      phaseText:    $('#scan-phase'),

      logTerminal:  this.terminal,

      onComplete:   (r) => this._showResults(r),

    });
 
    const form = $('#scan-form');

    if (form) {

      form.addEventListener('submit', async (e) => {

        e.preventDefault();

        const target = $('#scan-target')?.value?.trim();

        if (!target) return;

        this._startScan(target);

      });

    }
 
    const stopBtn = $('#stop-scan');

    if (stopBtn) {

      stopBtn.addEventListener('click', () => {

        this.scanner.stop();

        stopBtn.style.display = 'none';

        $('#start-scan') && ($('#start-scan').disabled = false);

      });

    }
 
    // Animate existing stat cards on load

    this._animateStatCards();
 
    // Live clock

    this._clock();

  }
 
  _clock() {

    const el = $('#live-clock');

    if (!el) return;

    const tick = () => {

      const d = new Date();

      el.textContent = d.toLocaleTimeString('en-US', { hour12: false });

    };

    tick();

    setInterval(tick, 1000);

  }
 
  _animateStatCards() {

    $$('.stat-card[data-value]').forEach((card, i) => {

      const el    = card.querySelector('.stat-value');

      const bar   = card.querySelector('.stat-bar');

      const val   = parseInt(card.dataset.value);

      const pct   = parseInt(card.dataset.pct || '0');

      const suf   = card.dataset.suffix || '';

      if (!el) return;

      el.textContent = '0' + suf;

      setTimeout(() => {

        animateCounter(el, val, 1400, suf);

        if (bar) setTimeout(() => (bar.style.width = pct + '%'), 100);

      }, i * 150 + 200);

    });

  }
 
  _startScan(target) {

    const startBtn = $('#start-scan');

    const stopBtn  = $('#stop-scan');

    const resultsEl = $('#results-section');
 
    if (startBtn) startBtn.disabled = true;

    if (stopBtn)  stopBtn.style.display = 'inline-flex';

    if (resultsEl) resultsEl.style.display = 'none';
 
    $('#scan-status') && ($('#scan-status').textContent = 'Scanning…');
 
    this.scanner.start(target);

  }
 
  _showResults(r) {

    this.results = r;

    const stopBtn  = $('#stop-scan');

    const startBtn = $('#start-scan');

    if (stopBtn)  stopBtn.style.display = 'none';

    if (startBtn) startBtn.disabled = false;

    $('#scan-status') && ($('#scan-status').textContent = 'Complete');
 
    const section = $('#results-section');

    if (!section) return;

    section.style.display = 'block';

    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
 
    // Score ring

    const ringEl = $('#risk-ring');

    if (ringEl) {

      const color = r.riskScore >= 75 ? '#ff3860' : r.riskScore >= 50 ? '#ffc107' : '#00e676';

      setRing(ringEl, r.riskScore, color);

      const label = ringEl.querySelector('.ring-pct');

      if (label) animateCounter(label, r.riskScore, 1500, '');

    }
 
    // Stat counters in results

    [

      ['#res-total',    r.total],

      ['#res-critical', r.critical],

      ['#res-high',     r.high],

      ['#res-medium',   r.medium],

      ['#res-low',      r.low],

      ['#res-ports',    r.openPorts],

    ].forEach(([sel, val]) => {

      const el = $(sel);

      if (el) animateCounter(el, val, 1200);

    });
 
    // Vuln table

    const tbody = $('#vuln-tbody');

    if (tbody) {

      tbody.innerHTML = '';

      r.vulns.forEach((v, i) => {

        const sevClass = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }[v.sev];

        const tagClass  = { critical: 'tag-danger', high: 'tag-danger', medium: 'tag-warn', low: 'tag-info', info: 'tag-ok' }[v.sev];

        const tr = document.createElement('tr');

        tr.style.animationDelay = `${i * 40}ms`;

        tr.className = 'animate-fade-up';

        tr.innerHTML = `
<td><span class="sev-dot ${sevClass}"></span>${v.id}</td>
<td>${v.name}</td>
<td><span class="tag ${tagClass}">${v.sev}</span></td>
<td>${v.cvss}</td>
<td>${v.port}</td>

        `;

        tbody.appendChild(tr);

      });

    }
 
    // Scanned at

    const scannedAt = $('#scanned-at');

    if (scannedAt) scannedAt.textContent = r.scannedAt;

  }

}
 
/* ── Landing page interactions ───────────────── */

class LandingPage {

  constructor() {

    this._initTypewriter();

    this._initScrollReveal();

  }
 
  _initTypewriter() {

    const el = $('#typewriter');

    if (!el) return;

    const texts = [

      'Scan for vulnerabilities.',

      'Detect open ports.',

      'Analyze SSL/TLS.',

      'Correlate CVEs.',

      'Generate security reports.',

    ];

    let ti = 0, ci = 0, deleting = false;
 
    const type = () => {

      const current = texts[ti];

      if (!deleting) {

        el.textContent = current.slice(0, ++ci);

        if (ci === current.length) { deleting = true; setTimeout(type, 1800); return; }

      } else {

        el.textContent = current.slice(0, --ci);

        if (ci === 0) { deleting = false; ti = (ti + 1) % texts.length; }

      }

      setTimeout(type, deleting ? 40 : 70);

    };

    type();

  }
 
  _initScrollReveal() {

    const els = $$('[data-reveal]');

    if (!els.length || !('IntersectionObserver' in window)) return;

    const io = new IntersectionObserver((entries) => {

      entries.forEach(e => {

        if (e.isIntersecting) {

          e.target.style.animationPlayState = 'running';

          io.unobserve(e.target);

        }

      });

    }, { threshold: 0.15 });

    els.forEach(el => {

      el.style.animation = 'fadeUp 0.6s ease both paused';

      io.observe(el);

    });

  }

}
 
/* ── Boot ────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {

  // Dashboard

  if ($('#scan-form') || $('.stat-card')) {

    new Dashboard();

  }

  // Landing

  if ($('#typewriter') || $('[data-reveal]')) {

    new LandingPage();

  }

});
 
