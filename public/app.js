// AI Shield Protector - frontend app: hash router + views.
import {
  apiFetch, esc, badge, formatDate, toast, confirmDialog,
  renderResult, emptyState, categoryClass,
} from './lib.js';

const view = document.getElementById('view');
const pageTitle = document.getElementById('page-title');

/* ---------------- Routing ---------------- */
const routes = {
  '/': { title: 'AI Shield Protector', render: renderLanding },
  '/dashboard': { title: 'Dashboard', render: renderDashboard },
  '/url': { title: 'URL Scanner', render: renderUrlScanner },
  '/message': { title: 'Message Scanner', render: renderMessageScanner },
  '/history': { title: 'Scan History', render: renderHistory },
  '/education': { title: 'Threat Education Center', render: renderEducation },
  '/settings': { title: 'Security Settings', render: renderSettings },
  '/account': { title: 'Account', render: renderAccount },
  '/privacy': { title: 'Privacy Policy', render: renderPrivacy },
  '/about': { title: 'About & Documentation', render: renderAbout },
};

function currentPath() {
  const hash = location.hash.replace(/^#/, '');
  return hash || '/';
}

async function router() {
  const path = currentPath();
  const route = routes[path] || routes['/'];
  pageTitle.textContent = route.title;
  document.title = `${route.title} · AI Shield Protector`;

  // Highlight active nav item
  document.querySelectorAll('#nav a').forEach((a) => {
    a.classList.toggle('active', a.getAttribute('data-route') === path);
  });

  closeSidebar();
  view.innerHTML = '<div class="row" style="padding:30px"><span class="spinner"></span> &nbsp; Loading…</div>';
  try {
    await route.render();
  } catch (err) {
    view.innerHTML = `<div class="card"><h2 class="section">Something went wrong</h2><p class="muted">${esc(err.message)}</p></div>`;
  }
  document.getElementById('main').focus();
}

window.addEventListener('hashchange', router);

/* ---------------- Views ---------------- */

function renderLanding() {
  view.innerHTML = `
    <section class="hero">
      <span class="pill">Defensive security helper</span>
      <h1>Spot phishing &amp; scams<br><span class="accent">before they catch you</span></h1>
      <p>AI Shield Protector inspects suspicious links and messages for common warning signs,
         then explains what it found in plain language. It never opens links or runs anything for you.</p>
      <div class="cta">
        <a class="btn primary" href="#/url">Scan a URL</a>
        <a class="btn" href="#/message">Scan a message</a>
        <a class="btn ghost" href="#/dashboard">Open dashboard</a>
      </div>
    </section>

    <div class="grid cols-3 mt">
      ${feature('link', 'Link analysis', 'Checks for IP hosts, lookalike domains, punycode, "@" tricks, odd ports and more — from the link text only.')}
      ${feature('message', 'Message analysis', 'Flags urgency, credential requests, unusual payments, prize bait and impersonation patterns.')}
      ${feature('explain', 'Clear explanations', 'Every result tells you which indicators fired, why they matter, and what to do next.')}
    </div>

    <div class="disclaimer mt">
      <b>Important:</b> This is an automated helper that highlights warning signs. It cannot detect
      every threat and cannot guarantee that any link or message is safe. Always use your own judgment.
    </div>`;
}

const FEATURE_ICONS = {
  link: '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>',
  message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  explain: '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/>',
};

function feature(icon, title, body) {
  return `<div class="card">
    <div class="feat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${FEATURE_ICONS[icon] || ''}</svg></div>
    <h2 class="section">${esc(title)}</h2>
    <p class="muted">${esc(body)}</p>
  </div>`;
}

async function renderDashboard() {
  const stats = await apiFetch('/stats');
  const dist = stats.distribution || {};
  const cats = [
    ['High Risk Indicators', 'high'],
    ['Suspicious', 'suspicious'],
    ['Low Risk Indicators', 'low'],
    ['Unknown / Insufficient Evidence', 'unknown'],
  ];

  const recent = stats.recent.length
    ? `<table>
        <thead><tr><th>Type</th><th>Summary</th><th>Risk</th><th>When</th></tr></thead>
        <tbody>
          ${stats.recent.map((s) => `
            <tr>
              <td>${esc(s.type)}</td>
              <td style="max-width:280px;word-break:break-all">${esc(s.summary || '—')}</td>
              <td>${badge(s.category)}</td>
              <td class="faint">${formatDate(s.created_at)}</td>
            </tr>`).join('')}
        </tbody>
      </table>`
    : emptyState('No scans yet. Run your first scan to see stats here.',
        '<a class="btn primary" href="#/url">Scan a URL</a>');

  view.innerHTML = `
    <div class="grid cols-4 mb">
      ${stat('Total scans', stats.total, 'All URL + message scans')}
      ${stat('High risk', dist['High Risk Indicators'] || 0, 'Strong indicators found')}
      ${stat('Suspicious', dist['Suspicious'] || 0, 'Some indicators found')}
      ${stat('Low risk', dist['Low Risk Indicators'] || 0, 'Few/no indicators')}
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h2 class="section">Recent scans</h2>
        ${recent}
      </div>
      <div class="card">
        <h2 class="section">Risk distribution</h2>
        ${stats.total === 0
          ? `<p class="muted">No data yet.</p>`
          : cats.map(([label, cls]) => {
              const count = dist[label] || 0;
              const pct = stats.total ? Math.round((count / stats.total) * 100) : 0;
              return `
                <div class="mb">
                  <div class="row space-between"><span>${esc(label)}</span><strong>${count}</strong></div>
                  <div class="meter"><span style="width:${pct}%;background:var(--${cls === 'low' ? 'ok' : cls === 'suspicious' ? 'warn' : cls === 'high' ? 'danger' : 'unknown'})"></span></div>
                </div>`;
            }).join('')}
      </div>
    </div>

    <div class="card mt">
      <h2 class="section">Quick actions &amp; tips</h2>
      <div class="row mb">
        <a class="btn primary" href="#/url">Scan a URL</a>
        <a class="btn" href="#/message">Scan a message</a>
        <a class="btn ghost" href="#/education">Learn the warning signs</a>
      </div>
      <ul class="rec-list">
        <li>Never share passwords or one-time codes in response to a message.</li>
        <li>Type official website addresses yourself instead of clicking links.</li>
        <li>Verify unexpected requests through a channel you already trust.</li>
      </ul>
    </div>

    <div class="disclaimer mt">
      <b>Note:</b> All statistics above come from your actual scans stored locally.
      No live "protection" is running in the background and no threat feed is simulated.
    </div>`;
}

function stat(label, value, hint) {
  return `<div class="card stat">
    <div class="label">${esc(label)}</div>
    <div class="value">${esc(value)}</div>
    <div class="hint">${esc(hint)}</div>
  </div>`;
}

function renderUrlScanner() {
  view.innerHTML = `
    <div class="card">
      <h2 class="section">URL Scanner</h2>
      <p class="muted mb">Paste a link to check it for phishing and scam warning signs.
        The link is only inspected as text — it is never opened or fetched.</p>
      <form id="url-form" novalidate>
        <label class="field" for="url-input">Link (URL)</label>
        <input type="text" id="url-input" name="url" placeholder="example.com/login or https://..."
               autocomplete="off" aria-describedby="url-err" />
        <div class="field-error" id="url-err" role="alert"></div>
        <div class="row space-between mt">
          <label style="font-weight:500;font-size:0.85rem" class="muted">
            <input type="checkbox" id="url-explain" style="width:auto" /> Add AI explanation (if configured)
          </label>
          <button type="submit" class="btn primary" id="url-submit">Analyze link</button>
        </div>
      </form>
    </div>
    <div id="url-result"></div>`;

  const form = document.getElementById('url-form');
  const input = document.getElementById('url-input');
  const errBox = document.getElementById('url-err');
  const resultBox = document.getElementById('url-result');
  const submit = document.getElementById('url-submit');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errBox.classList.remove('show');
    const url = input.value.trim();
    if (!url) {
      errBox.textContent = 'Please enter a link to analyze.';
      errBox.classList.add('show');
      input.focus();
      return;
    }
    submit.disabled = true;
    submit.innerHTML = '<span class="spinner"></span> Analyzing…';
    resultBox.innerHTML = '';
    try {
      const data = await apiFetch('/scans/url', {
        method: 'POST',
        body: JSON.stringify({ url, explain: document.getElementById('url-explain').checked }),
      });
      resultBox.innerHTML = renderResult(data.analysis);
      if (data.analysis.valid) toast('Link analyzed.', 'success');
    } catch (err) {
      toast(err.message, 'error');
      errBox.textContent = err.message;
      errBox.classList.add('show');
    } finally {
      submit.disabled = false;
      submit.textContent = 'Analyze link';
    }
  });
}

function renderMessageScanner() {
  view.innerHTML = `
    <div class="card">
      <h2 class="section">Message Scanner</h2>
      <p class="muted mb">Paste the text of a suspicious SMS, email, or chat message.
        We never ask for passwords, codes, PINs, or payment details — and you shouldn't share them either.</p>
      <form id="msg-form" novalidate>
        <label class="field" for="msg-input">Message text</label>
        <textarea id="msg-input" name="message" placeholder="Paste the message here..." aria-describedby="msg-err"></textarea>
        <div class="field-error" id="msg-err" role="alert"></div>
        <div class="row space-between mt">
          <label style="font-weight:500;font-size:0.85rem" class="muted">
            <input type="checkbox" id="msg-explain" style="width:auto" /> Add AI explanation (if configured)
          </label>
          <button type="submit" class="btn primary" id="msg-submit">Analyze message</button>
        </div>
      </form>
    </div>
    <div id="msg-result"></div>`;

  const form = document.getElementById('msg-form');
  const input = document.getElementById('msg-input');
  const errBox = document.getElementById('msg-err');
  const resultBox = document.getElementById('msg-result');
  const submit = document.getElementById('msg-submit');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errBox.classList.remove('show');
    const message = input.value.trim();
    if (!message) {
      errBox.textContent = 'Please paste a message to analyze.';
      errBox.classList.add('show');
      input.focus();
      return;
    }
    submit.disabled = true;
    submit.innerHTML = '<span class="spinner"></span> Analyzing…';
    resultBox.innerHTML = '';
    try {
      const data = await apiFetch('/scans/message', {
        method: 'POST',
        body: JSON.stringify({ message, explain: document.getElementById('msg-explain').checked }),
      });
      resultBox.innerHTML = renderResult(data.analysis);
      if (data.analysis.valid) toast('Message analyzed.', 'success');
    } catch (err) {
      toast(err.message, 'error');
      errBox.textContent = err.message;
      errBox.classList.add('show');
    } finally {
      submit.disabled = false;
      submit.textContent = 'Analyze message';
    }
  });
}

let historyOffset = 0;
const HISTORY_LIMIT = 10;

async function renderHistory() {
  historyOffset = 0;
  view.innerHTML = `
    <div class="card">
      <div class="row space-between mb">
        <h2 class="section" style="margin:0">Scan History</h2>
        <button class="btn danger sm" id="clear-all">Clear all</button>
      </div>
      <div id="history-body"></div>
      <div class="row space-between mt" id="history-pager"></div>
    </div>`;

  document.getElementById('clear-all').addEventListener('click', async () => {
    const ok = await confirmDialog('Clear all history?',
      'This permanently deletes all stored scan records. This cannot be undone.', 'Clear all');
    if (!ok) return;
    try {
      const r = await apiFetch('/scans', { method: 'DELETE' });
      toast(`Cleared ${r.cleared} record(s).`, 'success');
      loadHistoryPage();
    } catch (err) { toast(err.message, 'error'); }
  });

  await loadHistoryPage();
}

async function loadHistoryPage() {
  const body = document.getElementById('history-body');
  const pager = document.getElementById('history-pager');
  body.innerHTML = '<div class="row" style="padding:20px"><span class="spinner"></span> &nbsp; Loading…</div>';

  const data = await apiFetch(`/scans?limit=${HISTORY_LIMIT}&offset=${historyOffset}`);
  if (data.total === 0) {
    body.innerHTML = emptyState('No scans stored yet.',
      '<a class="btn primary" href="#/url">Run your first scan</a>');
    pager.innerHTML = '';
    return;
  }

  body.innerHTML = `
    <table>
      <thead><tr><th>Type</th><th>Summary</th><th>Risk</th><th>Score</th><th>When</th><th></th></tr></thead>
      <tbody>
        ${data.items.map((s) => `
          <tr data-id="${esc(s.id)}">
            <td>${esc(s.type)}</td>
            <td style="max-width:260px;word-break:break-all">${esc(s.summary || '—')}</td>
            <td>${badge(s.category)}</td>
            <td>${esc(s.score)}</td>
            <td class="faint">${formatDate(s.created_at)}</td>
            <td><button class="btn danger sm" data-del="${esc(s.id)}">Delete</button></td>
          </tr>`).join('')}
      </tbody>
    </table>`;

  body.querySelectorAll('[data-del]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-del');
      const ok = await confirmDialog('Delete this scan?', 'This record will be permanently removed.', 'Delete');
      if (!ok) return;
      try {
        await apiFetch(`/scans/${encodeURIComponent(id)}`, { method: 'DELETE' });
        toast('Scan deleted.', 'success');
        loadHistoryPage();
      } catch (err) { toast(err.message, 'error'); }
    });
  });

  const from = historyOffset + 1;
  const to = Math.min(historyOffset + HISTORY_LIMIT, data.total);
  pager.innerHTML = `
    <span class="faint">Showing ${from}–${to} of ${data.total}</span>
    <span class="row">
      <button class="btn sm" id="prev" ${historyOffset === 0 ? 'disabled' : ''}>Previous</button>
      <button class="btn sm" id="next" ${to >= data.total ? 'disabled' : ''}>Next</button>
    </span>`;
  const prev = document.getElementById('prev');
  const next = document.getElementById('next');
  if (prev) prev.addEventListener('click', () => { historyOffset = Math.max(0, historyOffset - HISTORY_LIMIT); loadHistoryPage(); });
  if (next) next.addEventListener('click', () => { historyOffset += HISTORY_LIMIT; loadHistoryPage(); });
}

function renderEducation() {
  const topics = [
    ['Phishing links', 'Attackers send links that imitate real sites to steal logins. Watch for lookalike domains, "@" in the address, raw IP hosts, and urgent "verify your account" messages.'],
    ['Smishing (SMS scams)', 'Texts claiming failed deliveries, bank alerts, or prizes. They push you to tap a link fast. Banks and couriers do not ask for passwords or codes by text.'],
    ['One-time code theft', 'If someone asks you to read back a verification code, it is almost always fraud. Codes are for you alone — never share them.'],
    ['Payment pressure', 'Requests for gift cards, crypto, or wire transfers, or a "fee to release" money, are classic scam patterns. Legitimate refunds never work this way.'],
    ['Impersonation', 'Messages posing as your bank, a tax office, or a big brand borrow their authority. Verify using official contact details you look up yourself.'],
    ['Lookalike domains', 'paypaI.com (capital i), g00gle.com, or brand names buried in subdomains like apple.com.secure-login.example are designed to fool a quick glance.'],
  ];
  view.innerHTML = `
    <div class="card mb">
      <h2 class="section">Threat Education Center</h2>
      <p class="muted">Understanding the common tricks is the best protection. Here are the patterns this tool looks for.</p>
    </div>
    <div class="grid cols-2">
      ${topics.map(([t, b]) => `<div class="card"><h2 class="section">${esc(t)}</h2><p class="muted">${esc(b)}</p></div>`).join('')}
    </div>
    <div class="disclaimer mt"><b>Remember:</b> no tool catches everything. When something feels off, slow down and verify independently.</div>`;
}

async function renderSettings() {
  const settings = await apiFetch('/settings');
  const store = settings.store_message_content === 'true';
  view.innerHTML = `
    <div class="card">
      <h2 class="section">Security &amp; Privacy Settings</h2>
      <form id="settings-form">
        <div class="finding" style="background:transparent">
          <div>
            <div class="ftitle">Store scanned message content</div>
            <div class="fexp">Off by default (data minimization). When off, only risk metadata is kept — never the message text.</div>
          </div>
          <label style="margin-left:auto">
            <input type="checkbox" id="store-content" ${store ? 'checked' : ''} style="width:auto" />
          </label>
        </div>

        <label class="field mt" for="retention">History retention (days)</label>
        <input type="number" id="retention" min="0" max="3650" value="${esc(settings.history_retention_days || '0')}" />
        <p class="faint">0 means keep until you delete manually. Older records are purged automatically on the next scan.</p>

        <button type="submit" class="btn primary mt">Save settings</button>
      </form>
    </div>
    <div class="disclaimer mt">
      <b>Privacy:</b> turning message storage off also purges any previously stored message content.
    </div>`;

  document.getElementById('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await apiFetch('/settings', {
        method: 'PATCH',
        body: JSON.stringify({
          store_message_content: document.getElementById('store-content').checked ? 'true' : 'false',
          history_retention_days: String(parseInt(document.getElementById('retention').value, 10) || 0),
        }),
      });
      toast('Settings saved.', 'success');
    } catch (err) { toast(err.message, 'error'); }
  });
}

function renderAccount() {
  view.innerHTML = `
    <div class="card">
      <h2 class="section">Account</h2>
      <p class="muted">This release runs in <strong>local, anonymous mode</strong>. No account or login is required,
        and no personal profile is created.</p>
      <div class="disclaimer mt">
        <b>Why no login yet?</b> Accounts were intentionally left out of this first release so that no credentials
        or personal data are collected until authentication can be implemented to a production-grade standard
        (secure password hashing, sessions, CSRF protection, and per-user data isolation).
      </div>
    </div>`;
}

function renderPrivacy() {
  view.innerHTML = `
    <div class="card">
      <h2 class="section">Privacy Policy</h2>
      <p class="muted">Plain-language summary of how AI Shield Protector handles your data.</p>
      <ul class="rec-list mt">
        <li><strong>Local first:</strong> scans run on your own server instance and are stored in a local SQLite database.</li>
        <li><strong>Data minimization:</strong> message content is <em>not</em> stored by default — only risk metadata.</li>
        <li><strong>No link fetching:</strong> submitted URLs are inspected as text; they are never opened or requested.</li>
        <li><strong>Optional AI:</strong> AI explanations are off unless you configure a server-side key. Only a short summary of indicators is sent, never raw credentials.</li>
        <li><strong>You are in control:</strong> you can delete any scan or clear all history at any time from the History page.</li>
        <li><strong>No secrets logged:</strong> the server avoids logging message contents or API keys.</li>
      </ul>
    </div>`;
}

function renderAbout() {
  view.innerHTML = `
    <div class="card mb">
      <h2 class="section">About AI Shield Protector</h2>
      <p class="muted">A defensive cybersecurity helper that analyzes links and messages for common phishing and scam
        indicators, explains what it finds, and suggests safe next steps.</p>
    </div>
    <div class="grid cols-2">
      <div class="card">
        <h2 class="section">What it does</h2>
        <ul class="rec-list">
          <li>Heuristic URL risk analysis (text only, no fetching).</li>
          <li>Rule-based scam-message analysis.</li>
          <li>Local scan history with privacy controls.</li>
          <li>Optional AI explanations and reputation lookups (off by default).</li>
        </ul>
      </div>
      <div class="card">
        <h2 class="section">What it does NOT do</h2>
        <ul class="rec-list">
          <li>Guarantee a link or message is safe or malicious.</li>
          <li>Detect every possible threat.</li>
          <li>Open links, run scripts, or download files.</li>
          <li>Provide live, real-time protection or a simulated threat feed.</li>
        </ul>
      </div>
    </div>
    <div class="card mt">
      <h2 class="section">API endpoints</h2>
      <ul class="rec-list">
        <li><code>GET /api/v1/health</code></li>
        <li><code>POST /api/v1/scans/url</code></li>
        <li><code>POST /api/v1/scans/message</code></li>
        <li><code>GET /api/v1/scans</code> · <code>GET /api/v1/scans/:id</code> · <code>DELETE /api/v1/scans/:id</code></li>
        <li><code>GET /api/v1/stats</code></li>
        <li><code>GET /api/v1/settings</code> · <code>PATCH /api/v1/settings</code></li>
      </ul>
    </div>`;
}

/* ---------------- Chrome: theme, sidebar, health ---------------- */
function initTheme() {
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  document.getElementById('theme-toggle').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
  });
}

function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('scrim').classList.remove('hidden');
  document.getElementById('hamburger').setAttribute('aria-expanded', 'true');
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('scrim').classList.add('hidden');
  document.getElementById('hamburger').setAttribute('aria-expanded', 'false');
}
function initSidebar() {
  document.getElementById('hamburger').addEventListener('click', () => {
    const open = document.getElementById('sidebar').classList.contains('open');
    open ? closeSidebar() : openSidebar();
  });
  document.getElementById('scrim').addEventListener('click', closeSidebar);
}

async function initHealth() {
  const badgeEl = document.getElementById('health-badge');
  try {
    const h = await apiFetch('/health');
    badgeEl.className = 'badge low';
    badgeEl.textContent = h.integrations.ai ? 'online · AI on' : 'online';
    badgeEl.title = `v${h.version} · AI ${h.integrations.ai ? 'on' : 'off'} · Threat intel ${h.integrations.threatIntel ? 'on' : 'off'}`;
  } catch {
    badgeEl.className = 'badge high';
    badgeEl.textContent = 'offline';
  }
}

/* ---------------- Boot ---------------- */
initTheme();
initSidebar();
initHealth();
if (!location.hash) location.hash = '#/';
router();
