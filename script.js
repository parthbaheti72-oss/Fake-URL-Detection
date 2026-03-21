const API = "http://localhost:5000";

// ═══════════════════════════════════════════
//  TAB NAVIGATION
// ═══════════════════════════════════════════

function switchTab(tab) {
  const panelMap = { single: 'panelSingle', bulk: 'panelBulk' };
  const tabMap   = { single: 'tabSingle',   bulk: 'tabBulk' };

  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

  document.getElementById(panelMap[tab]).classList.add('active');
  document.getElementById(tabMap[tab]).classList.add('active');
}


// ═══════════════════════════════════════════
//  TAB 1: SINGLE URL ANALYSIS
// ═══════════════════════════════════════════

async function analyzeURL() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) { alert("Please enter a URL!"); return; }

  const btn = document.getElementById("analyzeBtn");
  btn.disabled = true;
  btn.textContent = "Analyzing...";

  try {
    const res = await fetch(`${API}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    renderResult(data);
    loadHistory();
  } catch {
    alert("Backend not reachable. Run: python app.py");
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze";
  }
}

function renderResult(data) {
  const card = document.getElementById("resultCard");
  card.style.display = "block";

  const icons  = { "SAFE": "✅", "SUSPICIOUS": "⚠️", "FAKE / MALICIOUS": "🚨" };
  const colors = { "SAFE": "#10b981", "SUSPICIOUS": "#f59e0b", "FAKE / MALICIOUS": "#ef4444" };
  const color  = colors[data.verdict] || "#ef4444";

  document.getElementById("verdictIcon").textContent = icons[data.verdict] || "";
  document.getElementById("verdictText").textContent = data.verdict;
  document.getElementById("verdictText").style.color = color;
  document.getElementById("verdictSub").textContent  = data.domain;
  document.getElementById("scoreNum").textContent    = data.score;

  const circle = document.getElementById("scoreCircle");
  circle.style.borderColor = color;
  circle.style.color = color;

  // Visual Comparison
  const compSec  = document.getElementById("comparisonSection");
  const compCards = document.getElementById("comparisonCards");

  if (data.typo_matches && data.typo_matches.length > 0) {
    compSec.style.display = "block";
    compCards.innerHTML = data.typo_matches.map(match => {
      const sim = match.similarity;
      const barColor = sim >= 85 ? "#ef4444" : sim >= 70 ? "#f59e0b" : "#10b981";
      return `
        <div class="comparison-card">
          <div class="comparison-row">
            <div class="domain-box">
              <div class="domain-label">Entered URL</div>
              <div class="domain-value domain-fake">${data.domain}</div>
            </div>
            <div class="vs-label">VS</div>
            <div class="domain-box">
              <div class="domain-label">Legitimate Domain</div>
              <div class="domain-value domain-real">${match.legit_domain}</div>
            </div>
          </div>
          <div class="sim-bar-wrap">
            <div class="sim-bar-label">
              <span>Similarity Score</span>
              <span style="color:${barColor};font-weight:700">${sim}%</span>
            </div>
            <div class="sim-bar-bg">
              <div class="sim-bar-fill" style="width:0%;background:${barColor}" data-width="${sim}"></div>
            </div>
          </div>
          <span class="attack-tag">${match.attack_type}</span>
          ${match.leet_normalized ? `<span class="attack-tag" style="margin-left:6px">Decoded: ${match.leet_normalized}</span>` : ""}
        </div>
      `;
    }).join("");

    setTimeout(() => {
      document.querySelectorAll(".sim-bar-fill").forEach(bar => {
        bar.style.width = bar.dataset.width + "%";
      });
    }, 100);
  } else {
    compSec.style.display = "none";
  }

  // Attack Banner
  const banner = document.getElementById("attackBanner");
  if (data.typo_matches && data.typo_matches.length > 0) {
    banner.style.display = "block";
    const top = data.typo_matches[0];
    const attackIcons = {
      "Leet Speak Attack": "", "Typosquatting": "",
      "Character Substitution": "", "Character Addition/Deletion": "",
      "Subdomain Impersonation": "", "Brand in Subdomain": ""
    };
    document.getElementById("attackIcon").textContent  = attackIcons[top.attack_type] || "";
    document.getElementById("attackTitle").textContent = top.attack_type + " Detected";
    document.getElementById("attackDesc").textContent  =
      `This domain mimics '${top.legit_domain}' with ${top.similarity}% similarity. Users may be tricked into thinking it's the real site.`;
  } else if (data.brand_subdomain) {
    banner.style.display = "block";
    document.getElementById("attackIcon").textContent  = "";
    document.getElementById("attackTitle").textContent = "Brand Impersonation via Subdomain";
    document.getElementById("attackDesc").textContent  =
      `'${data.brand_subdomain.brand}' brand name placed in subdomain. Real domain: ${data.brand_subdomain.legit_domain}`;
  } else {
    banner.style.display = "none";
  }

  // Flags
  const flagsList = document.getElementById("flagsList");
  flagsList.innerHTML = (!data.flags || data.flags.length === 0)
    ? `<div class="no-flags">No threats detected. This URL appears legitimate.</div>`
    : data.flags.map(f => `<div class="flag-item">${f}</div>`).join("");

  // Stats
  const maxSim = data.typo_matches?.length > 0
    ? Math.max(...data.typo_matches.map(m => m.similarity)) + "%" : "N/A";

  document.getElementById("statChecks").textContent     = data.flags_triggered;
  document.getElementById("statSimilarity").textContent = maxSim;
  document.getElementById("statBrands").textContent     = "30";

  renderAPIResults(data);
  card.scrollIntoView({ behavior: "smooth" });
}

function renderAPIResults(data) {
  const existing = document.getElementById("apiResultsSection");
  if (existing) existing.remove();

  const vt = data.vt || {};

  const vtColor  = vt.error ? "#475569" : vt.flagged ? "#ef4444" : "#10b981";
  const vtStatus = vt.error ? "Unavailable" : vt.flagged ? "FLAGGED" : "Clean";
  const vtDetail = vt.error
    ? `<span style="color:#475569;font-size:0.75rem">${vt.error}</span>`
    : `<div class="vt-bars">
        <div class="vt-bar-item"><span class="vt-dot" style="background:#ef4444"></span><span>Malicious: <b style="color:#fca5a5">${vt.malicious}</b></span></div>
        <div class="vt-bar-item"><span class="vt-dot" style="background:#f59e0b"></span><span>Suspicious: <b style="color:#fcd34d">${vt.suspicious}</b></span></div>
        <div class="vt-bar-item"><span class="vt-dot" style="background:#10b981"></span><span>Harmless: <b style="color:#6ee7b7">${vt.harmless}</b></span></div>
        <div class="vt-bar-item"><span style="color:#475569;font-size:0.72rem">Total engines: ${vt.total_engines}</span></div>
      </div>`;

  const section = document.createElement("div");
  section.id = "apiResultsSection";
  section.innerHTML = `
    <div class="section-title" style="margin-top:20px">Intelligence Sources</div>
    <div class="api-grid api-grid-2">
      <div class="api-card">
        <div class="api-header"><span class="api-icon"></span>
          <div><div class="api-name">Heuristic Engine</div>
          <div class="api-status" style="color:#a78bfa">Score: ${data.heuristic_score ?? "—"}/100</div></div>
        </div>
        <div style="font-size:0.75rem;color:#475569">Typosquatting · Leet speak · Brand impersonation · Keyword analysis</div>
      </div>
      <div class="api-card">
        <div class="api-header"><span class="api-icon"></span>
          <div><div class="api-name">VirusTotal</div>
          <div class="api-status" style="color:${vtColor}">${vtStatus}</div></div>
        </div>
        ${vtDetail}
      </div>
    </div>
    <div class="weight-row">
      <span class="weight-pill" style="background:rgba(167,139,250,0.1);color:#a78bfa;border:1px solid rgba(167,139,250,0.2)">Heuristics 60%</span>
      <span class="weight-pill" style="background:rgba(251,146,60,0.1);color:#fb923c;border:1px solid rgba(251,146,60,0.2)">VirusTotal 40%</span>
    </div>`;

  document.getElementById("flagsSection").parentNode.insertBefore(
    section, document.getElementById("flagsSection")
  );
}

async function loadHistory() {
  try {
    const res     = await fetch(`${API}/history`);
    const history = await res.json();
    const el      = document.getElementById("historyList");

    if (history.length === 0) {
      el.innerHTML = `<p class="empty">No scans yet. Analyze a URL above!</p>`;
      return;
    }

    const c  = { "SAFE": "#10b981", "SUSPICIOUS": "#f59e0b", "FAKE / MALICIOUS": "#ef4444" };
    const bg = { "SAFE": "rgba(16,185,129,0.1)", "SUSPICIOUS": "rgba(245,158,11,0.1)", "FAKE / MALICIOUS": "rgba(239,68,68,0.1)" };

    el.innerHTML = history.map(item => `
      <div class="history-item">
        <span class="history-url" title="${item.url}">${item.url}</span>
        <span class="history-badge" style="color:${c[item.verdict]};background:${bg[item.verdict]}">
          ${item.verdict} (${item.score})
        </span>
      </div>
    `).join("");
  } catch { /* silent fail */ }
}

function fillURL(url) { document.getElementById("urlInput").value = url; }


// ═══════════════════════════════════════════
//  TAB 2: BULK CSV SCANNER
// ═══════════════════════════════════════════

let bulkResultsData = [];

function handleCSVUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    const text = e.target.result;
    const lines = text.split(/[\r\n]+/).filter(Boolean);
    const extracted = [];

    lines.forEach(line => {
      line.split(",").forEach(cell => {
        const c = cell.trim().replace(/^["']|["']$/g, "");
        if (c && !["url","urls","link","links","website"].includes(c.toLowerCase())
            && c.includes(".") && c.length > 4) {
          extracted.push(c);
        }
      });
    });

    document.getElementById("bulkTextarea").value = extracted.join("\n");
    showBulkError("");
  };
  reader.readAsText(file);
  event.target.value = "";
}

function showBulkError(msg) {
  const el = document.getElementById("bulkError");
  if (msg) {
    el.textContent = " " + msg;
    el.style.display = "block";
  } else {
    el.style.display = "none";
  }
}

async function startBulkScan() {
  const raw = document.getElementById("bulkTextarea").value;
  const urls = raw.split("\n").map(u => u.trim()).filter(u => u && u.includes(".") && u.length > 4);

  if (urls.length === 0) { showBulkError("Enter at least one valid URL."); return; }
  if (urls.length > 50)  { showBulkError("Maximum 50 URLs allowed. You entered " + urls.length + "."); return; }

  showBulkError("");
  const btn = document.getElementById("bulkScanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning " + urls.length + " URLs...";

  const progressWrap = document.getElementById("bulkProgress");
  const progressBar  = document.getElementById("bulkProgressBar");
  const progressText = document.getElementById("bulkProgressText");
  progressWrap.style.display = "block";
  progressText.style.display = "block";
  progressBar.style.width = "0%";

  let progress = 0;
  const progressInterval = setInterval(() => {
    progress = Math.min(progress + Math.random() * 12, 90);
    progressBar.style.width = progress + "%";
    progressText.textContent = `Analyzing URLs... ${Math.round(progress)}%`;
  }, 500);

  try {
    const res = await fetch(`${API}/bulk-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls })
    });
    const data = await res.json();

    if (data.error) {
      showBulkError(data.error);
      return;
    }

    clearInterval(progressInterval);
    progressBar.style.width = "100%";
    progressText.textContent = "Scan complete!";
    setTimeout(() => {
      progressWrap.style.display = "none";
      progressText.style.display = "none";
    }, 1500);

    bulkResultsData = data.results;

    const sum = data.summary;
    document.getElementById("sumTotal").textContent      = sum.total;
    document.getElementById("sumSafe").textContent       = sum.safe;
    document.getElementById("sumSuspicious").textContent = sum.suspicious;
    document.getElementById("sumMalicious").textContent  = sum.malicious;
    document.getElementById("bulkSummary").style.display = "block";

    renderBulkTable(data.results);

  } catch (err) {
    clearInterval(progressInterval);
    showBulkError("Could not connect to URLGuard API. Make sure it's running on localhost:5000");
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan All URLs";
  }
}

function renderBulkTable(results) {
  const tbody = document.getElementById("bulkTableBody");
  const verdictColors = {
    "SAFE": "#10b981", "SUSPICIOUS": "#f59e0b", "FAKE / MALICIOUS": "#ef4444", "ERROR": "#6b7280"
  };
  const verdictClasses = {
    "SAFE": "vb-safe", "SUSPICIOUS": "vb-suspicious", "FAKE / MALICIOUS": "vb-malicious", "ERROR": "vb-error"
  };

  tbody.innerHTML = results.map((r, i) => {
    const color = verdictColors[r.verdict] || "#6b7280";
    const cls   = verdictClasses[r.verdict] || "vb-error";
    const flags = (r.flags || []).slice(0, 2).join(", ");
    const extra = (r.flags || []).length > 2 ? ` +${r.flags.length - 2} more` : "";

    return `
      <tr>
        <td style="color:#94a3b8;font-weight:500">${i+1}</td>
        <td class="url-cell" title="${r.url}">${r.url}</td>
        <td><span class="score-badge" style="color:${color};background:${color}15">${r.score}/100</span></td>
        <td><span class="verdict-badge ${cls}">${r.verdict}</span></td>
        <td class="flags-cell">${flags ? flags + extra : "—"}</td>
      </tr>
    `;
  }).join("");

  document.getElementById("bulkResults").style.display = "block";
  document.getElementById("bulkResults").scrollIntoView({ behavior: "smooth" });
}

function exportBulkCSV() {
  if (!bulkResultsData || bulkResultsData.length === 0) return;

  let csv = "URL,Domain,Risk Score,Verdict,Heuristic Score,Flags Triggered,Flags,VT Malicious,VT Suspicious,Timestamp\n";

  bulkResultsData.forEach(r => {
    const flags = (r.flags || []).join(" | ").replace(/,/g, ";");
    csv += `"${r.url}","${r.domain || ""}",${r.score},"${r.verdict}",${r.heuristic_score || 0},${r.flags_triggered || 0},"${flags}",${r.vt?.malicious || 0},${r.vt?.suspicious || 0},"${r.timestamp || ""}"\n`;
  });

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "urlguard_bulk_report_" + Date.now() + ".csv";
  link.click();
}

function clearBulkResults() {
  bulkResultsData = [];
  document.getElementById("bulkSummary").style.display  = "none";
  document.getElementById("bulkResults").style.display   = "none";
  document.getElementById("bulkTableBody").innerHTML     = "";
  document.getElementById("bulkTextarea").value          = "";
}


// ═══════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("urlInput").addEventListener("keydown", e => {
    if (e.key === "Enter") analyzeURL();
  });
  loadHistory();
});
