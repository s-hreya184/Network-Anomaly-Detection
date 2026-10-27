// CyberGuard XAI-NIDS — Frontend Application Logic

let attackChartInstance = null;
let protocolChartInstance = null;
let attributionChartInstance = null;
let currentBatchData = null;
let lastFlowResult = null;
let availablePresets = {};
let chatHistory = [];

document.addEventListener("DOMContentLoaded", () => {
  initNav();
  loadPresets();
  setupSingleFlowForm();
  setupBatchUpload();
  setupWhatIfSimulator();
  setupChatCopilot();
  loadAlerts();
});

// --- NAVIGATION ---
function initNav() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = tab.dataset.target;
      switchTab(targetId);
    });
  });
}

function switchTab(targetId) {
  document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
  
  const activeTab = document.querySelector(`.nav-tab[data-target="${targetId}"]`);
  const activeContent = document.getElementById(targetId);
  
  if (activeTab) activeTab.classList.add("active");
  if (activeContent) activeContent.classList.add("active");
}

// --- PRESETS ---
async function loadPresets() {
  try {
    const res = await fetch("/api/presets");
    availablePresets = await res.json();
    const container = document.getElementById("presets-container");
    if (!container) return;
    
    container.innerHTML = `<span style="font-size: 0.76rem; color: #1E3A8A; font-weight: 700; text-transform: uppercase; margin-right: 4px;">1-Click Scenarios:</span>`;
    
    for (const [key, preset] of Object.entries(availablePresets)) {
      const chip = document.createElement("button");
      chip.className = "preset-chip";
      chip.type = "button";
      chip.dataset.preset = key;
      chip.textContent = preset.title;
      chip.addEventListener("click", () => applyPreset(key));
      container.appendChild(chip);
    }
  } catch (err) {
    console.error("Failed to load presets:", err);
  }
}

function applyPreset(presetKey) {
  const preset = availablePresets[presetKey];
  if (!preset) return;
  
  // Highlight active preset chip
  document.querySelectorAll(".preset-chip").forEach(c => {
    c.classList.toggle("active-preset", c.dataset.preset === presetKey);
  });
  
  for (const [feat, val] of Object.entries(preset.data)) {
    const input = document.getElementById(`flow_${feat}`);
    if (input) input.value = val;
  }
  showToast(`Loaded scenario: ${preset.title}`);
}

function resetFlowForm() {
  const form = document.getElementById("single-flow-form");
  if (!form) return;
  
  document.querySelectorAll(".preset-chip").forEach(c => c.classList.remove("active-preset"));
  
  document.getElementById("flow_duration").value = "0";
  document.getElementById("flow_protocol").value = "TCP";
  document.getElementById("flow_service").value = "HTTP";
  document.getElementById("flow_tcp_flags").value = "ACK";
  document.getElementById("flow_src_bytes").value = "0";
  document.getElementById("flow_dst_bytes").value = "0";
  document.getElementById("flow_src_packets").value = "0";
  document.getElementById("flow_dst_packets").value = "0";
  document.getElementById("flow_src_dst_byte_ratio").value = "0";
  document.getElementById("flow_packets_per_second").value = "0";
  document.getElementById("flow_bytes_per_second").value = "0";
  
  const container = document.getElementById("single-result-container");
  if (container) container.innerHTML = "";
  
  showToast("Reset form inputs to baseline defaults");
}

// --- SINGLE FLOW PREDICTION WITH XAI & COUNTERFACTUALS ---
function setupSingleFlowForm() {
  const form = document.getElementById("single-flow-form");
  if (!form) return;
  
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = form.querySelector("button[type='submit']");
    btn.disabled = true;
    btn.textContent = "Analyzing & Explaining Flow...";
    
    const payload = {
      duration: parseFloat(document.getElementById("flow_duration").value) || 0.0,
      protocol: document.getElementById("flow_protocol").value,
      service: document.getElementById("flow_service").value,
      src_bytes: parseFloat(document.getElementById("flow_src_bytes").value) || 0.0,
      dst_bytes: parseFloat(document.getElementById("flow_dst_bytes").value) || 0.0,
      src_packets: parseFloat(document.getElementById("flow_src_packets").value) || 0.0,
      dst_packets: parseFloat(document.getElementById("flow_dst_packets").value) || 0.0,
      src_dst_byte_ratio: parseFloat(document.getElementById("flow_src_dst_byte_ratio").value) || 0.0,
      packets_per_second: parseFloat(document.getElementById("flow_packets_per_second").value) || 0.0,
      bytes_per_second: parseFloat(document.getElementById("flow_bytes_per_second").value) || 0.0,
      tcp_flags: document.getElementById("flow_tcp_flags").value
    };
    
    try {
      const res = await fetch("/api/predict?include_xai=true", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Prediction request failed");
      }
      
      const result = await res.json();
      lastFlowResult = result;
      renderSingleResult(result);
      loadAlerts(); // Refresh alerts list
      showToast("Prediction and XAI Attribution computed");
    } catch (err) {
      alert(`Detection Error: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.textContent = "Classify & Explain Flow \u2192";
    }
  });
}

function renderSingleResult(result) {
  const container = document.getElementById("single-result-container");
  if (!container) return;
  
  const isAnomaly = result.is_anomaly;
  const boxClass = isAnomaly ? "anomaly" : "normal";
  const sevClass = isAnomaly ? result.severity.toLowerCase() : "normal";
  const exp = result.explanation;
  const cf = result.counterfactual;
  
  let cfModificationsHtml = "";
  if (cf && cf.modifications_required) {
    const mods = Object.entries(cf.modifications_required);
    if (mods.length > 0) {
      cfModificationsHtml = mods.map(([k, v]) => `
        <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #E2E8F0; font-size: 0.85rem;">
          <span style="color: #64748B;">${k}:</span>
          <span style="color: #0F172A; font-family: 'JetBrains Mono', monospace;"><b>${v.original}</b> &rarr; <b style="color: #1E3A8A;">${v.counterfactual}</b> <span style="color: #64748B; font-size: 0.78rem;">(${v.delta})</span></span>
        </div>
      `).join("");
    } else {
      cfModificationsHtml = `<div style="color: #64748B; font-size: 0.85rem;">No modifications required; flow is already compliant.</div>`;
    }
  }

  container.innerHTML = `
    <div class="result-box ${boxClass}">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
        <div>
          <span style="font-size: 0.78rem; font-weight: 700; letter-spacing: 0.1em; color: ${isAnomaly ? 'var(--color-rose)' : 'var(--color-emerald)'}; text-transform: uppercase;">
            ${isAnomaly ? 'ANOMALY / THREAT DETECTED' : 'BENIGN / NORMAL TRAFFIC'}
          </span>
          <h2 style="font-family: 'Space Grotesk', sans-serif; font-size: 2.5rem; font-weight: 700; color: #0F172A; margin: 4px 0 10px 0;">
            ${result.prediction}
          </h2>
          <span class="badge badge-${sevClass}">${result.severity} SEVERITY</span>
        </div>
        <div style="text-align: right;">
          <div style="font-size: 0.76rem; color: #64748B; text-transform: uppercase; font-weight: 600;">Model Confidence</div>
          <div style="font-family: 'Space Grotesk', sans-serif; font-size: 2.2rem; font-weight: 700; color: #0F172A;">
            ${result.confidence_pct}
          </div>
          <div style="font-size: 0.75rem; color: #64748B;">Analyzed at ${result.timestamp}</div>
        </div>
      </div>
      
      <!-- Natural Language Rationale -->
      ${exp ? `
        <div style="background: rgba(30, 58, 138, 0.05); border-left: 3px solid #1E3A8A; padding: 14px 18px; border-radius: 6px; margin: 18px 0; font-size: 0.92rem; color: #1E293B; line-height: 1.6;">
          <b style="color: #1E3A8A; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 4px;">Explainable Decision Rationale:</b>
          ${exp.natural_language_rationale}
        </div>
      ` : ''}

      <!-- Dual Engine Verification: Supervised RF vs Unsupervised iForest -->
      ${result.unsupervised && result.unsupervised.active ? `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 18px;">
          <div style="background: #FFFFFF; border: 1px solid #CBD5E1; padding: 14px 16px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <span style="font-size: 0.72rem; font-weight: 700; color: #1E3A8A; text-transform: uppercase; letter-spacing: 0.05em;">Supervised Engine (Random Forest)</span>
              <span class="badge badge-low" style="font-size: 0.68rem;">Multi-Class</span>
            </div>
            <div style="font-size: 1.15rem; font-weight: 700; color: #0F172A;">
              ${result.prediction} <span style="font-size: 0.85rem; font-weight: 500; color: #64748B;">(${result.confidence_pct} conf)</span>
            </div>
            <div style="font-size: 0.78rem; color: #64748B; margin-top: 4px;">Known signature classification from 100 decision trees.</div>
          </div>

          <div style="background: ${result.unsupervised.is_anomaly ? '#FEF2F2' : '#F0FDF4'}; border: 1px solid ${result.unsupervised.is_anomaly ? '#FECACA' : '#BBF7D0'}; padding: 14px 16px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <span style="font-size: 0.72rem; font-weight: 700; color: ${result.unsupervised.is_anomaly ? '#DC2626' : '#059669'}; text-transform: uppercase; letter-spacing: 0.05em;">Unsupervised Engine (Isolation Forest)</span>
              <span class="badge" style="background: ${result.unsupervised.is_anomaly ? '#FEE2E2; color: #991B1B' : '#D1FAE5; color: #065F46'}; font-size: 0.68rem;">Zero Labels</span>
            </div>
            <div style="font-size: 1.15rem; font-weight: 700; color: #0F172A;">
              ${result.unsupervised.is_anomaly ? 'Outlier / Anomaly Flagged' : 'Normal Baseline Profile'} 
              <span style="font-size: 0.82rem; font-weight: 500; color: #64748B;">(Score: ${result.unsupervised.anomaly_score})</span>
            </div>
            <div style="font-size: 0.78rem; color: #475569; margin-top: 4px;">${result.unsupervised.interpretation}</div>
          </div>
        </div>
      ` : ''}

      <!-- Telemetry Overview -->
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 20px; background: #F8FAFC; padding: 18px; border-radius: 8px; border: 1px solid #E2E8F0;">
        <div><span style="color:#64748B; font-size:0.75rem;">PROTOCOL / SERVICE</span><br><b style="color:#0F172A;">${result.traffic_profile.protocol} / ${result.traffic_profile.service}</b></div>
        <div><span style="color:#64748B; font-size:0.75rem;">PACKETS / SEC</span><br><b style="color:#0F172A;">${result.traffic_profile.packets_per_second.toLocaleString()} P/s</b></div>
        <div><span style="color:#64748B; font-size:0.75rem;">BYTES / SEC</span><br><b style="color:#0F172A;">${result.traffic_profile.bytes_per_second.toLocaleString()} B/s</b></div>
        <div><span style="color:#64748B; font-size:0.75rem;">SRC/DST RATIO</span><br><b style="color:#0F172A;">${result.traffic_profile.src_dst_byte_ratio}</b></div>
      </div>

      <!-- XAI Feature Attribution & Counterfactual Columns -->
      <div style="display: grid; grid-template-columns: 1.2fr 1fr; gap: 20px; margin-top: 24px;">
        <!-- Feature Attribution Chart -->
        <div class="card" style="margin-bottom: 0; background: #FFFFFF;">
          <h4 style="font-size: 0.95rem; color: #0F172A; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em;">Local Feature Attribution</h4>
          <p style="font-size: 0.78rem; color: #64748B; margin-bottom: 12px;">Marginal contribution of flow features toward this decision.</p>
          <div style="height: 240px;">
            <canvas id="attributionChart"></canvas>
          </div>
        </div>

        <!-- Counterfactual & Evasion Robustness -->
        <div class="card" style="margin-bottom: 0; background: #FFFFFF;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <h4 style="font-size: 0.95rem; color: #0F172A; text-transform: uppercase; letter-spacing: 0.04em;">Counterfactual Robustness</h4>
            <span class="badge ${cf && cf.evasion_robustness_margin < 30 ? 'badge-critical' : 'badge-low'}" style="font-size: 0.7rem;">
              ${cf ? cf.evasion_risk_level : 'Evaluated'}
            </span>
          </div>
          <p style="font-size: 0.78rem; color: #64748B; margin-bottom: 14px;">Minimum parameter delta to transition classification to <b>${cf ? cf.target_prediction : 'Normal'}</b>.</p>
          
          <div style="margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: #64748B; margin-bottom: 4px;">
              <span>Adversarial Evasion Distance Margin:</span>
              <b style="color: #0F172A;">${cf ? cf.evasion_robustness_margin : 0}/100</b>
            </div>
            <div style="background: rgba(30,58,138,0.1); height: 6px; border-radius: 3px; overflow: hidden;">
              <div style="width: ${cf ? cf.evasion_robustness_margin : 0}%; height: 100%; background: ${cf && cf.evasion_robustness_margin < 30 ? 'var(--color-rose)' : '#1E3A8A'};"></div>
            </div>
          </div>

          <div>
            <span style="font-size: 0.75rem; color: #64748B; font-weight: 600; text-transform: uppercase; display: block; margin-bottom: 8px;">Minimal Perturbation Trajectory:</span>
            ${cfModificationsHtml}
          </div>
        </div>
      </div>

      <!-- Action Button to consult AI Copilot -->
      <div style="margin-top: 20px; text-align: right;">
        <button class="btn-primary" onclick="consultCopilotWithCurrentFlow()">
          Ask AI SOC Copilot About This Threat &rarr;
        </button>
      </div>
    </div>
  `;

  if (exp && exp.attributions) {
    setTimeout(() => renderAttributionChart(exp.attributions), 50);
  }
}

function consultCopilotWithCurrentFlow() {
  switchTab("tab-copilot");
  if (lastFlowResult) {
    sendChatMessage(`Please analyze the current flow classified as ${lastFlowResult.prediction} (${lastFlowResult.severity} severity) and recommend mitigation steps.`);
  }
}

function renderAttributionChart(attributions) {
  const ctx = document.getElementById("attributionChart");
  if (!ctx) return;
  if (attributionChartInstance) attributionChartInstance.destroy();
  
  const sorted = Object.entries(attributions).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
  const labels = sorted.map(s => s[0]);
  const values = sorted.map(s => s[1]);
  const colors = values.map(v => v >= 0 ? "rgba(244, 63, 94, 0.85)" : "rgba(6, 182, 212, 0.85)");

  attributionChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Attribution Impact (%)",
        data: values,
        backgroundColor: colors,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (item) => ` Attribution: ${item.raw > 0 ? '+' : ''}${item.raw}% towards anomaly`
          }
        }
      },
      scales: {
        x: {
          ticks: { color: "#94A3B8", font: { size: 10 } },
          grid: { color: "rgba(255,255,255,0.05)" }
        },
        y: {
          ticks: { color: "#E2E8F0", font: { size: 10 } },
          grid: { display: false }
        }
      }
    }
  });
}

// --- AI SOC COPILOT (GEMINI INTEGRATION) ---
function setupChatCopilot() {
  const form = document.getElementById("chat-form");
  if (!form) return;
  
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = document.getElementById("chat-input");
    const text = input.value.trim();
    if (text) {
      sendChatMessage(text);
      input.value = "";
    }
  });
}

function sendQuickPrompt(promptText) {
  sendChatMessage(promptText);
}

async function sendChatMessage(message) {
  const messagesContainer = document.getElementById("chat-messages");
  if (!messagesContainer) return;
  
  // Append user bubble
  const userBubble = document.createElement("div");
  userBubble.className = "chat-bubble user";
  userBubble.textContent = message;
  messagesContainer.appendChild(userBubble);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
  
  // Append typing indicator
  const typingBubble = document.createElement("div");
  typingBubble.className = "chat-bubble bot";
  typingBubble.id = "chat-typing";
  typingBubble.innerHTML = `<span style="color: #94A3B8; font-style: italic;">CyberGuard Copilot is analyzing telemetry...</span>`;
  messagesContainer.appendChild(typingBubble);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
  
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message,
        flow_context: lastFlowResult,
        history: chatHistory
      })
    });
    
    if (!res.ok) {
      throw new Error(`Copilot response error: ${res.statusText}`);
    }
    
    const data = await res.json();
    
    // Remove typing bubble
    const typing = document.getElementById("chat-typing");
    if (typing) typing.remove();
    
    // Add bot bubble
    const botBubble = document.createElement("div");
    botBubble.className = "chat-bubble bot";
    
    const formattedReply = formatMarkdownSimple(data.reply);
    botBubble.innerHTML = `
      <div style="font-size: 0.72rem; color: var(--color-cyan); font-weight: 700; text-transform: uppercase; margin-bottom: 6px;">
        ${data.provider}
      </div>
      <div>${formattedReply}</div>
    `;
    messagesContainer.appendChild(botBubble);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    // Track history
    chatHistory.push({ role: "user", content: message });
    chatHistory.push({ role: "model", content: data.reply });
    
  } catch (err) {
    const typing = document.getElementById("chat-typing");
    if (typing) typing.remove();
    
    const errBubble = document.createElement("div");
    errBubble.className = "chat-bubble bot";
    errBubble.innerHTML = `<span style="color: var(--color-rose);">Error communicating with Copilot: ${err.message}</span>`;
    messagesContainer.appendChild(errBubble);
  }
}

function formatMarkdownSimple(text) {
  if (!text) return "";
  
  // Format code blocks
  let html = text.replace(/```([\s\S]*?)```/g, (match, code) => {
    return `<pre><code>${code.trim()}</code></pre>`;
  });
  
  // Format inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // Format bold
  html = html.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  
  // Format headers
  html = html.replace(/^### (.*$)/gim, '<h4 style="color:#FFF; margin: 10px 0 4px 0;">$1</h4>');
  html = html.replace(/^## (.*$)/gim, '<h3 style="color:#FFF; margin: 12px 0 6px 0;">$1</h3>');
  
  // Format bullet points
  html = html.replace(/^\- (.*$)/gim, '<div style="margin-left: 14px;">&bull; $1</div>');
  
  // Line breaks
  html = html.replace(/\n\n/g, '<br><br>');
  
  return html;
}

// --- BATCH CSV ANALYSIS ---
function setupBatchUpload() {
  const dropzone = document.getElementById("csv-dropzone");
  const fileInput = document.getElementById("csv-file-input");
  const demoBtn = document.getElementById("load-demo-btn");
  
  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length) uploadCSV(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) uploadCSV(fileInput.files[0]);
    });
  }
  
  if (demoBtn) {
    demoBtn.addEventListener("click", async () => {
      demoBtn.disabled = true;
      demoBtn.textContent = "Analyzing Benchmark Dataset...";
      try {
        const res = await fetch("/api/demo-data");
        if (!res.ok) throw new Error("Failed to load demo data");
        const data = await res.json();
        renderBatchResults(data);
        showToast("Demo dataset analyzed successfully");
      } catch (err) {
        alert(err.message);
      } finally {
        demoBtn.disabled = false;
        demoBtn.textContent = "Load Benchmark Demo Dataset (1,000 Flows)";
      }
    });
  }
}

async function uploadCSV(file) {
  const formData = new FormData();
  formData.append("file", file);
  
  const container = document.getElementById("batch-status");
  if (container) container.textContent = `Analyzing ${file.name}...`;
  
  try {
    const res = await fetch("/api/predict/batch-file", {
      method: "POST",
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Batch upload failed");
    }
    const data = await res.json();
    renderBatchResults(data);
    showToast(`Processed ${data.total_flows} flows`);
  } catch (err) {
    alert(`Upload Error: ${err.message}`);
  }
}

function renderBatchResults(data) {
  currentBatchData = data;
  document.getElementById("batch-results-panel").style.display = "block";
  
  document.getElementById("batch-total").textContent = data.total_flows.toLocaleString();
  document.getElementById("batch-normal").textContent = data.normal_flows.toLocaleString();
  document.getElementById("batch-anomalies").textContent = data.anomalies_detected.toLocaleString();
  document.getElementById("batch-rate").textContent = `${data.detection_rate_pct}%`;
  
  renderCharts(data);
  renderTable(data.results.slice(0, 100));
}

function renderCharts(data) {
  const attackCtx = document.getElementById("attackDistributionChart");
  if (attackCtx) {
    if (attackChartInstance) attackChartInstance.destroy();
    const labels = Object.keys(data.distribution);
    const counts = Object.values(data.distribution);
    
    attackChartInstance = new Chart(attackCtx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: counts,
          backgroundColor: ["#10B981", "#F43F5E", "#06B6D4", "#F59E0B", "#8B5CF6", "#EC4899", "#64748B"],
          borderWidth: 2,
          borderColor: "#090D16"
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: "right", labels: { color: "#94A3B8", font: { family: "Inter", size: 12 } } }
        }
      }
    });
  }
  
  const sevCtx = document.getElementById("severityChart");
  if (sevCtx) {
    if (protocolChartInstance) protocolChartInstance.destroy();
    const sevLabels = Object.keys(data.severity_breakdown);
    const sevCounts = Object.values(data.severity_breakdown);
    
    protocolChartInstance = new Chart(sevCtx, {
      type: "bar",
      data: {
        labels: sevLabels,
        datasets: [{
          label: "Flows",
          data: sevCounts,
          backgroundColor: ["#F43F5E", "#FB7185", "#F59E0B", "#3B82F6", "#64748B"],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94A3B8" }, grid: { display: false } },
          y: { ticks: { color: "#94A3B8" }, grid: { color: "rgba(255,255,255,0.05)" } }
        }
      }
    });
  }
}

function renderTable(rows) {
  const tbody = document.getElementById("batch-table-body");
  if (!tbody) return;
  
  tbody.innerHTML = rows.map(r => {
    const isAnomaly = r.is_anomaly;
    const sevClass = isAnomaly ? r.severity.toLowerCase() : "normal";
    return `
      <tr>
        <td>#${r.Flow_ID}</td>
        <td><b>${r.prediction}</b></td>
        <td><span class="badge badge-${sevClass}">${r.severity}</span></td>
        <td>${r.confidence_pct}</td>
        <td>${r.protocol}</td>
        <td>${r.service}</td>
        <td>${r.src_bytes} / ${r.dst_bytes}</td>
        <td>${r.packets_per_second}</td>
      </tr>
    `;
  }).join("");
}

// --- BATCH REPORT DOWNLOADS ---
function downloadBatchCSVReport() {
  if (!currentBatchData || !currentBatchData.results || currentBatchData.results.length === 0) {
    alert("Please analyze a dataset first before downloading the report.");
    return;
  }
  
  const headers = [
    "Flow_ID",
    "prediction",
    "is_anomaly",
    "severity",
    "confidence_pct",
    "protocol",
    "service",
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_packets",
    "dst_packets",
    "packets_per_second",
    "bytes_per_second",
    "tcp_flags"
  ];
  
  const csvRows = [headers.join(",")];
  
  for (const r of currentBatchData.results) {
    const values = headers.map(h => {
      let val = r[h] !== undefined ? r[h] : "";
      if (typeof val === "string" && val.includes(",")) {
        val = `"${val.replace(/"/g, '""')}"`;
      }
      return val;
    });
    csvRows.push(values.join(","));
  }
  
  const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
  triggerFileDownload(blob, `cyberguard_inspection_report_${new Date().toISOString().slice(0, 10)}.csv`);
  showToast("Full CSV report downloaded");
}

function downloadBatchSummaryReport() {
  if (!currentBatchData) {
    alert("Please analyze a dataset first before downloading the report.");
    return;
  }
  
  const d = currentBatchData;
  const attackBreakdown = d.attack_counts ? Object.entries(d.attack_counts).map(([atk, cnt]) => `  - ${atk}: ${cnt} flows (${((cnt / d.total_flows) * 100).toFixed(1)}%)`).join("\n") : "  None";
  const sevBreakdown = d.severity_counts ? Object.entries(d.severity_counts).map(([sev, cnt]) => `  - ${sev}: ${cnt} flows`).join("\n") : "  None";
  
  const reportText = `========================================================================
CYBERGUARD XAI-NIDS: NETWORK TRAFFIC ANALYSIS REPORT
Generated on: ${new Date().toLocaleString()}
========================================================================

1. EXECUTIVE SUMMARY
------------------------------------------------------------------------
Total Network Flows Analyzed : ${d.total_flows.toLocaleString()}
Normal / Benign Flows        : ${d.normal_flows.toLocaleString()}
Anomalies / Threats Detected : ${d.anomalies_detected.toLocaleString()}
Overall Threat Detection Rate: ${d.detection_rate_pct}%

2. ATTACK CLASSIFICATION BREAKDOWN
------------------------------------------------------------------------
${attackBreakdown}

3. SEVERITY RISK ASSESSMENT
------------------------------------------------------------------------
${sevBreakdown}

4. KEY RECOMMENDED ACTIONS FOR SOC OPERATORS
------------------------------------------------------------------------
- Review Critical & High severity flows flagged under DoS or Botnet categories.
- Export drop rules for identified attack sources using the AI SOC Copilot.
- Inspect application layer protocols with high packet/second velocity.

========================================================================
End of Report - CyberGuard ML Network Intrusion Detection System
========================================================================`;

  const blob = new Blob([reportText], { type: "text/plain;charset=utf-8;" });
  triggerFileDownload(blob, `cyberguard_executive_summary_${new Date().toISOString().slice(0, 10)}.txt`);
  showToast("Executive summary report downloaded");
}

function triggerFileDownload(blob, filename) {
  const link = document.createElement("a");
  const url = URL.createObjectURL(blob);
  link.setAttribute("href", url);
  link.setAttribute("download", filename);
  link.style.visibility = "hidden";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// --- WHAT-IF SIMULATOR ---
function setupWhatIfSimulator() {
  const form = document.getElementById("simulator-form");
  if (!form) return;
  
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const baseFlow = {
      duration: parseFloat(document.getElementById("sim_base_duration").value) || 0.1,
      protocol: document.getElementById("sim_base_protocol").value,
      service: document.getElementById("sim_base_service").value,
      src_bytes: parseFloat(document.getElementById("sim_base_src_bytes").value) || 200,
      dst_bytes: parseFloat(document.getElementById("sim_base_dst_bytes").value) || 400,
      src_packets: parseFloat(document.getElementById("sim_base_src_packets").value) || 5,
      dst_packets: parseFloat(document.getElementById("sim_base_dst_packets").value) || 5,
      src_dst_byte_ratio: parseFloat(document.getElementById("sim_base_ratio").value) || 0.5,
      packets_per_second: parseFloat(document.getElementById("sim_base_pps").value) || 50,
      bytes_per_second: parseFloat(document.getElementById("sim_base_bps").value) || 5000,
      tcp_flags: document.getElementById("sim_base_flags").value
    };
    
    const modified = {
      src_packets: parseFloat(document.getElementById("sim_mod_src_packets").value) || baseFlow.src_packets,
      packets_per_second: parseFloat(document.getElementById("sim_mod_pps").value) || baseFlow.packets_per_second,
      bytes_per_second: parseFloat(document.getElementById("sim_mod_bps").value) || baseFlow.bytes_per_second,
      tcp_flags: document.getElementById("sim_mod_flags").value
    };
    
    try {
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ base_flow: baseFlow, modified_features: modified })
      });
      if (!res.ok) throw new Error("Simulation failed");
      const data = await res.json();
      renderSimulationResult(data);
    } catch (err) {
      alert(err.message);
    }
  });
}

function loadSimulatorDemo() {
  document.getElementById("sim_base_duration").value = "0.20";
  document.getElementById("sim_base_protocol").value = "TCP";
  document.getElementById("sim_base_service").value = "HTTP";
  document.getElementById("sim_base_flags").value = "ACK";
  document.getElementById("sim_base_src_bytes").value = "2500";
  document.getElementById("sim_base_dst_bytes").value = "600";
  document.getElementById("sim_base_src_packets").value = "10";
  document.getElementById("sim_base_dst_packets").value = "10";
  document.getElementById("sim_base_ratio").value = "4.16";
  document.getElementById("sim_base_pps").value = "100";
  document.getElementById("sim_base_bps").value = "15500";

  document.getElementById("sim_mod_src_packets").value = "85";
  document.getElementById("sim_mod_pps").value = "600";
  document.getElementById("sim_mod_bps").value = "45000";
  document.getElementById("sim_mod_flags").value = "SYN";

  const form = document.getElementById("simulator-form");
  if (form) {
    form.dispatchEvent(new Event("submit"));
  }
  showToast("Loaded What-If Demo: Normal traffic perturbed into DoS Burst!");
}

function renderSimulationResult(data) {
  const container = document.getElementById("sim-result-container");
  if (!container) return;
  
  container.innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 24px;">
      <div class="result-box ${data.baseline.prediction === 'Normal' ? 'normal' : 'anomaly'}">
        <span style="font-size:0.75rem; color:#64748B; text-transform:uppercase; font-weight:700;">BASELINE FLOW</span>
        <h3 style="font-size: 2rem; color: #0F172A; margin: 6px 0;">${data.baseline.prediction}</h3>
        <p style="color:#64748B;">Confidence: <b>${data.baseline.confidence_pct}</b> &bull; ${data.baseline.severity}</p>
      </div>
      <div class="result-box ${data.simulated.prediction === 'Normal' ? 'normal' : 'anomaly'}">
        <span style="font-size:0.75rem; color:#1E3A8A; text-transform:uppercase; font-weight:700;">SIMULATED FLOW</span>
        <h3 style="font-size: 2rem; color: #0F172A; margin: 6px 0;">${data.simulated.prediction}</h3>
        <p style="color:#1E3A8A;">Confidence: <b>${data.simulated.confidence_pct}</b> &bull; ${data.simulated.severity}</p>
      </div>
    </div>
  `;
}

// --- ALERTS ---
async function loadAlerts() {
  try {
    const res = await fetch("/api/alerts?limit=15");
    const alerts = await res.json();
    const list = document.getElementById("alerts-feed");
    if (!list) return;
    
    if (alerts.length === 0) {
      list.innerHTML = `<div style="color: #64748B; padding: 20px; text-align: center;">No active security alerts logged.</div>`;
      return;
    }
    
    list.innerHTML = alerts.map(a => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; margin-bottom: 10px;">
        <div>
          <span class="badge badge-${a.severity ? a.severity.toLowerCase() : 'medium'}">${a.severity || 'ALERT'}</span>
          <b style="color: #0F172A; margin-left: 10px; font-size: 0.95rem;">${a.attack_type}</b>
          <span style="color: #64748B; font-size: 0.8rem; margin-left: 10px;">${a.source_info || ''}</span>
        </div>
        <div style="text-align: right;">
          <span style="color: #1E3A8A; font-weight: 600; font-size: 0.85rem;">${a.confidence || ''}</span>
          <div style="color: #64748B; font-size: 0.75rem;">${a.timestamp || ''}</div>
        </div>
      </div>
    `).join("");
  } catch (err) {
    console.error("Failed to load alerts:", err);
  }
}

// --- TOAST NOTIFICATIONS ---
function showToast(msg) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = msg;
  toast.style.display = "block";
  setTimeout(() => { toast.style.display = "none"; }, 3000);
}
