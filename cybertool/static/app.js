"use strict";

const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));

let currentScan = null;
let toastTimer;

function toast(message) {
  const element = $("toast");
  element.textContent = message;
  element.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove("show"), 2400);
}

function setStatus(id, message, kind = "loading") {
  const element = $(id);
  element.className = "status" + (kind === "error" ? " error" : "");
  element.innerHTML = kind === "error"
    ? escapeHtml(message)
    : '<span class="spinner"></span><span>' + escapeHtml(message) + "</span>";
  element.classList.remove("hidden");
}

function clearStatus(id) {
  $(id).classList.add("hidden");
  $(id).innerHTML = "";
}

async function loadStatus() {
  try {
    const response = await fetch("/api/status");
    const data = await response.json();
    const dot = $("engine-pill").querySelector(".dot");
    if (data.nmap_available) {
      $("engine-pill").innerHTML = '<span class="dot ok"></span> nmap available';
      $("engine-note").textContent =
        "nmap detected — the scan will use nmap -sV with XML output, including service version detection.";
    } else {
      $("engine-pill").innerHTML = '<span class="dot"></span> fallback scan';
      $("engine-note").textContent =
        "nmap is not installed here, so the app uses a built-in TCP connect scan with banner grabbing on common ports. Install nmap to enable full-port scans and richer version detection.";
      $("profile").querySelector('option[value="full"]').disabled = true;
    }
  } catch (error) {
    $("engine-note").textContent = "Could not detect the scan engine.";
  }
}

function selectedPorts() {
  return Array.from(document.querySelectorAll(".port-row input:checked")).map((box) => Number(box.value));
}

function updateSelection() {
  const count = selectedPorts().length;
  $("selection-count").textContent = count + " selected";
  $("vuln-btn").classList.toggle("hidden", count === 0);
}

function renderPorts(scan) {
  currentScan = scan;
  const list = $("port-list");
  list.innerHTML = "";
  if (!scan.ports.length) {
    list.innerHTML = '<p class="empty-note">No open ports found in the selected range.</p>';
    $("ports-subtitle").textContent = "No ports to choose from. Try a different target or profile.";
    $("vuln-btn").classList.add("hidden");
  } else {
    $("ports-subtitle").textContent =
      scan.port_count + " open port" + (scan.port_count === 1 ? "" : "s") +
      " found on " + scan.target + " (" + scan.engine + "). Select the ones to check.";
    scan.ports.forEach((port) => {
      const row = document.createElement("label");
      row.className = "port-row";
      const description = [port.product, port.version].filter(Boolean).join(" ") || port.method || "detected";
      row.innerHTML =
        '<input type="checkbox" value="' + port.port + '">' +
        '<span class="port-number">' + port.port + "/" + escapeHtml(port.protocol || "tcp") + "</span>" +
        '<span class="port-service"><strong>' + escapeHtml(port.service || "unknown") + "</strong>" +
        "<small>" + escapeHtml(description) + "</small></span>" +
        '<span class="port-state">open</span>';
      row.querySelector("input").addEventListener("change", updateSelection);
      list.appendChild(row);
    });
  }
  $("ports-step").classList.remove("hidden");
  $("vuln-step").classList.add("hidden");
  updateSelection();
  $("ports-step").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderVulns(result) {
  $("vuln-summary").innerHTML =
    '<span class="count"><b>' + result.checked_ports.length + "</b> ports checked</span>" +
    Object.entries(result.counts).map(([name, count]) =>
      '<span class="count ' + name + '">' + escapeHtml(name.toUpperCase()) + " <b>" + count + "</b></span>").join("");

  const findings = $("findings");
  findings.innerHTML = "";
  if (!result.findings.length) {
    findings.innerHTML = '<p class="empty-note">No known signature matched the selected ports.</p>';
  } else {
    result.findings.forEach((item, index) => {
      const article = document.createElement("article");
      article.className = "finding " + item.severity;
      const references = (item.references || []).map((ref) =>
        '<span class="reference">' + escapeHtml(ref) + "</span>").join("");
      article.innerHTML =
        '<div class="finding-head"><h3>' + escapeHtml(item.title) + "</h3>" +
        '<span class="sev ' + item.severity + '">' + escapeHtml(item.severity) + "</span></div>" +
        '<p class="meta">' + escapeHtml(item.evidence) + " · " + escapeHtml(item.kind) +
        (item.cve ? " · " + escapeHtml(item.cve) : "") + " · " + escapeHtml(item.confidence) + "</p>" +
        "<p>" + escapeHtml(item.description) + "</p>" +
        '<p><strong>Fix: </strong>' + escapeHtml(item.remediation) + "</p>" +
        '<div class="references">' + references + "</div>" +
        '<div class="finding-actions"><button type="button" class="btn ghost small verify-btn" data-finding="' +
        escapeHtml(item.id) + '" data-port="' + item.port + '">Verify safely</button>' +
        '<button type="button" class="btn ghost small guide-btn" data-finding="' +
        escapeHtml(item.id) + '">Manual guide</button></div>' +
        '<div class="verify-slot" id="verify-slot-' + index + '"></div>' +
        '<div class="guide-slot" id="guide-slot-' + index + '"></div>';
      findings.appendChild(article);
    });
  }

  const notes = $("notes");
  notes.innerHTML = "";
  if (result.notes.length || result.disclaimer) {
    const wrapper = document.createElement("div");
    wrapper.className = "notes";
    wrapper.innerHTML = "<ul>" + result.notes.map((note) =>
      "<li>" + escapeHtml(note) + "</li>").join("") + "</ul>" +
      "<p>" + escapeHtml(result.disclaimer) + "</p>";
    notes.appendChild(wrapper);
  }
  $("vuln-step").classList.remove("hidden");
  $("vuln-step").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runScan() {
  const target = $("target").value.trim();
  if (!target) {
    toast("Enter a target first");
    $("target").focus();
    return;
  }
  if (!$("authorized").checked) {
    toast("Confirm that you are authorized to scan this target");
    $("authorized").focus();
    return;
  }
  const button = $("scan-btn");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Scanning…";
  setStatus("scan-status", "Scanning ports on " + target + "…");
  $("ports-step").classList.add("hidden");
  $("vuln-step").classList.add("hidden");

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        authorized: true,
        profile: $("profile").value,
        timeout: Number($("timeout").value),
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Scan request failed");
    renderPorts(data);
    clearStatus("scan-status");
    toast(data.engine === "nmap" ? "nmap scan complete" : "Connect scan complete");
  } catch (error) {
    setStatus("scan-status", error.message, "error");
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function runVulnCheck() {
  const ports = selectedPorts();
  if (!ports.length || !currentScan) return;
  const button = $("vuln-btn");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Checking…";
  setStatus("vuln-status", "Checking " + ports.length + " port(s) against local signatures…");
  $("vuln-step").classList.add("hidden");

  try {
    const response = await fetch("/api/vulns", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: currentScan.scan_id, ports }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Lookup failed");
    renderVulns(data);
    clearStatus("vuln-status");
    toast("Lookup complete");
  } catch (error) {
    setStatus("vuln-status", error.message, "error");
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function renderVerifyResult(result) {
  const labels = { confirmed: "Confirmed", not_confirmed: "Not confirmed", inconclusive: "Inconclusive" };
  return '<div class="verify-result ' + result.status + '">' +
    '<div class="verify-head"><strong>' + escapeHtml(labels[result.status] || result.status) + "</strong>" +
    "<span>" + escapeHtml(result.check || "read-only check") + "</span></div>" +
    '<p class="meta">' + escapeHtml(result.evidence || "") + "</p>" +
    "<p>" + escapeHtml(result.detail || "") + "</p></div>";
}

async function verifyFinding(button) {
  const slot = button.closest(".finding").querySelector(".verify-slot");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Verifying…";
  slot.innerHTML = '<div class="verify-result loading">Re-probing the service banner…</div>';
  try {
    const response = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: currentScan.scan_id,
        finding_id: button.dataset.finding,
        port: Number(button.dataset.port),
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Verification failed");
    slot.innerHTML = renderVerifyResult(data);
    toast("Verification complete");
  } catch (error) {
    slot.innerHTML = '<div class="verify-result not_confirmed">' + escapeHtml(error.message) + "</div>";
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function renderGuide(guide) {
  const list = (items) => "<ol>" + items.map((item) => "<li>" + escapeHtml(item) + "</li>").join("") + "</ol>";
  const refs = (guide.references || []).map((ref) =>
    '<span class="reference">' + escapeHtml(ref) + "</span>").join("");
  return '<div class="guide-panel">' +
    '<div class="guide-head"><strong>Manual guide</strong><span>read-only · no payloads</span></div>' +
    "<p>" + escapeHtml(guide.overview) + "</p>" +
    "<h4>Safe verification</h4>" + list(guide.safe_steps) +
    "<h4>How to fix</h4>" + list(guide.fix_steps) +
    '<div class="references">' + refs + "</div>" +
    '<p class="scope">' + escapeHtml(guide.scope_note) + "</p></div>";
}

async function openGuide(button) {
  const slot = button.closest(".finding").querySelector(".guide-slot");
  if (slot.innerHTML.trim()) {
    slot.innerHTML = "";
    button.textContent = "Manual guide";
    return;
  }
  button.disabled = true;
  button.textContent = "Loading…";
  try {
    const response = await fetch("/api/guide", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: button.dataset.finding }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Could not load guide");
    slot.innerHTML = renderGuide(data);
    button.textContent = "Hide guide";
  } catch (error) {
    slot.innerHTML = '<div class="verify-result not_confirmed">' + escapeHtml(error.message) + "</div>";
    toast(error.message);
    button.textContent = "Manual guide";
  } finally {
    button.disabled = false;
  }
}

$("findings").addEventListener("click", (event) => {
  const guideButton = event.target.closest(".guide-btn");
  if (guideButton) {
    openGuide(guideButton);
    return;
  }
  const verifyButton = event.target.closest(".verify-btn");
  if (verifyButton) verifyFinding(verifyButton);
});

$("scan-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runScan();
});

$("demo-btn").addEventListener("click", () => {
  $("target").value = "127.0.0.1";
  $("authorized").checked = true;
  $("profile").value = "top";
  runScan();
});

$("select-all").addEventListener("click", () => {
  document.querySelectorAll(".port-row input").forEach((box) => { box.checked = true; });
  updateSelection();
});

$("clear-all").addEventListener("click", () => {
  document.querySelectorAll(".port-row input").forEach((box) => { box.checked = false; });
  updateSelection();
});

$("vuln-btn").addEventListener("click", runVulnCheck);
$("target").addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); runScan(); }
});

loadStatus();
