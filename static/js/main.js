"use strict";

const socket = io();

// DOM refs
const ifaceSelect  = document.getElementById("iface-select");
const filterInput  = document.getElementById("filter-input");
const btnStart     = document.getElementById("btn-start");
const btnStop      = document.getElementById("btn-stop");
const btnClear     = document.getElementById("btn-clear");
const statusBadge  = document.getElementById("status-badge");
const statTotal    = document.getElementById("stat-total");
const protoStats   = document.getElementById("proto-stats");
const tbody        = document.getElementById("packet-tbody");
const emptyMsg     = document.getElementById("empty-msg");
const detailPanel  = document.getElementById("detail-panel");
const detailContent = document.getElementById("detail-content");

// State
let packets = [];
let selectedId = null;
const MAX_ROWS = 1000; // keep DOM lean

// ── Helpers ──────────────────────────────────────────────────────────────

function setStatus(state) {
  statusBadge.className = "badge badge-" + state;
  const labels = { idle: "Idle", running: "Capturing…", stopped: "Stopped" };
  statusBadge.textContent = labels[state] || state;
}

function showToast(message, type) {
  const toast = document.createElement("div");
  toast.className = "toast toast-" + (type || "info");
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.classList.add("toast-visible"), 10);
  setTimeout(() => {
    toast.classList.remove("toast-visible");
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function protoClass(proto) {
  const known = ["TCP","UDP","HTTP","HTTPS","DNS","ICMP","ARP","SSH","FTP","SMTP","IPv6"];
  return known.includes(proto) ? proto : "Other";
}

function buildRow(pkt) {
  const tr = document.createElement("tr");
  tr.dataset.id = pkt.id;
  const pc = protoClass(pkt.protocol);
  tr.innerHTML = `
    <td>${pkt.id}</td>
    <td>${pkt.time}</td>
    <td>${escHtml(pkt.src)}</td>
    <td>${escHtml(pkt.dst)}</td>
    <td><span class="proto-${pc}">${escHtml(pkt.protocol)}</span></td>
    <td>${pkt.length}</td>
    <td>${escHtml(pkt.info)}</td>
  `;
  tr.addEventListener("click", () => showDetail(pkt, tr));
  return tr;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function showDetail(pkt, tr) {
  // deselect previous
  const prev = tbody.querySelector("tr.selected");
  if (prev) prev.classList.remove("selected");
  tr.classList.add("selected");
  selectedId = pkt.id;

  const fields = [
    ["#", pkt.id],
    ["Time", pkt.time],
    ["Source", pkt.src],
    ["Destination", pkt.dst],
    ["Protocol", pkt.protocol],
    ["Length", pkt.length + " bytes"],
    ["Info", pkt.info],
  ];
  detailContent.innerHTML = `<div class="detail-grid">${
    fields.map(([label, val]) =>
      `<div class="detail-field">
        <span class="df-label">${label}</span>
        <span class="df-value">${escHtml(String(val))}</span>
      </div>`
    ).join("")
  }</div>`;
  detailPanel.classList.remove("hidden");
}

function updateStats(stats, total) {
  statTotal.textContent = total;
  protoStats.innerHTML = Object.entries(stats)
    .sort((a, b) => b[1] - a[1])
    .map(([proto, count]) => {
      const pc = protoClass(proto);
      return `<span class="proto-badge pbadge-${pc}">${escHtml(proto)}: ${count}</span>`;
    }).join("");
}

function clearAll() {
  packets = [];
  selectedId = null;
  tbody.innerHTML = "";
  emptyMsg.style.display = "";
  detailPanel.classList.add("hidden");
  statTotal.textContent = "0";
  protoStats.innerHTML = "";
}

// ── Socket events ─────────────────────────────────────────────────────────

socket.on("connect",    () => console.log("Socket connected"));
socket.on("disconnect", () => console.log("Socket disconnected"));

socket.on("packet", (pkt) => {
  packets.push(pkt);
  // Prune memory alongside DOM
  if (packets.length > MAX_ROWS) {
    packets.shift();
  }
  emptyMsg.style.display = "none";

  // Prune oldest rows if over limit
  if (tbody.children.length >= MAX_ROWS) {
    tbody.removeChild(tbody.firstChild);
  }

  const row = buildRow(pkt);
  tbody.appendChild(row);
  // Auto-scroll to bottom
  row.scrollIntoView({ block: "nearest" });

  updateStats(pkt.stats, pkt.id);
});

socket.on("error", (data) => {
  showToast("Capture error: " + data.message, "error");
  setStatus("stopped");
  btnStart.disabled = false;
  btnStop.disabled  = true;
});

// ── Button handlers ───────────────────────────────────────────────────────

btnStart.addEventListener("click", async () => {
  btnStart.disabled = true;
  btnStop.disabled  = false;
  setStatus("running");

  const body = {
    interface: ifaceSelect.value,
    filter: filterInput.value.trim(),
  };
  const res = await fetch("/api/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    setStatus("idle");
    btnStart.disabled = false;
    btnStop.disabled  = true;
    showToast("Failed to start capture.", "error");
  }
});

btnStop.addEventListener("click", async () => {
  btnStop.disabled  = true;
  btnStart.disabled = false;
  setStatus("stopped");
  await fetch("/api/stop", { method: "POST" });
});

btnClear.addEventListener("click", clearAll);

// ── Bootstrap ─────────────────────────────────────────────────────────────

(async function loadInterfaces() {
  try {
    const res  = await fetch("/api/interfaces");
    const list = await res.json();
    list.forEach(iface => {
      const opt = document.createElement("option");
      opt.value = opt.textContent = iface;
      ifaceSelect.appendChild(opt);
    });
  } catch (e) {
    console.error("Could not load interfaces", e);
  }
})();
