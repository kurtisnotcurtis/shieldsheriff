const PRESETS = {
  "quiet-guardian": {
    name: "Quiet Guardian (Default)",
    badgeText: "★ KEEPING THE PEACE",
    badgeClass: "chip-gold",
    rtp: { text: "ON (Locked)", cls: "chip-on" },
    bm: { text: "ON (Locked)", cls: "chip-on" },
    cloud: { text: "OFF — SpynetReporting=0", cls: "chip-off" },
    samples: { text: "NEVER — SubmitSamplesConsent=2", cls: "chip-off" },
    nags: { text: "SILENCED (DisableNotifications=1)", cls: "chip-gold" },
    watch: { text: "Manual / Timer Only", cls: "chip-off" },
    trayText: "ShieldSheriff ★ Keeping the Peace | Real-Time: ON | Cloud/Samples: OFF | Nags: Silenced"
  },
  "dev-workstation": {
    name: "Developer Workstation",
    badgeText: "★ FAST BUILD MODE",
    badgeClass: "chip-cyan",
    rtp: { text: "ON (Auto-Pauses on Builds)", cls: "chip-cyan" },
    bm: { text: "OFF (Zero Hook Overhead)", cls: "chip-off" },
    cloud: { text: "OFF — SpynetReporting=0", cls: "chip-off" },
    samples: { text: "NEVER — Uncompiled Binaries Stay Local", cls: "chip-off" },
    nags: { text: "SILENCED + Tray Icon Muted", cls: "chip-gold" },
    watch: { text: "cargo.exe, msbuild.exe, link.exe, rustc.exe", cls: "chip-cyan" },
    trayText: "ShieldSheriff ★ Dev Mode | Auto Stand-Down watching cargo.exe, msbuild.exe"
  },
  "on-demand-only": {
    name: "On-Demand Deputy",
    badgeText: "★ ZERO BACKGROUND CPU",
    badgeClass: "chip-gold",
    rtp: { text: "PERMANENTLY OFF (No 24h Reset)", cls: "chip-off" },
    bm: { text: "OFF", cls: "chip-off" },
    cloud: { text: "OFF — SpynetReporting=0", cls: "chip-off" },
    samples: { text: "NEVER — SubmitSamplesConsent=2", cls: "chip-off" },
    nags: { text: "SILENCED (No Red Shield Warnings)", cls: "chip-gold" },
    watch: { text: "MpCmdRun.exe CLI Scans Still Active", cls: "chip-on" },
    trayText: "ShieldSheriff ★ On-Demand Deputy | Real-Time: OFF | CLI Scans & Updates: Ready"
  },
  "full-shield": {
    name: "Full Shield (Nag-Free)",
    badgeText: "★ MAX ENGINE + NO NAGS",
    badgeClass: "chip-on",
    rtp: { text: "ON (Locked)", cls: "chip-on" },
    bm: { text: "ON + Network Protection Block", cls: "chip-on" },
    cloud: { text: "ON — Advanced MAPS (2)", cls: "chip-on" },
    samples: { text: "NEVER — No Automatic File Uploads", cls: "chip-off" },
    nags: { text: "SILENCED (No Sample/Tamper Nags)", cls: "chip-gold" },
    watch: { text: "5s Drift Guard Active", cls: "chip-on" },
    trayText: "ShieldSheriff ★ Full Shield | Local + Cloud: ON | Sample Uploads: OFF | Nags: Silenced"
  }
};

const SCENARIOS = {
  "all": {
    verdict: "<strong>Summary:</strong> Other tools either kill the entire Defender service, crank cloud telemetry <em>up</em>, or wrap it in a heavy suite. <strong>ShieldSheriff</strong> keeps the exact local protection you choose while permanently silencing telemetry and nags.",
    rows: []
  },
  "privacy": {
    verdict: "<strong>Privacy &amp; Zero Nags:</strong> Turning off Cloud Protection and Sample Submission in Windows 11 normally triggers constant Security Center warnings. <strong>ShieldSheriff</strong> locks both OFF and silences the nag layer.",
    rows: ["row-philosophy", "row-cloud-off", "row-nags", "row-drift"]
  },
  "dev": {
    verdict: "<strong>Developer Build Speed:</strong> <strong>ShieldSheriff</strong> watches for <code>cargo.exe</code>, <code>msbuild.exe</code>, and <code>link.exe</code>—automatically pausing Real-Time scanning during builds and resuming on exit.",
    rows: ["row-process-watch", "row-subengines", "row-wsman"]
  },
  "ondemand": {
    verdict: "<strong>On-Demand Only:</strong> Defender Control kills <code>WinDefend</code>, breaking manual scans. <strong>ShieldSheriff</strong> turns Real-Time scanning OFF permanently while keeping <code>MpCmdRun.exe</code> scans and updates working.",
    rows: ["row-ondemand", "row-drift", "row-nags"]
  },
  "clean": {
    verdict: "<strong>Clean Engineering:</strong> Kill-switch tools use <code>TrustedInstaller</code> exploits that get flagged as malware. <strong>ShieldSheriff</strong> uses standard Windows Group Policy and DCOM WMI.",
    rows: ["row-av-clean", "row-wsman", "row-footprint"]
  }
};

function selectPreset(id, btnEl) {
  const p = PRESETS[id];
  if (!p) return;

  document.querySelectorAll(".sim-tab").forEach(b => b.classList.remove("active"));
  if (btnEl) btnEl.classList.add("active");

  const setChip = (elId, data) => {
    const el = document.getElementById(elId);
    if (!el) return;
    el.textContent = data.text;
    el.className = "status-chip " + data.cls;
  };

  setChip("simBadge", { text: p.badgeText, cls: p.badgeClass });
  setChip("simRtp", p.rtp);
  setChip("simBm", p.bm);
  setChip("simCloud", p.cloud);
  setChip("simSamples", p.samples);
  setChip("simNags", p.nags);
  setChip("simWatch", p.watch);

  const trayEl = document.getElementById("simTrayText");
  if (trayEl) trayEl.textContent = p.trayText;
}

function selectScenario(id, btnEl) {
  const sc = SCENARIOS[id] || SCENARIOS["all"];
  document.querySelectorAll(".scenario-btn").forEach(b => b.classList.remove("active"));
  if (btnEl) btnEl.classList.add("active");

  const vBox = document.getElementById("scenarioVerdict");
  if (vBox) vBox.innerHTML = sc.verdict;

  const allRows = document.querySelectorAll(".comp-table tbody tr");
  allRows.forEach(tr => {
    if (!sc.rows || sc.rows.length === 0) {
      tr.style.opacity = "1";
      tr.style.background = "";
    } else if (sc.rows.includes(tr.id)) {
      tr.style.opacity = "1";
      tr.style.background = "rgba(250, 204, 21, 0.08)";
    } else {
      tr.style.opacity = "0.42";
      tr.style.background = "";
    }
  });
}

window.addEventListener("DOMContentLoaded", () => {
  selectPreset("quiet-guardian", document.querySelector('.sim-tab[data-preset="quiet-guardian"]'));
  selectScenario("all", document.querySelector('.scenario-btn[data-scenario="all"]'));
});
