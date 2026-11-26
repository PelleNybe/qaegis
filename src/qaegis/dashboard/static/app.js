(() => {
  "use strict";

  const state = {
    token: localStorage.getItem("qaegis_dashboard_token") || "",
    activeTab: "overview",
    overview: null,
    configBundle: null,
    events: [],
    eventsPaused: false,
    sse: null,
    lastCbom: null,
  };

  const SECTION_META = [
    { key: "_root", title: "Core Node & Storage Paths", keys: ["node_id", "data_dir", "keys_dir", "db_path"] },
    { key: "bus", title: "Event Bus & CurveZMQ Transport" },
    { key: "identity", title: "NIST PQC Identity & Hardware Sealing (PKCS#11 / TPM 2.0)" },
    { key: "lifecycle", title: "Day / Night Lifecycle State Machine" },
    { key: "telemetry", title: "Structured Logging & Prometheus Exporter" },
    { key: "dashboard", title: "Web Mission-Control Dashboard" },
    { key: "reality_stamp", title: "01 · Proof of Reality (QRNG & NIST Checks)" },
    { key: "chameleon_fw", title: "02 · Quantum Chameleon Adaptive Firewall" },
    { key: "qubit_compiler", title: "03 · AI-to-Qubit Neural Compiler" },
    { key: "quantum_dreamer", title: "04 · Quantum Dreamer (QAOA, QPU & ZNE/TREX)" },
    { key: "quantum_entropy", title: "05 · Quantum Entropy Engine & Ollama Bridge" },
  ];

  const ENUM_OPTIONS = {
    "bus.transport": ["inproc", "zmq"],
    "bus.zmq_security": ["none", "curve"],
    "bus.backpressure_policy": ["block", "drop_oldest", "reject"],
    "identity.hardware_seal_backend": ["none", "pkcs11", "tpm2"],
    "lifecycle.default_mode": ["DAY", "NIGHT"],
    "telemetry.log_level": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    "quantum_dreamer.backend_type": ["aer_statevector", "aer_noisy", "aws_braket", "ionq", "ibm_runtime"],
    "quantum_dreamer.ibm_channel": ["ibm_quantum", "ibm_cloud"],
    "quantum_dreamer.mitigation_mode": ["none", "zne", "trex", "both"],
    "quantum_dreamer.zne_extrapolation": ["linear", "richardson", "exponential"],
  };

  function esc(val) {
    return String(val ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function toast(msg, isError = false) {
    const stack = document.getElementById("toastStack");
    const el = document.createElement("div");
    el.className = "toast" + (isError ? " err" : "");
    el.textContent = msg;
    stack.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (state.token) {
      headers["Authorization"] = `Bearer ${state.token}`;
    }
    const resp = await fetch(path, Object.assign({}, options, { headers }));
    if (resp.status === 401) {
      document.getElementById("authModal").classList.remove("hidden");
      throw new Error("Authentication token required");
    }
    const ctype = resp.headers.get("content-type") || "";
    const data = ctype.includes("application/json") ? await resp.json() : await resp.text();
    if (!resp.ok) {
      const detail = data && data.details ? JSON.stringify(data.details, null, 2) : (data.error || resp.statusText);
      const err = new Error(detail);
      err.payload = data;
      throw err;
    }
    return data;
  }

  function formatDuration(sec) {
    const s = Math.floor(sec || 0);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const rem = s % 60;
    return h > 0 ? `${h}h ${m}m ${rem}s` : `${m}m ${rem}s`;
  }

  /* Navigation */
  function switchTab(tabName) {
    state.activeTab = tabName;
    document.querySelectorAll(".nav-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === tabName);
    });
    document.querySelectorAll(".tab-panel").forEach((p) => {
      p.classList.toggle("active", p.id === `tab-${tabName}`);
    });
    if (tabName === "config") loadConfigCenter();
    if (tabName === "identity") loadIdentityTab();
    if (tabName === "reality") loadRealityTab();
    if (tabName === "dreamer") loadDreamerTab();
    if (tabName === "entropy") loadAuditLedger();
  }

  /* Overview & Live SSE */
  function renderOverview(ov) {
    state.overview = ov;
    document.getElementById("sidebarVersion").textContent = `Mission Control v${ov.version}`;
    document.getElementById("sideNodeId").textContent = ov.node_id;
    document.getElementById("sideKeyVer").textContent = `v${ov.identity.key_version} (${ov.identity.primary_sig_alg})`;
    document.getElementById("sideUptime").textContent = formatDuration(ov.uptime_s);

    const modePill = document.getElementById("lifecyclePill");
    modePill.textContent = `MODE: ${ov.lifecycle.mode}`;
    modePill.classList.toggle("night", ov.lifecycle.mode === "NIGHT");

    const tier = ov.subsystems.chameleon_fw.current_tier;
    const tierPill = document.getElementById("tierPill");
    tierPill.textContent = `TIER: ${tier}`;
    tierPill.className = "pill pill-tier" + (tier === "ELEVATED" ? " elevated" : tier === "QUANTUM_CRITICAL" ? " critical" : "");

    const auditPill = document.getElementById("auditPill");
    auditPill.textContent = ov.storage.audit_chain_valid
      ? `AUDIT CHAIN: VALID (${ov.storage.audit_event_count})`
      : "AUDIT CHAIN: TAMPERED!";

    document.getElementById("kpiCpu").textContent = `${ov.host.cpu_percent.toFixed(1)}%`;
    document.getElementById("meterCpu").style.width = `${Math.min(100, ov.host.cpu_percent)}%`;
    document.getElementById("kpiCpuSub").textContent = `${ov.host.cpu_count_logical} logical cores · ${ov.host.platform}`;

    document.getElementById("kpiRam").textContent = `${ov.host.ram_percent.toFixed(1)}%`;
    document.getElementById("meterRam").style.width = `${Math.min(100, ov.host.ram_percent)}%`;
    document.getElementById("kpiRamSub").textContent = `${ov.host.ram_used_gb}/${ov.host.ram_total_gb} GB · RSS ${ov.host.process_rss_mb} MB`;

    const rs = ov.subsystems.reality_stamp;
    document.getElementById("kpiMerkle").textContent = `${rs.merkle_tree_size} leaves`;
    document.getElementById("kpiMerkleRoot").textContent = `root: ${rs.merkle_root.slice(0, 20)}...`;

    const qd = ov.subsystems.quantum_dreamer;
    document.getElementById("kpiDreamQueue").textContent = `${qd.pending_problems} pending`;
    document.getElementById("kpiDreamSub").textContent = `${qd.solved_problems} solved · ${qd.failed_problems} failed`;

    const cards = [
      {
        tab: "reality",
        title: "01 · Proof of Reality",
        badge: rs.equivocation_alerts > 0 ? "ALERT" : "ONLINE",
        warn: rs.equivocation_alerts > 0,
        lines: [
          `Merkle Size: <strong>${rs.merkle_tree_size}</strong>`,
          `NIST Strict: <strong>${rs.strict_nist_checks}</strong>`,
          `Gossip Peers: <strong>${rs.gossip_peers_witnessed}</strong>`,
        ],
      },
      {
        tab: "chameleon",
        title: "02 · Chameleon FW",
        badge: tier,
        warn: tier !== "STANDARD",
        lines: [
          `Session Epoch: <strong>${ov.subsystems.chameleon_fw.session_epoch}</strong>`,
          `Msg Counter: <strong>${ov.subsystems.chameleon_fw.message_counter}</strong>`,
          `Thresholds: <strong>${ov.subsystems.chameleon_fw.elevated_threshold}/${ov.subsystems.chameleon_fw.critical_threshold}</strong>`,
        ],
      },
      {
        tab: "compiler",
        title: "03 · Qubit Compiler",
        badge: ov.subsystems.qubit_compiler.onnx_active ? "ONNX ACTIVE" : "PYTORCH",
        warn: false,
        lines: [
          `Qubits: <strong>${ov.subsystems.qubit_compiler.default_num_qubits}q</strong>`,
          `Opt Level: <strong>O${ov.subsystems.qubit_compiler.optimization_level}</strong>`,
          `2Q Noise: <strong>${ov.subsystems.qubit_compiler.backend_noise_level}</strong>`,
        ],
      },
      {
        tab: "dreamer",
        title: "04 · Quantum Dreamer",
        badge: qd.backend_type,
        warn: false,
        lines: [
          `Mitigation: <strong>${qd.mitigation_mode}</strong>`,
          `QAOA Layers: <strong>p=${qd.qaoa_reps}</strong>`,
          `Active Policies: <strong>${qd.active_policies.length}</strong>`,
        ],
      },
      {
        tab: "entropy",
        title: "05 · Quantum Entropy",
        badge: "ONLINE",
        warn: false,
        lines: [
          `Circuit: <strong>${ov.subsystems.quantum_entropy.harvester_qubits}q × ${ov.subsystems.quantum_entropy.harvester_shots}</strong>`,
          `Pool Bytes: <strong>${ov.subsystems.quantum_entropy.pool_min_bytes} B</strong>`,
          `LLM Model: <strong>${esc(ov.subsystems.quantum_entropy.ollama_model)}</strong>`,
        ],
      },
    ];

    const grid = document.getElementById("subsystemCards");
    grid.innerHTML = cards
      .map(
        (c) => `
      <div class="sub-card" data-jump="${c.tab}">
        <div class="sub-card-top">
          <span class="sub-card-title">${c.title}</span>
          <span class="badge ${c.warn ? "badge-warn" : ""}">${esc(c.badge)}</span>
        </div>
        ${c.lines.map((l) => `<div class="sub-card-metric">${l}</div>`).join("")}
      </div>`
      )
      .join("");
    grid.querySelectorAll(".sub-card").forEach((el) => {
      el.addEventListener("click", () => switchTab(el.dataset.jump));
    });
  }

  function renderEventsFeed() {
    const filter = (document.getElementById("eventFilterInput").value || "").trim().toLowerCase();
    const feed = document.getElementById("liveEventFeed");
    const filtered = state.events.filter((e) => !filter || String(e.topic).toLowerCase().includes(filter));
    if (!filtered.length) {
      feed.innerHTML = `<div class="result-box">Waiting for EventBus activity (or trigger any subsystem action)...</div>`;
      return;
    }
    feed.innerHTML = filtered
      .slice(0, 80)
      .map(
        (ev) => `
      <div class="event-item">
        <div class="event-item-head">
          <span class="event-topic">${esc(ev.topic)}</span>
          <span class="event-meta">${esc(ev.source)} · ${esc(String(ev.timestamp_utc || "").slice(11, 19))}Z</span>
        </div>
        <div class="event-payload">${esc(JSON.stringify(ev.payload))}</div>
      </div>`
      )
      .join("");
  }

  async function loadDoctor() {
    const doc = await api("/api/doctor");
    const rows = [
      ["Overall System Health", doc.healthy ? "HEALTHY" : "DEGRADED"],
      ["NIST FIPS 203 (ML-KEM-768)", String(doc.pqc_mechanisms.ml_kem_768)],
      ["NIST FIPS 204 (ML-DSA-65)", String(doc.pqc_mechanisms.ml_dsa_65)],
      ["NIST FIPS 205 (SLH-DSA-128f)", String(doc.pqc_mechanisms.slh_dsa_128f)],
      ["SQLite WAL Schema", `v${doc.schema_version}`],
      ["Audit Hash Chain", `${doc.audit_chain.valid} (${doc.audit_chain.records} records)`],
      ["Dream Queue Row Hashes", `${doc.dream_queue_integrity.valid} (${doc.dream_queue_integrity.problems} items)`],
      ["Policy Snapshot Hashes", `${doc.policy_snapshots_integrity.valid} (${doc.policy_snapshots_integrity.snapshots} snaps)`],
      ["Trust Keyring", `v${doc.keyring.current_version} (${doc.keyring.total_keys} key(s))`],
      ["TPM 2.0 Hardware", `dev=${doc.hardware_security.tpm2_device_exists}, tools=${doc.hardware_security.tpm2_tools_installed}`],
      [
        "PKCS#11 HSM / SoftHSM2",
        doc.hardware_security.pkcs11_library
          ? `${doc.hardware_security.pkcs11_slots.length} slot(s) (${doc.hardware_security.pkcs11_library.split("/").pop()})`
          : "not installed",
      ],
      ["Quantum Backends", doc.quantum_backends.join(", ")],
    ];
    document.getElementById("doctorMatrix").innerHTML = rows
      .map(([k, v]) => `<div class="matrix-row"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`)
      .join("");
  }

  function connectSse() {
    if (state.sse) {
      state.sse.close();
    }
    const pill = document.getElementById("sseStatusPill");
    const url = state.token ? `/api/events/stream?token=${encodeURIComponent(state.token)}` : "/api/events/stream";
    const es = new EventSource(url);
    state.sse = es;

    es.onopen = () => {
      pill.textContent = "LIVE SSE STREAM";
      pill.className = "pill pill-live ok";
    };
    es.addEventListener("overview", (e) => {
      try {
        renderOverview(JSON.parse(e.data));
      } catch (_err) {}
    });
    es.addEventListener("bus_event", (e) => {
      if (state.eventsPaused) return;
      try {
        const env = JSON.parse(e.data);
        state.events.unshift(env);
        if (state.events.length > 250) state.events.pop();
        renderEventsFeed();
      } catch (_err) {}
    });
    es.onerror = () => {
      pill.textContent = "SSE RECONNECTING...";
      pill.className = "pill pill-live warn";
    };
  }

  /* Configuration Center ("Configure Everything") */
  async function loadConfigCenter() {
    const bundle = await api("/api/config");
    state.configBundle = bundle;
    document.getElementById("configPathLabel").textContent = bundle.config_file_path;
    document.getElementById("rawYamlTextarea").value = bundle.yaml;
    renderConfigSections(bundle.config);
  }

  function renderFieldInput(fullPath, val) {
    if (ENUM_OPTIONS[fullPath]) {
      const opts = ENUM_OPTIONS[fullPath]
        .map((o) => `<option value="${esc(o)}" ${String(val) === o ? "selected" : ""}>${esc(o)}</option>`)
        .join("");
      return `<select class="input" data-cfg-path="${esc(fullPath)}" data-cfg-type="string">${opts}</select>`;
    }
    if (typeof val === "boolean") {
      return `<label class="checkbox-row"><input type="checkbox" data-cfg-path="${esc(fullPath)}" data-cfg-type="boolean" ${val ? "checked" : ""} /><span>Enabled</span></label>`;
    }
    if (typeof val === "number") {
      const step = Number.isInteger(val) ? "1" : "any";
      return `<input type="number" step="${step}" class="input mono" data-cfg-path="${esc(fullPath)}" data-cfg-type="${Number.isInteger(val) ? "int" : "float"}" value="${val}" />`;
    }
    if (Array.isArray(val)) {
      return `<input type="text" class="input mono" data-cfg-path="${esc(fullPath)}" data-cfg-type="json_array" value="${esc(JSON.stringify(val))}" title="JSON array (e.g. [1, 3, 5])" />`;
    }
    const isNull = val === null;
    return `<input type="text" class="input mono" data-cfg-path="${esc(fullPath)}" data-cfg-type="nullable_string" placeholder="null" value="${isNull ? "" : esc(val)}" />`;
  }

  function renderConfigSections(cfg) {
    const container = document.getElementById("configFormContainer");
    container.innerHTML = SECTION_META.map((sec) => {
      const entries =
        sec.key === "_root"
          ? sec.keys.map((k) => [k, cfg[k], k])
          : Object.entries(cfg[sec.key] || {}).map(([k, v]) => [k, v, `${sec.key}.${k}`]);
      return `
        <div class="card">
          <div class="card-header"><h2>${esc(sec.title)}</h2></div>
          <div class="cfg-field-grid">
            ${entries
              .map(
                ([k, v, path]) => `
              <div class="cfg-field">
                <div class="cfg-field-label">${esc(k)}</div>
                <div>${renderFieldInput(path, v)}</div>
              </div>`
              )
              .join("")}
          </div>
        </div>`;
    }).join("");
  }

  function collectConfigFromForm() {
    const out = {};
    document.querySelectorAll("[data-cfg-path]").forEach((el) => {
      const path = el.dataset.cfgPath;
      const kind = el.dataset.cfgType;
      let val;
      if (kind === "boolean") {
        val = el.checked;
      } else if (kind === "int") {
        val = parseInt(el.value, 10);
      } else if (kind === "float") {
        val = parseFloat(el.value);
      } else if (kind === "json_array") {
        val = JSON.parse(el.value || "[]");
      } else if (kind === "nullable_string") {
        val = el.value.trim() === "" ? null : el.value;
      } else {
        val = el.value;
      }
      const parts = path.split(".");
      if (parts.length === 1) {
        out[parts[0]] = val;
      } else {
        out[parts[0]] = out[parts[0]] || {};
        out[parts[0]][parts[1]] = val;
      }
    });
    return out;
  }

  function showConfigAlert(msg, ok = false) {
    const banner = document.getElementById("configAlert");
    banner.textContent = msg;
    banner.className = "alert-banner" + (ok ? " ok" : "");
    banner.classList.remove("hidden");
  }

  async function submitConfig(persistYaml) {
    document.getElementById("configAlert").classList.add("hidden");
    try {
      const configObj = collectConfigFromForm();
      const updated = await api("/api/config", {
        method: "PUT",
        body: JSON.stringify({ config: configObj, persist_yaml: persistYaml }),
      });
      state.configBundle = updated;
      document.getElementById("rawYamlTextarea").value = updated.yaml;
      renderConfigSections(updated.config);
      showConfigAlert(
        persistYaml
          ? `Configuration validated, hot-applied to all running services, and saved to ${updated.config_file_path}`
          : "Configuration validated and hot-applied in memory.",
        true
      );
      toast("Configuration applied live");
      refreshAll();
    } catch (err) {
      showConfigAlert(`Validation / Apply Error:\n${err.message}`, false);
      toast("Configuration rejected by validator", true);
    }
  }

  /* Identity & CBOM */
  async function loadIdentityTab() {
    const id = await api("/api/identity");
    const b = id.active_bundle;
    const rows = [
      ["Node ID", b.node_id],
      ["Active Key ID", `${b.key_id} (v${b.key_version})`],
      ["Primary Sig (FIPS 204)", `${b.primary_sig_alg} · ${b.primary_sig_fingerprint.slice(0, 20)}...`],
      ["Fallback Sig (FIPS 205)", `${b.fallback_sig_alg} · ${b.fallback_sig_fingerprint.slice(0, 20)}...`],
      ["Post-Quantum KEM (FIPS 203)", `${b.kem_alg} · ${b.kem_fingerprint.slice(0, 20)}...`],
      ["Classical Hybrid KEX", `X25519 · ${b.x25519_fingerprint.slice(0, 20)}...`],
      ["Secret Key File", id.secret_file],
      ["Hardware Sealed Blob", `${id.sealed_exists ? "PRESENT" : "not sealed"} (${id.sealed_file})`],
    ];
    document.getElementById("identityActiveDetails").innerHTML = rows
      .map(([k, v]) => `<div class="matrix-row"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`)
      .join("");

    const entries = Object.values(id.keyring.keys || {}).sort((x, y) => y.key_version - x.key_version);
    document.querySelector("#keyringTable tbody").innerHTML = entries
      .map(
        (k) => `
      <tr>
        <td>v${k.key_version}</td>
        <td>${esc(k.key_id)}</td>
        <td>${esc(k.primary_sig_alg)}</td>
        <td>${esc(k.primary_sig_fingerprint.slice(0, 24))}...</td>
        <td>${esc(String(k.created_at_utc).slice(0, 19))}Z</td>
        <td><span class="badge ${k.retired_at_utc ? "badge-warn" : ""}">${k.retired_at_utc ? "RETIRED (VERIFIABLE)" : "ACTIVE"}</span></td>
      </tr>`
      )
      .join("");
  }

  /* Module 1: Proof of Reality & Gossip */
  async function loadRealityTab() {
    const [st, gos] = await Promise.all([api("/api/reality/state"), api("/api/gossip")]);
    document.querySelector("#merkleLeavesTable tbody").innerHTML = (st.persisted_leaves || [])
      .map(
        (l) => `
      <tr>
        <td>#${l.leaf_index}</td>
        <td>${esc(l.stamp_id.slice(0, 12))}...</td>
        <td>${esc(l.payload.sensor_id)} / ${esc(l.payload.perception_label)} (${l.payload.confidence})</td>
        <td>${esc(l.algorithm)}</td>
        <td>${esc(l.leaf_hash.slice(0, 20))}...</td>
        <td>${esc(l.created_at.slice(0, 19))}Z</td>
      </tr>`
      )
      .join("");

    const roots = Object.entries(gos.latest_roots || {});
    document.getElementById("gossipResult").innerHTML = `
      <div class="matrix-list">
        <div class="matrix-row"><span>Curve25519 Z85 PubKey</span><strong>${esc(gos.curve_public_key.slice(0, 24))}...</strong></div>
        <div class="matrix-row"><span>Equivocation Alerts</span><strong>${gos.equivocation_alerts.length}</strong></div>
        <div class="matrix-row"><span>Witnessed Checkpoints</span><strong>${gos.checkpoints.length}</strong></div>
        ${roots
          .map(
            ([peer, info]) =>
              `<div class="matrix-row"><span>Peer ${esc(peer)} (size=${info.tree_size})</span><strong>${esc(info.merkle_root.slice(0, 20))}...</strong></div>`
          )
          .join("")}
      </div>`;
  }

  /* Module 4: Quantum Dreamer */
  async function loadDreamerTab() {
    const st = await api("/api/dreamer/state");
    document.querySelector("#dreamProblemsTable tbody").innerHTML = (st.problems || [])
      .map((p) => {
        const sol = p.solution || {};
        const badgeCls = p.status === "SOLVED" ? "" : p.status === "FAILED" ? "badge-err" : "badge-warn";
        const ratio = sol.approximation_ratio != null ? ` (r=${Number(sol.approximation_ratio).toFixed(3)})` : "";
        return `
        <tr>
          <td>${esc(p.problem_id)}</td>
          <td>${esc(p.problem_type)}</td>
          <td>${p.priority}</td>
          <td><span class="badge ${badgeCls}">${esc(p.status)}</span></td>
          <td>${esc(sol.backend_name || "-")}</td>
          <td>${esc(sol.optimal_bitstring || "-")}</td>
          <td>${sol.optimal_energy != null ? Number(sol.optimal_energy).toFixed(3) + ratio : "-"}</td>
          <td>${sol.mitigated_expected_energy != null ? Number(sol.mitigated_expected_energy).toFixed(4) : "-"}</td>
        </tr>`;
      })
      .join("");

    document.querySelector("#policySnapshotsTable tbody").innerHTML = (st.policies || [])
      .map(
        (s) => `
      <tr>
        <td>v${s.version}</td>
        <td>${esc(s.policy_name)}</td>
        <td>${Number(s.validation_score).toFixed(4)}</td>
        <td>${Number(s.baseline_score).toFixed(4)}</td>
        <td><span class="badge ${s.active ? "" : "badge-warn"}">${s.active ? "ACTIVE" : "ROLLED BACK / ARCHIVED"}</span></td>
        <td>${esc(s.source_problem_id || "baseline")}</td>
        <td>${esc(s.snapshot_hash.slice(0, 18))}...</td>
      </tr>`
      )
      .join("");
  }

  /* Module 5: Audit Ledger */
  async function loadAuditLedger() {
    const led = await api("/api/audit?limit=80");
    document.getElementById("auditChainBanner").textContent = led.chain_valid
      ? `SHA-256 Chain Verified (${led.total_records} total records)`
      : "WARNING: SHA-256 Audit Chain Tampering Detected!";
    document.querySelector("#auditLedgerTable tbody").innerHTML = (led.events || [])
      .map(
        (r) => `
      <tr>
        <td>#${r.seq}</td>
        <td>${esc(String(r.created_at).slice(0, 19))}Z</td>
        <td>${esc(r.event_type)}</td>
        <td>${esc(r.actor)}</td>
        <td>${esc(r.prev_hash.slice(0, 16))}...</td>
        <td>${esc(r.entry_hash.slice(0, 16))}...</td>
      </tr>`
      )
      .join("");
  }

  async function refreshAll() {
    try {
      const [ov, rec] = await Promise.all([api("/api/overview"), api("/api/events/recent?limit=80")]);
      renderOverview(ov);
      state.events = rec.events || [];
      renderEventsFeed();
      await loadDoctor();
    } catch (err) {
      toast(err.message, true);
    }
  }

  function bindActions() {
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });

    document.getElementById("refreshAllBtn").addEventListener("click", refreshAll);
    document.getElementById("runDoctorBtn").addEventListener("click", async () => {
      await loadDoctor();
      toast("System diagnostics verified");
    });

    document.getElementById("toggleModeBtn").addEventListener("click", async () => {
      const cur = state.overview?.lifecycle?.mode || "DAY";
      const next = cur === "DAY" ? "NIGHT" : "DAY";
      await api("/api/lifecycle/mode", {
        method: "POST",
        body: JSON.stringify({ mode: next, reason: "dashboard_header_toggle" }),
      });
      toast(`Switched operating mode to ${next}`);
      await refreshAll();
    });

    document.getElementById("eventFilterInput").addEventListener("input", renderEventsFeed);
    document.getElementById("pauseEventsBtn").addEventListener("click", (e) => {
      state.eventsPaused = !state.eventsPaused;
      e.target.textContent = state.eventsPaused ? "Resume" : "Pause";
    });
    document.getElementById("clearEventsBtn").addEventListener("click", () => {
      state.events = [];
      renderEventsFeed();
    });

    /* Auth Modal */
    document.getElementById("authTokenBtn").addEventListener("click", () => {
      document.getElementById("authTokenInput").value = state.token;
      document.getElementById("authModal").classList.remove("hidden");
    });
    document.getElementById("closeAuthModalBtn").addEventListener("click", () => {
      document.getElementById("authModal").classList.add("hidden");
    });
    document.getElementById("saveAuthTokenBtn").addEventListener("click", () => {
      state.token = document.getElementById("authTokenInput").value.trim();
      localStorage.setItem("qaegis_dashboard_token", state.token);
      document.getElementById("authModal").classList.add("hidden");
      connectSse();
      refreshAll();
    });

    /* Config Center */
    document.getElementById("saveConfigBtn").addEventListener("click", () => submitConfig(true));
    document.getElementById("applyMemoryConfigBtn").addEventListener("click", () => submitConfig(false));
    document.getElementById("reloadConfigBtn").addEventListener("click", loadConfigCenter);
    document.getElementById("resetConfigBtn").addEventListener("click", async () => {
      const updated = await api("/api/config/reset", { method: "POST", body: JSON.stringify({ persist_yaml: true }) });
      state.configBundle = updated;
      document.getElementById("rawYamlTextarea").value = updated.yaml;
      renderConfigSections(updated.config);
      showConfigAlert("Subsystem configuration reset to defaults and applied live.", true);
      toast("Defaults restored");
    });
    document.getElementById("toggleYamlEditorBtn").addEventListener("click", () => {
      document.getElementById("rawYamlCard").classList.toggle("hidden");
    });
    document.getElementById("applyRawYamlBtn").addEventListener("click", async () => {
      try {
        const yamlText = document.getElementById("rawYamlTextarea").value;
        const updated = await api("/api/config/yaml", {
          method: "POST",
          body: JSON.stringify({ yaml: yamlText, persist_yaml: true }),
        });
        state.configBundle = updated;
        renderConfigSections(updated.config);
        showConfigAlert(`YAML configuration validated, applied live, and persisted to ${updated.config_file_path}`, true);
        toast("YAML applied live");
      } catch (err) {
        showConfigAlert(`YAML Validation Error:\n${err.message}`, false);
      }
    });
    document.getElementById("downloadYamlBtn").addEventListener("click", () => {
      const blob = new Blob([document.getElementById("rawYamlTextarea").value || ""], { type: "text/yaml" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "qaegis.yaml";
      a.click();
    });

    /* Identity & CBOM */
    document.getElementById("rotateKeysForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await api("/api/identity/rotate", {
          method: "POST",
          body: JSON.stringify({
            seal_backend: document.getElementById("rotSealBackend").value,
            token_label: document.getElementById("rotTokenLabel").value || null,
            user_pin: document.getElementById("rotPin").value || null,
            remove_plaintext: document.getElementById("rotRemovePlain").checked,
          }),
        });
        toast("Zero-downtime PQC key rotation completed");
        await loadIdentityTab();
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("loadCbomBtn").addEventListener("click", async () => {
      const fmt = document.getElementById("cbomFormatSelect").value;
      const doc = await api(`/api/identity/cbom?format=${encodeURIComponent(fmt)}`);
      state.lastCbom = doc;
      document.getElementById("cbomOutput").textContent = JSON.stringify(doc, null, 2);
    });
    document.getElementById("downloadCbomBtn").addEventListener("click", async () => {
      const fmt = document.getElementById("cbomFormatSelect").value;
      const doc = state.lastCbom || (await api(`/api/identity/cbom?format=${encodeURIComponent(fmt)}`));
      const blob = new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `qaegis-cbom-${fmt}.json`;
      a.click();
    });

    /* Module 1: Proof of Reality */
    document.getElementById("createStampForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const meta = JSON.parse(document.getElementById("stampMeta").value || "{}");
        const stamp = await api("/api/reality/stamp", {
          method: "POST",
          body: JSON.stringify({
            sensor_id: document.getElementById("stampSensor").value,
            perception_label: document.getElementById("stampLabel").value,
            confidence: parseFloat(document.getElementById("stampConf").value),
            metadata: meta,
            use_stateless_hash_sig: document.getElementById("stampStateless").checked,
          }),
        });
        document.getElementById("verifyStampInput").value = JSON.stringify(stamp, null, 2);
        toast(`Reality Stamp signed (${stamp.algorithm}) & Merkle anchored`);
        await loadRealityTab();
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("verifyStampBtn").addEventListener("click", async () => {
      try {
        const raw = JSON.parse(document.getElementById("verifyStampInput").value);
        const res = await api("/api/reality/verify", {
          method: "POST",
          body: JSON.stringify({ stamp: raw }),
        });
        document.getElementById("verifyStampResult").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>Overall Cryptographic Validity</span><strong style="color:${res.valid ? "var(--emerald)" : "var(--rose)"}">${res.valid}</strong></div>
            <div class="matrix-row"><span>Payload SHA-256 Match</span><strong>${res.payload_hash_ok}</strong></div>
            <div class="matrix-row"><span>Keyring / Fingerprint Match</span><strong>${res.fingerprint_ok}</strong></div>
            <div class="matrix-row"><span>${esc(res.algorithm)} Signature</span><strong>${res.signature_ok}</strong></div>
            <div class="matrix-row"><span>Leaf-Bound Merkle Proof</span><strong>${res.merkle_proof_ok}</strong></div>
            ${res.error ? `<div class="matrix-row"><span>Diagnostic</span><strong>${esc(res.error)}</strong></div>` : ""}
          </div>`;
      } catch (err) {
        toast(`Verification error: ${err.message}`, true);
      }
    });

    document.getElementById("runQrngBtn").addEventListener("click", async () => {
      try {
        const q = await api("/api/reality/qrng", { method: "POST", body: JSON.stringify({ num_bytes: 128 }) });
        const tests = q.health_report.tests || [];
        document.getElementById("qrngResult").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>Sources XOR-Mixed</span><strong>${esc(q.sources.join(" + "))}</strong></div>
            <div class="matrix-row"><span>Min-Entropy (bits/byte)</span><strong>${Number(q.health_report.min_entropy_bits_per_byte).toFixed(3)}</strong></div>
            <div class="matrix-row"><span>Sample Hex (first 32B)</span><strong>${esc(q.raw_hex.slice(0, 64))}...</strong></div>
            ${tests
              .map(
                (t) =>
                  `<div class="matrix-row"><span>${esc(t.name)}</span><strong>${t.passed ? "PASS" : "FAIL"} (${t.p_value != null ? "p=" + Number(t.p_value).toFixed(4) : "stat=" + Number(t.statistic).toFixed(2)})</strong></div>`
              )
              .join("")}
          </div>`;
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("signGossipBtn").addEventListener("click", async () => {
      await api("/api/gossip/checkpoint", { method: "POST", body: "{}" });
      toast("Signed & persisted local ML-DSA-65 Merkle gossip checkpoint");
      await loadRealityTab();
    });

    document.getElementById("signArtifactForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const bundle = await api("/api/reality/sign-artifact", {
          method: "POST",
          body: JSON.stringify({
            artifact_name: document.getElementById("artifactNameInput").value,
            content_text: document.getElementById("artifactContentInput").value,
            use_stateless_hash_sig: document.getElementById("artifactStatelessSelect").value === "true",
          }),
        });
        document.getElementById("artifactBundleOutput").value = JSON.stringify(bundle, null, 2);
        toast(`Signed detached bundle (${bundle.algorithm})`);
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("verifyArtifactBtn").addEventListener("click", async () => {
      try {
        const bundle = JSON.parse(document.getElementById("artifactBundleOutput").value);
        const res = await api("/api/reality/verify-artifact", {
          method: "POST",
          body: JSON.stringify({
            bundle,
            content_text: document.getElementById("artifactContentInput").value,
          }),
        });
        document.getElementById("verifyArtifactResult").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>Overall Validity</span><strong style="color:${res.valid ? "var(--emerald)" : "var(--rose)"}">${res.valid}</strong></div>
            <div class="matrix-row"><span>SHA-256 + SHA3-256 Match</span><strong>${res.digest_ok} (size_ok=${res.size_ok})</strong></div>
            <div class="matrix-row"><span>Keyring / Fingerprint</span><strong>${res.fingerprint_ok} (v${res.key_version})</strong></div>
            <div class="matrix-row"><span>${esc(res.algorithm)} Signature</span><strong>${res.signature_ok}</strong></div>
            ${res.error ? `<div class="matrix-row"><span>Diagnostic</span><strong>${esc(res.error)}</strong></div>` : ""}
          </div>`;
      } catch (err) {
        toast(`Artifact verification error: ${err.message}`, true);
      }
    });

    document.getElementById("downloadArtifactSigBtn").addEventListener("click", () => {
      const txt = document.getElementById("artifactBundleOutput").value;
      if (!txt) {
        toast("Sign an artifact bundle first", true);
        return;
      }
      const name = document.getElementById("artifactNameInput").value || "artifact.bin";
      const blob = new Blob([txt], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `${name}.sig.json`;
      a.click();
    });

    /* Module 2: Chameleon Firewall */
    document.getElementById("chameleonForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const res = await api("/api/chameleon/protect", {
          method: "POST",
          body: JSON.stringify({
            protocol: document.getElementById("chamProtocol").value,
            sensitivity: document.getElementById("chamSensitivity").value,
            retention_years: parseFloat(document.getElementById("chamRetention").value),
            minimum_tier: document.getElementById("chamFloor").value || null,
            payload_text: document.getElementById("chamPayload").value,
          }),
        });
        const a = res.assessment;
        const env = res.envelope;
        document.getElementById("chameleonResult").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>Selected Security Tier</span><strong>${esc(a.tier)}</strong></div>
            <div class="matrix-row"><span>Composite Risk Score</span><strong>${Number(a.risk_score).toFixed(4)} (anom=${Number(a.anomaly_score).toFixed(3)}, HNDL=${Number(a.hndl_probability).toFixed(3)})</strong></div>
            <div class="matrix-row"><span>Cipher Suite</span><strong>${esc(env.cipher_suite)}</strong></div>
            <div class="matrix-row"><span>Post-Quantum KEM / Sig</span><strong>${esc(env.kem_alg || "Classical X25519")} / ${esc(env.sig_alg || "AEAD-only")}</strong></div>
            <div class="matrix-row"><span>Wire Size / Round-Trip</span><strong>${res.wire_size_bytes} B · ${res.roundtrip_latency_ms} ms (verified=${res.roundtrip_verified})</strong></div>
            <div class="matrix-row"><span>Escalation Reasons</span><strong>${esc((a.reasons || []).join(", ") || "baseline")}</strong></div>
          </div>`;
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    });

    /* Module 3: Qubit Compiler */
    document.getElementById("compileVectorForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const vec = document
          .getElementById("compVector")
          .value.split(",")
          .map((s) => parseFloat(s.trim()))
          .filter((n) => !Number.isNaN(n));
        const res = await api("/api/compiler/compile", {
          method: "POST",
          body: JSON.stringify({
            vector: vec,
            run_pennylane: document.getElementById("compPennyLane").checked,
          }),
        });
        const art = res.artifact;
        document.getElementById("compilerMetrics").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>Encoder Backend</span><strong>${esc(res.angles.encoder_backend)} (${res.compile_latency_ms} ms)</strong></div>
            <div class="matrix-row"><span>Transpiled Circuit</span><strong>${art.num_qubits}q · depth=${art.depth} · CX=${art.two_qubit_gate_count} (${esc(art.entanglement_pattern)})</strong></div>
            <div class="matrix-row"><span>Estimated NISQ Fidelity</span><strong>${Number(art.estimated_fidelity).toFixed(4)}</strong></div>
          </div>`;
        document.getElementById("qasmOutput").textContent = art.openqasm3;

        let vizHtml = `<div class="matrix-list">`;
        res.angles.angles_rad.forEach((row, q) => {
          vizHtml += `<div class="matrix-row"><span>Qubit q[${q}] (Rx, Ry, Rz)</span><strong>(${row.map((v) => Number(v).toFixed(3)).join(", ")}) rad</strong></div>`;
        });
        if (res.pennylane) {
          vizHtml += `<div class="matrix-row"><span>PennyLane Pauli-Z &lt;Z_q&gt;</span><strong>[${res.pennylane.pauli_z_expectations.map((v) => Number(v).toFixed(3)).join(", ")}]</strong></div>`;
          const topStates = res.pennylane.probabilities
            .map((p, idx) => [idx.toString(2).padStart(art.num_qubits, "0"), p])
            .sort((a, b) => b[1] - a[1])
            .slice(0, 6);
          topStates.forEach(([bs, p]) => {
            const pct = (p * 100).toFixed(1);
            vizHtml += `
              <div class="hist-row">
                <span>|${bs}⟩</span>
                <div class="meter" style="margin:0;"><div class="meter-fill meter-cyan" style="width:${pct}%"></div></div>
                <span>${pct}%</span>
              </div>`;
          });
        }
        vizHtml += `</div>`;
        document.getElementById("pennylaneViz").innerHTML = vizHtml;
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("trainEncoderForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      toast("Training PyTorch autoencoder & exporting ONNX...");
      try {
        const res = await api("/api/compiler/train", {
          method: "POST",
          body: JSON.stringify({
            epochs: parseInt(document.getElementById("trainEpochs").value, 10),
            samples_count: parseInt(document.getElementById("trainSamples").value, 10),
          }),
        });
        document.getElementById("trainEncoderResult").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>MSE Reconstruction Loss</span><strong>${res.initial_loss} → ${res.final_loss}</strong></div>
            <div class="matrix-row"><span>Training + ONNX Export Time</span><strong>${res.elapsed_ms} ms</strong></div>
            <div class="matrix-row"><span>Self-Contained ONNX Path</span><strong>${esc(res.onnx_path)}</strong></div>
          </div>`;
        toast("ONNX encoder trained and hot-activated");
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("copyQasmBtn").addEventListener("click", () => {
      navigator.clipboard?.writeText(document.getElementById("qasmOutput").textContent || "");
      toast("OpenQASM 3.0 copied to clipboard");
    });

    /* Module 4: Quantum Dreamer */
    document.getElementById("enqueueDreamForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const res = await api("/api/dreamer/enqueue", {
          method: "POST",
          body: JSON.stringify({
            kind: document.getElementById("dreamKind").value,
            num_nodes: parseInt(document.getElementById("dreamNodes").value, 10),
            priority: parseInt(document.getElementById("dreamPriority").value, 10),
            policy_name: document.getElementById("dreamPolicy").value,
          }),
        });
        toast(`Queued ${res.problem_id} in SQLite WAL`);
        await loadDreamerTab();
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("runNightForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      toast("Running Night-Mode QAOA optimization...");
      try {
        const rep = await api("/api/dreamer/run-night", {
          method: "POST",
          body: JSON.stringify({
            backend: document.getElementById("dreamBackend").value,
            mitigation: document.getElementById("dreamMitigation").value,
            max_problems: parseInt(document.getElementById("dreamMaxBatch").value, 10),
          }),
        });
        toast(`Night cycle solved ${rep.solutions.length} QUBO problem(s)`);
        await loadDreamerTab();
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("runFederatedForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      toast("Running Federated Fleet QAOA deduplication cycle...");
      try {
        const rep = await api("/api/dreamer/federated", {
          method: "POST",
          body: JSON.stringify({
            fleet_nodes: parseInt(document.getElementById("fedNodes").value, 10),
            budget_seconds: parseFloat(document.getElementById("fedBudget").value),
          }),
        });
        document.getElementById("federatedResult").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>Submissions → Unique Solved</span><strong>${rep.submissions_received} → ${rep.unique_problems_solved} (saved ${rep.deduplicated_count} QPU runs)</strong></div>
            <div class="matrix-row"><span>ML-DSA-65 Signed Broadcasts</span><strong>${rep.broadcasts.length}</strong></div>
          </div>`;
        toast("Federated QAOA cycle completed");
      } catch (err) {
        toast(err.message, true);
      }
    });

    /* Module 5: Quantum Entropy & Audit */
    document.getElementById("harvestEntropyForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const b = await api("/api/entropy/harvest", {
          method: "POST",
          body: JSON.stringify({
            num_qubits: parseInt(document.getElementById("entQubits").value, 10),
            shots: parseInt(document.getElementById("entShots").value, 10),
            noise_rate: parseFloat(document.getElementById("entNoise").value),
          }),
        });
        const top = Object.entries(b.probabilities || {})
          .sort((x, y) => y[1] - x[1])
          .slice(0, 8);
        document.getElementById("entropyHarvestResult").innerHTML = `
          <div class="matrix-list">
            <div class="matrix-row"><span>Shannon Entropy</span><strong>${Number(b.shannon_entropy_bits).toFixed(4)} bits (${b.pool_bytes} B pool)</strong></div>
            <div class="matrix-row"><span>Sources</span><strong>${esc(b.sources.join(" + "))}</strong></div>
            <div class="matrix-row"><span>Mixed Hex (24B)</span><strong>${esc(b.qrng_mixed_hex.slice(0, 48))}...</strong></div>
          </div>
          <div style="margin-top:0.65rem;">
            ${top
              .map(([bs, p]) => {
                const pct = (p * 100).toFixed(1);
                return `<div class="hist-row"><span>|${esc(bs)}⟩</span><div class="meter" style="margin:0;"><div class="meter-fill" style="width:${Math.min(100, p * 300)}%"></div></div><span>${pct}%</span></div>`;
              })
              .join("")}
          </div>`;
      } catch (err) {
        toast(err.message, true);
      }
    });

    document.getElementById("runSampleLogitsBtn").addEventListener("click", async () => {
      const res = await api("/api/entropy/sample-logits", { method: "POST", body: "{}" });
      document.getElementById("entropyAgentResult").innerHTML = `
        <div class="matrix-list">
          <div class="matrix-row"><span>Quantum Nucleus Selected Token</span><strong>index #${res.token_index} (prob=${Number(res.token_probability).toFixed(4)})</strong></div>
          <div class="matrix-row"><span>Candidate Nucleus Size / Temp</span><strong>${res.candidate_count} tokens · T=${res.effective_temperature}</strong></div>
        </div>`;
    });

    document.getElementById("runEvolutionBtn").addEventListener("click", async () => {
      const res = await api("/api/entropy/evolve", { method: "POST", body: "{}" });
      document.getElementById("entropyAgentResult").innerHTML = `
        <div class="matrix-list">
          <div class="matrix-row"><span>Best Fitness (${res.generations} gens)</span><strong>${Number(res.best_fitness).toFixed(5)}</strong></div>
          <div class="matrix-row"><span>Population Diversity</span><strong>${Number(res.population_diversity).toFixed(5)}</strong></div>
          <div class="matrix-row"><span>Best Genome</span><strong>[${res.best_genome.map((v) => Number(v).toFixed(3)).join(", ")}]</strong></div>
        </div>`;
    });

    document.getElementById("checkOllamaBtn").addEventListener("click", async () => {
      const res = await api("/api/entropy/ollama");
      document.getElementById("entropyAgentResult").innerHTML = `
        <div class="matrix-list">
          <div class="matrix-row"><span>Ollama Runtime Endpoint</span><strong>${esc(res.endpoint)}</strong></div>
          <div class="matrix-row"><span>Reachable</span><strong>${res.reachable}</strong></div>
          <div class="matrix-row"><span>Available Models</span><strong>${esc((res.available_models || []).join(", ") || "none (offline)")}</strong></div>
        </div>`;
    });

    document.getElementById("refreshAuditBtn").addEventListener("click", loadAuditLedger);
    document.getElementById("loadMetricsBtn").addEventListener("click", async () => {
      const txt = await api("/api/metrics/raw");
      document.getElementById("prometheusOutput").textContent = txt;
    });
  }

  document.addEventListener("DOMContentLoaded", async () => {
    bindActions();
    try {
      const auth = await fetch("/api/auth-status").then((r) => r.json());
      if (auth.auth_required && !state.token) {
        document.getElementById("authModal").classList.remove("hidden");
      }
    } catch (_e) {}
    connectSse();
    await refreshAll();
  });
})();
