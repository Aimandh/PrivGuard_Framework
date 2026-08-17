(function () {
  "use strict";

  const els = {
    promptInput: document.getElementById("promptInput"),
    analyzeButton: document.getElementById("analyzeButton"),
    sendButton: document.getElementById("sendButton"),
    clearButton: document.getElementById("clearButton"),
    toggleReportButton: document.getElementById("toggleReportButton"),
    copyReportButton: document.getElementById("copyReportButton"),
    riskBadge: document.getElementById("riskBadge"),
    riskFill: document.getElementById("riskFill"),
    riskBefore: document.getElementById("riskBefore"),
    riskAfter: document.getElementById("riskAfter"),
    sendAllowed: document.getElementById("sendAllowed"),
    categoryChips: document.getElementById("categoryChips"),
    actionChips: document.getElementById("actionChips"),
    sanitizedPrompt: document.getElementById("sanitizedPrompt"),
    responseBox: document.getElementById("responseBox"),
    reportBox: document.getElementById("reportBox"),
    providerMode: document.getElementById("providerMode"),
    providerDot: document.getElementById("providerDot"),
    apiKeyInput: document.getElementById("apiKeyInput"),
    modelSelect: document.getElementById("modelSelect"),
    modelInput: document.getElementById("modelInput"),
    customModelRow: document.getElementById("customModelRow"),
  };

  let currentReport = {
    original_risk_score: 0,
    sanitized_risk_score: 0,
    risk_level_before: "Low",
    risk_level_after: "Low",
    detected_categories: [],
    actions_applied: [],
    sanitized_text: "",
    send_to_llm: true,
    notes: [],
  };
  let debounceTimer = null;
  let backendMode = "mock";
  let backendReady = false;
  let reportVisible = false;

  /** Return the currently selected OpenRouter model slug. */
  function selectedModel() {
    if (els.modelSelect.value === "__custom__") {
      return (els.modelInput.value || "").trim();
    }
    return els.modelSelect.value;
  }

  function setReportVisible(isVisible) {
    reportVisible = isVisible;
    els.reportBox.hidden = !isVisible;
    els.copyReportButton.hidden = !isVisible;
    els.toggleReportButton.textContent = isVisible ? "Hide report" : "Show report";
    els.toggleReportButton.setAttribute("aria-expanded", String(isVisible));
  }

  function setReportPayload(payload) {
    els.reportBox.textContent = JSON.stringify(payload, null, 2);
  }

  function renderChips(container, values, emptyText) {
    container.textContent = "";
    if (!values || !values.length) {
      const span = document.createElement("span");
      span.className = "muted";
      span.textContent = emptyText;
      container.appendChild(span);
      return;
    }
    for (const value of values) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = value;
      container.appendChild(chip);
    }
  }

  function riskClass(score) {
    if (score <= 20) return "low";
    if (score <= 50) return "medium";
    if (score <= 80) return "high";
    return "critical";
  }

  function renderReport(report) {
    currentReport = report;
    els.riskBefore.textContent = String(report.original_risk_score);
    els.riskAfter.textContent = String(report.sanitized_risk_score);
    els.sendAllowed.textContent = report.send_to_llm ? "Yes" : "No";
    els.riskBadge.textContent = `${report.risk_level_before} -> ${report.risk_level_after}`;

    const width = Math.max(report.original_risk_score, report.sanitized_risk_score);
    els.riskFill.style.width = `${Math.min(100, width)}%`;
    els.riskFill.className = `risk-fill ${riskClass(report.original_risk_score)}`;

    renderChips(els.categoryChips, report.detected_categories, "None detected");
    renderChips(els.actionChips, report.actions_applied, "None");
    els.sanitizedPrompt.textContent = report.sanitized_text || "The sanitized prompt will appear here.";
    setReportPayload({
      model: selectedModel() || "(server default)",
      client_input_report: report,
    });
  }

  async function analyzeLocal() {
    const text = els.promptInput.value;
    if (!text.trim()) {
      renderReport({
        original_risk_score: 0,
        sanitized_risk_score: 0,
        risk_level_before: "Low",
        risk_level_after: "Low",
        detected_categories: [],
        actions_applied: [],
        sanitized_text: "",
        send_to_llm: true,
        notes: [],
      });
      return;
    }

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        cache: "no-store",
        body: JSON.stringify({ text, stage: "input" }),
      });
      if (!response.ok) throw new Error("Analysis failed");
      const report = await response.json();
      renderReport(report);
      currentReport = report;
    } catch (error) {
      console.error("Analysis error:", error);
      const fallback = window.PrivacyEngine.analyzeAndSanitize(text, "input");
      renderReport(fallback);
      currentReport = fallback;
    }
    return currentReport;
  }

  function setBusy(isBusy) {
    els.sendButton.disabled = isBusy;
    els.analyzeButton.disabled = isBusy;
    els.clearButton.disabled = isBusy;
    els.sendButton.textContent = isBusy ? "Processing..." : "Sanitize and send";
  }

  async function refreshHealth() {
    try {
      const response = await fetch("/api/health", { cache: "no-store" });
      if (!response.ok) throw new Error("Health check failed");
      const data = await response.json();
      backendMode = data.provider_mode || "mock";
      backendReady = true;
      els.providerMode.textContent = `Provider: OpenRouter (${backendMode} mode)`;
      els.providerDot.classList.add("ready");
    } catch (error) {
      backendReady = false;
      els.providerMode.textContent = "Backend unavailable";
      els.providerDot.classList.remove("ready");
    }
  }

  async function sendChat() {
    const text = els.promptInput.value.trim();
    if (!text) {
      els.responseBox.textContent = "Please enter a prompt.";
      return;
    }

    setBusy(true);
    els.responseBox.textContent = "Sending sanitized prompt to backend relay...";

    try {
      const body = {
        sanitized_prompt: text,
      };

      const model = selectedModel();
      if (model) body.model = model;

      const apiKey = (els.apiKeyInput.value || "").trim();
      if (apiKey) body.api_key = apiKey;

      if (currentReport.send_to_llm) {
        body.client_report = {
          original_risk_score: currentReport.original_risk_score,
          sanitized_risk_score: currentReport.sanitized_risk_score,
          detected_categories: currentReport.detected_categories,
          actions_applied: currentReport.actions_applied,
        };
      }

      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        cache: "no-store",
        body: JSON.stringify(body),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Chat request failed");

      if (data.input_guard_report) {
        renderReport(data.input_guard_report);
        currentReport = data.input_guard_report;
      }

      const finalOutputReport = window.PrivacyEngine.analyzeAndSanitize(data.safe_response || "", "output");
      els.responseBox.textContent = finalOutputReport.sanitized_text;

      const mergedReport = {
        model: data.model || model || "(server default)",
        provider_mode: data.provider_mode,
        client_input_report: currentReport,
        backend_input_guard_report: data.input_guard_report,
        backend_output_guard_report: data.output_guard_report,
        browser_final_output_report: finalOutputReport,
        prompt_sent_to_provider: data.prompt_sent_to_provider,
      };
      setReportPayload(mergedReport);
    } catch (error) {
      const rawDetail = error?.message || String(error);
      if (rawDetail.includes("HTTPStatusError") || rawDetail.includes("Provider returned")) {
        els.responseBox.textContent = `Provider error: ${rawDetail}`;
      } else {
        els.responseBox.textContent = `Error: ${rawDetail}`;
      }
    } finally {
      setBusy(false);
    }
  }

  els.modelSelect.addEventListener("change", () => {
    const isCustom = els.modelSelect.value === "__custom__";
    els.customModelRow.classList.toggle("hidden", !isCustom);
    if (isCustom) els.modelInput.focus();
  });

  els.promptInput.addEventListener("input", () => {
    window.clearTimeout(debounceTimer);
    debounceTimer = window.setTimeout(analyzeLocal, 150);
  });

  els.analyzeButton.addEventListener("click", analyzeLocal);
  els.sendButton.addEventListener("click", sendChat);
  els.clearButton.addEventListener("click", () => {
    els.promptInput.value = "";
    els.responseBox.textContent = "The privacy-checked response will appear here.";
    renderReport(window.PrivacyEngine.analyzeAndSanitize("", "input"));
    setReportVisible(false);
  });
  els.toggleReportButton.addEventListener("click", () => {
    setReportVisible(!reportVisible);
  });
  els.copyReportButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(els.reportBox.textContent);
      els.copyReportButton.textContent = "Copied";
      window.setTimeout(() => { els.copyReportButton.textContent = "Copy report"; }, 1000);
    } catch (error) {
      els.copyReportButton.textContent = "Copy failed";
      window.setTimeout(() => { els.copyReportButton.textContent = "Copy report"; }, 1000);
    }
  });

  setReportVisible(false);
  renderReport(currentReport);
  refreshHealth();
}());
