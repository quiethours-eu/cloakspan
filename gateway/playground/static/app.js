"use strict";

const $ = (id) => document.getElementById(id);
const examples = {
  email: "Please reply to alex@example.com about tomorrow's meeting.",
  card: "Test card: 4111 1111 1111 1111. Please check the formatting.",
  secret: "Example credential: AKIAIOSFODNN7EXAMPLE. Do not use real keys here.",
  national: "Synthetic Latvian personal code: 120385-12342.",
  clean: "Please summarize the public product announcement."
};
let accessCode = "";
let generation = 0;
let activeController = null;
let currentOutput = null;

function message(target, text) { $(target).textContent = text; }
function option(select, value) {
  const item = document.createElement("option");
  item.value = value;
  item.textContent = value;
  select.append(item);
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.headers || {}), Authorization: `Bearer ${accessCode}` },
    cache: "no-store"
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error?.message || "Local request failed.");
  return body;
}
function setWorker(text) { message("worker-status", text); }

$("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const candidate = $("access-code").value.trim();
  if (!candidate) return;
  accessCode = candidate;
  try {
    const status = await api("/api/status");
    $("access-code").value = "";
    $("unlock").hidden = true;
    $("workspace").hidden = false;
    $("fingerprint").textContent = `Config ${status.config_fingerprint}`;
    $("coverage-profile").textContent = `${status.coverage.profile}. Built-ins: ${status.coverage.built_in.join(", ")}. ${status.coverage.custom_filters} custom filter(s).`;
    const routingLabels = {
      off: "Plain policy routing",
      detected: "Detected-only local routing",
      all: "All-local routing"
    };
    $("routing-mode").textContent = routingLabels[status.routing_mode] || status.routing_mode;
    const warnings = $("coverage-warnings");
    for (const warning of status.warnings) {
      const item = document.createElement("li");
      item.textContent = warning;
      warnings.append(item);
    }
    for (const role of status.roles) option($("role"), role);
    $("role").value = "user";
    for (const application of status.applications) option($("application"), application);
    $("application").value = "default";
    $("input-text").maxLength = status.limits.text_chars;
    setWorker(status.worker === "ready" ? "Ready for local inspection" : "Worker recovering");
    $("input-text").focus();
  } catch (error) {
    accessCode = "";
    message("unlock-message", error.message);
  }
});

function invalidate() {
  generation += 1;
  if (activeController) activeController.abort();
  activeController = null;
  $("inspect").disabled = false;
  if (!$("result").hidden) $("stale-badge").hidden = false;
  $("text-count").textContent = `${Array.from($("input-text").value).length} characters`;
}
$("input-text").addEventListener("input", invalidate);
$("role").addEventListener("change", invalidate);
$("application").addEventListener("change", invalidate);
$("samples").addEventListener("change", () => {
  if (!$("samples").value) return;
  $("input-text").value = examples[$("samples").value];
  invalidate();
  message("request-message", "Example loaded. Custom policy may produce a different decision.");
});

function appendText(parent, text) { parent.append(document.createTextNode(text)); }
function renderHighlights(text, detections) {
  const target = $("highlighted-text");
  target.replaceChildren();
  const points = Array.from(text);
  let cursor = 0;
  for (const detection of detections) {
    const start = detection.start;
    const end = detection.end;
    if (start < cursor || end > points.length || start >= end) continue;
    appendText(target, points.slice(cursor, start).join(""));
    const mark = document.createElement("mark");
    mark.textContent = points.slice(start, end).join("");
    mark.title = detection.entity_type;
    target.append(mark);
    cursor = end;
  }
  appendText(target, points.slice(cursor).join(""));
}
function renderResult(result, original) {
  const decision = result.decision;
  $("result").hidden = false;
  $("stale-badge").hidden = true;
  $("decision-action").textContent = decision.effective_action.replace("_", " ");
  $("decision-destination").textContent = decision.destination || "None — blocked";
  $("decision-rule").textContent = decision.effective_rule;
  let explanation = `Base rule ${decision.base_rule} chose ${decision.base_action}.`;
  if (decision.routing_override_reason) explanation += ` Routing override: ${decision.routing_override_reason}.`;
  explanation += ` Policy version: ${decision.policy_version}.`;
  $("decision-explanation").textContent = explanation;
  const detections = result.detections.slice().sort((a, b) => a.start - b.start);
  renderHighlights(original, detections);
  const list = $("detection-list");
  list.replaceChildren();
  for (const detection of detections) {
    const item = document.createElement("li");
    item.textContent = `${detection.entity_type} · ${detection.detector} · ${detection.start}–${detection.end} · score ${detection.score}`;
    list.append(item);
  }
  $("no-detections").hidden = detections.length > 0;
  currentOutput = result.outbound_preview?.text ?? null;
  $("outbound-text").textContent = currentOutput ?? "Blocked before any request would be sent.";
  $("model-line").textContent = result.outbound_preview ? `Effective model: ${result.outbound_preview.model}` : "No model selected.";
  $("copy").hidden = currentOutput === null;
  setWorker("Ready for local inspection");
}

async function waitForWorker() {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    try {
      const status = await api("/api/status");
      if (status.worker === "ready") { setWorker("Ready for local inspection"); return; }
    } catch { return; }
  }
}

$("inspect").addEventListener("click", async () => {
  const text = $("input-text").value;
  const role = $("role").value;
  const application = $("application").value;
  const requestGeneration = ++generation;
  const controller = new AbortController();
  activeController = controller;
  $("inspect").disabled = true;
  setWorker("Inspecting locally…");
  message("request-message", "Inspecting locally…");
  try {
    const result = await api("/api/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, role, application }),
      signal: controller.signal
    });
    if (requestGeneration !== generation) return;
    renderResult(result, text);
    message("request-message", `Preview complete in ${result.inspection_ms} ms. No provider contacted.`);
  } catch (error) {
    if (requestGeneration !== generation || error.name === "AbortError") return;
    message("request-message", error.message);
    if (error.message.includes("worker") || error.message.includes("timed out")) {
      setWorker("Worker recovering");
      void waitForWorker();
    } else setWorker("Ready for local inspection");
  } finally {
    if (requestGeneration === generation) {
      activeController = null;
      $("inspect").disabled = false;
    }
  }
});

$("clear").addEventListener("click", () => {
  invalidate();
  $("input-text").value = "";
  $("samples").value = "";
  $("result").hidden = true;
  $("highlighted-text").replaceChildren();
  $("detection-list").replaceChildren();
  $("outbound-text").textContent = "";
  for (const id of ["decision-action", "decision-destination", "decision-rule", "decision-explanation", "model-line"]) {
    $(id).textContent = "";
  }
  currentOutput = null;
  $("inspect").disabled = false;
  message("request-message", "Cleared from this page.");
  $("text-count").textContent = "0 characters";
  $("input-text").focus();
});

$("copy").addEventListener("click", async () => {
  if (currentOutput === null) return;
  try { await navigator.clipboard.writeText(currentOutput); message("request-message", "Projected text copied."); }
  catch { message("request-message", "Copy was unavailable in this browser."); }
});
