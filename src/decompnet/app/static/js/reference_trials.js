"use strict";
// Owner-only source previews and explicitly consented judged trials; the normal judge remains authoritative.
let trialRevision = 0;
let trialChoiceRequest = 0;
let trialPlan = null;
let trialRunActive = false;
const trialOperations = new Set();
const TRIAL_HISTORY_LIMIT = 20;
const TRIAL_OPERATION_LIMIT = 5;

function trialReset() {
  trialRevision++;
  trialChoiceRequest++;
  trialPlan = null;
  for (const operation of [...trialOperations]) {
    if (operation.kind === "run") operation.root.remove();
    else finishTrialOperation(operation, true);
  }
  for (const id of ["trialSource", "trialFile", "trialTarget", "trialPreview", "trialHistory"]) $(id).replaceChildren();
  for (const id of ["trialName", "trialStart", "trialEnd", "trialMappings", "trialCode", "trialPrelude"]) $(id).value = "";
  $("trialConsent").checked = false;
  $("trialConsent").disabled = true;
  $("trialRun").disabled = true;
  $("trialLog").replaceChildren();
}
window.resetReferenceTrials = trialReset;
window.loadReferenceTrials = loadReferenceTrials;

function trialInvalidate(clearSource = false) {
  trialRevision++;
  trialPlan = null;
  $("trialConsent").checked = false;
  $("trialRun").disabled = true;
  if (clearSource) {
    $("trialCode").value = "";
    $("trialPrelude").value = "";
    $("trialPreview").replaceChildren();
  }
}
function trialCanRun() {
  return !!trialPlan?.ready && $("trialConsent").checked && !trialRunActive;
}
function updateTrialRunButton() {
  const runOwners = referenceControlOwners.get($("trialRun"));
  if (!runOwners || runOwners.owners === 0) $("trialRun").disabled = !trialCanRun();
  const consentOwners = referenceControlOwners.get($("trialConsent"));
  if (!consentOwners || consentOwners.owners === 0) $("trialConsent").disabled = !trialPlan?.ready || trialRunActive;
}
function trialOption(select, value, label, disabled = false) {
  const option = document.createElement("option");
  option.value = String(value); option.textContent = label; option.disabled = disabled;
  select.append(option);
}
function beginTrialOperation(label, controls, completed, kind = "read") {
  const root = document.createElement("div"), log = document.createElement("div"), status = document.createElement("p");
  root.className = "reference-trial-operation"; log.className = "reference-trial-operation-log";
  root.append(log, status); $("trialLog").append(root);
  const operation = { root, log, status, controls, kind, controlsReleased: false, done: false, finishWork: null };
  claimReferenceControls(controls);
  operation.finishWork = beginWork(log, label, [], completed);
  trialOperations.add(operation);
  pruneTrialOperations();
  return operation;
}
function finishTrialOperation(operation, remove = false) {
  if (operation.done) return;
  operation.done = true;
  operation.finishWork();
  releaseReferenceControls(operation.controls, operation);
  trialOperations.delete(operation);
  if (remove) operation.root.remove();
  else pruneTrialOperations();
  updateTrialRunButton();
}
function pruneTrialOperations() {
  const completed = [...$("trialLog").children].filter((root) => ![...trialOperations].some((operation) => operation.root === root));
  while (completed.length > TRIAL_OPERATION_LIMIT) completed.shift().remove();
}
function trialStatus(operation, message) { operation.status.textContent = message; }
function trialFlags(context) {
  if (!context || !Object.prototype.hasOwnProperty.call(context, "flags") || context.flags === null) return "not shown";
  if (Array.isArray(context.flags)) return JSON.stringify(context.flags);
  if (typeof context.flags === "string") return context.flags === "" ? '"" (empty string)' : context.flags;
  return "unknown";
}
function trialError(operation, error) { showJobError(operation.log, error.message || String(error)); }
function trialCurrent(slug, gen, revision) { return slug === S.slug && gen === S.gen && revision === trialRevision; }

async function loadReferenceTrials() {
  if (trialRunActive) return; // Revisiting the tab must not replace controls or status during a non-cancelable run.
  const slug = S.slug, gen = S.gen, pane = $("referencesPane"), request = ++trialChoiceRequest;
  const priorSource = $("trialSource").value, priorFile = $("trialFile").value, priorTarget = $("trialTarget").value;
  const revision = trialRevision;
  try {
    const sources = await api(`/api/references?slug=${encodeURIComponent(slug)}`);
    if (slug !== S.slug || gen !== S.gen || !pane.isConnected || request !== trialChoiceRequest || revision !== trialRevision) return;
    const eligibleSources = (sources.sources || []).filter((source) => source.enabled && !source.stale && ["ready", "partial"].includes(source.status));
    const sourceSelect = $("trialSource"); sourceSelect.replaceChildren();
    for (const source of eligibleSources) trialOption(sourceSelect, source.id, `${source.name} · ${source.kind}`);
    if (!eligibleSources.some((source) => String(source.id) === priorSource)) {
      if (eligibleSources.length) sourceSelect.value = String(eligibleSources[0].id);
      else trialOption(sourceSelect, "", "No enabled, fresh reference sources", true);
    } else sourceSelect.value = priorSource;
    const selectedSource = sourceSelect.value;
    let files = [];
    if (selectedSource) {
      const response = await api(`/api/reference-trials/files?slug=${encodeURIComponent(slug)}&source_id=${encodeURIComponent(selectedSource)}&limit=30`);
      if (slug !== S.slug || gen !== S.gen || request !== trialChoiceRequest || revision !== trialRevision || sourceSelect.value !== selectedSource) return;
      files = response.files || [];
    }
    const fileSelect = $("trialFile"); fileSelect.replaceChildren();
    for (const file of files) trialOption(fileSelect, JSON.stringify(file.origin), `${file.name}${file.has_code ? "" : " · no code"}`, !file.has_code);
    if (files.some((file) => JSON.stringify(file.origin) === priorFile)) fileSelect.value = priorFile;
    const [targetData, history] = await Promise.all([
      api(`/api/reference-trials/targets?slug=${encodeURIComponent(slug)}&limit=50`),
      api(`/api/reference-trials?slug=${encodeURIComponent(slug)}&limit=${TRIAL_HISTORY_LIMIT}`),
    ]);
    if (slug !== S.slug || gen !== S.gen || request !== trialChoiceRequest || revision !== trialRevision) return;
    const targetSelect = $("trialTarget"); targetSelect.replaceChildren();
    for (const target of targetData.targets || []) {
      const label = `${target.name} · ${target.unit || ""}${target.eligible ? "" : ` · ${target.reason || "unavailable"}`}`;
      trialOption(targetSelect, target.id, label, !target.eligible);
    }
    if ((targetData.targets || []).some((target) => String(target.id) === priorTarget)) targetSelect.value = priorTarget;
    renderTrialHistory(history.trials || []);
  } catch (error) {
    if (slug === S.slug && gen === S.gen && request === trialChoiceRequest) {
      const operation = beginTrialOperation("Loading reference trial choices", [], "Choices loaded.");
      trialError(operation, error); finishTrialOperation(operation);
    }
  }
}
function trialOutcomeText(status, outcome) {
  const result = outcome && typeof outcome === "object" ? outcome : {};
  const label = status || (typeof outcome === "string" ? outcome : result.matched === true ? "matched" : result.matched === false ? "nonmatch" : "unknown");
  let text = label;
  if (result.percent != null) text += ` · ${result.percent}%`;
  if (result.text) text += ` · ${String(result.text).slice(0, 240)}`;
  return text;
}
function renderTrialHistory(trials) {
  const root = $("trialHistory"); root.replaceChildren();
  for (const trial of trials.slice(0, TRIAL_HISTORY_LIMIT)) {
    const row = document.createElement("div"), summary = document.createElement("span"), detail = document.createElement("button");
    summary.textContent = `${trialOutcomeText(trial.status, trial.outcome)} · ${trial.target_name || trial.function_id || "function"}`;
    detail.type = "button"; detail.textContent = "Review details";
    detail.onclick = () => loadTrialDetail(trial.id); row.append(summary, detail); root.append(row);
  }
}
async function loadTrialDetail(id) {
  const slug = S.slug, gen = S.gen, request = ++trialChoiceRequest;
  const operation = beginTrialOperation("Loading trial details", [$("trialPrepare")], "Trial details loaded.");
  try {
    const detail = await api(`/api/reference-trials/detail?slug=${encodeURIComponent(slug)}&id=${encodeURIComponent(id)}`);
    if (slug !== S.slug || gen !== S.gen || request !== trialChoiceRequest) return;
    const view = $("trialPreview"); view.replaceChildren();
    const summary = document.createElement("p"); summary.textContent = `${trialOutcomeText(detail.status, detail.outcome)}: ${detail.target_name || detail.function_id || "function"}`; view.append(summary);
    const provenance = document.createElement("p");
    provenance.textContent = `Reference: ${detail.provenance?.source_name || "source unavailable"} · ${detail.provenance?.path || `record ${detail.provenance?.record_id || "?"}`} · lines ${detail.provenance?.start || "?"}–${detail.provenance?.end_line || "?"}`;
    view.append(provenance);
    const source = document.createElement("pre"); source.textContent = detail.source || ""; view.append(source);
    const prelude = document.createElement("pre"); prelude.textContent = detail.prelude || ""; view.append(prelude);
    trialStatus(operation, "Historical code is for review only. Prepare it again before another trial.");
  } catch (error) { if (slug === S.slug && gen === S.gen && request === trialChoiceRequest) trialError(operation, error); }
  finally { finishTrialOperation(operation); }
}
async function loadTrialFiles(slug = S.slug, gen = S.gen, request = trialChoiceRequest) {
  const sourceId = $("trialSource").value;
  if (!sourceId) return;
  const response = await api(`/api/reference-trials/files?slug=${encodeURIComponent(slug)}&source_id=${encodeURIComponent(sourceId)}&limit=30`);
  if (slug !== S.slug || gen !== S.gen || request !== trialChoiceRequest || $("trialSource").value !== sourceId) return;
  const select = $("trialFile"); select.replaceChildren();
  for (const file of response.files || []) trialOption(select, JSON.stringify(file.origin), `${file.name}${file.has_code ? "" : " · no code"}`, !file.has_code);
}

$("trialSource").onchange = () => {
  trialInvalidate(true);
  const request = ++trialChoiceRequest, slug = S.slug, gen = S.gen;
  loadTrialFiles(slug, gen, request).catch((error) => {
    if (slug === S.slug && gen === S.gen && request === trialChoiceRequest) {
      const operation = beginTrialOperation("Loading reference files", [], "Files loaded.");
      trialError(operation, error); finishTrialOperation(operation);
    }
  });
};
for (const id of ["trialFile", "trialTarget"]) $(id).addEventListener("change", () => trialInvalidate(true));
for (const id of ["trialName", "trialStart", "trialEnd", "trialMappings", "trialCode", "trialPrelude"]) {
  $(id).addEventListener("input", () => { trialInvalidate(false); updateTrialRunButton(); });
}
$("trialConsent").onchange = updateTrialRunButton;
$("trialShowSource").onclick = async () => {
  const slug = S.slug, gen = S.gen, revision = ++trialRevision, logOrigin = $("trialFile").value;
  let origin;
  try { origin = JSON.parse(logOrigin || "null"); }
  catch { const op = beginTrialOperation("Reading selected reference snapshot", [], "Reference text loaded."); trialError(op, new Error("The selected reference origin is invalid. Refresh the source list.")); finishTrialOperation(op); return; }
  if (!origin) return;
  const operation = beginTrialOperation("Reading selected reference snapshot", [$("trialShowSource")], "Reference text loaded.");
  try {
    const result = await api("/api/reference-trials/source", { method: "POST", body: { slug, origin } });
    if (!trialCurrent(slug, gen, revision) || logOrigin !== $("trialFile").value) return;
    const view = $("trialPreview"); view.replaceChildren();
    const provenance = document.createElement("p");
    provenance.textContent = `Reference: ${result.provenance?.source_name || "selected source"} · ${result.provenance?.path || `record ${result.provenance?.record_id || "?"}`} · lines ${result.start || result.provenance?.start || "?"}–${result.end_line || result.provenance?.end_line || "?"}`;
    view.append(provenance);
    const text = document.createElement("pre"); text.textContent = result.text; view.append(text);
  } catch (error) { if (slug === S.slug && gen === S.gen && revision === trialRevision) trialError(operation, error); }
  finally { finishTrialOperation(operation); }
};
$("trialPrepare").onclick = async () => {
  const slug = S.slug, gen = S.gen, revision = ++trialRevision;
  const sourceId = $("trialSource").value, file = $("trialFile").value, targetId = $("trialTarget").value;
  const name = $("trialName").value, start = $("trialStart").value, end = $("trialEnd").value;
  const mappingText = $("trialMappings").value, submittedSource = $("trialCode").value, prelude = $("trialPrelude").value;
  trialPlan = null; $("trialConsent").checked = false; updateTrialRunButton();
  let origin, mappings;
  try {
    origin = JSON.parse(file || "null");
    if (!origin || !sourceId) throw new Error("Choose an enabled reference source and a file or pseudocode record.");
    const selectedFile = $("trialFile").options.find((option) => option.value === file);
    if (!selectedFile || selectedFile.disabled) throw new Error("Choose a reference file or pseudocode record with code.");
    const selectedTarget = $("trialTarget").options.find((option) => option.value === targetId);
    if (!selectedTarget || selectedTarget.disabled) throw new Error("Choose an eligible target function.");
    mappings = mappingText.split(/\r?\n/).filter(Boolean).map((line) => {
      const at = line.indexOf("=");
      if (at < 1) throw new Error("Mappings must use old_identifier=new_identifier, one per line.");
      return { old: line.slice(0, at).trim(), new: line.slice(at + 1).trim() };
    });
  } catch (error) {
    const operation = beginTrialOperation("Preparing source-only preview", [], "Preview prepared.");
    trialError(operation, error); finishTrialOperation(operation); return;
  }
  const controls = [$("trialPrepare"), $("trialSource"), $("trialFile"), $("trialTarget"), $("trialName"), $("trialStart"), $("trialEnd"), $("trialMappings"), $("trialCode"), $("trialPrelude"), $("trialConsent")];
  const operation = beginTrialOperation("Preparing source-only preview", controls, "Preview prepared.");
  try {
    const body = { slug, target_id: Number(targetId), origin, reference_name: name, mappings, prelude };
    if (start) body.start = Number(start); if (end) body.end = Number(end);
    if (submittedSource) body.source_override = submittedSource;
    const preview = await api("/api/reference-trials/prepare", { method: "POST", body });
    if (!trialCurrent(slug, gen, revision) || sourceId !== $("trialSource").value || file !== $("trialFile").value || targetId !== $("trialTarget").value) return;
    trialPlan = preview;
    const view = $("trialPreview"); view.replaceChildren();
    const summary = document.createElement("p");
    summary.textContent = `Target: ${preview.target.name} · ${preview.target.unit || ""}; mode ${preview.context?.mode || "unknown"}; compiler ${preview.context?.compiler || "unknown"}; flags ${trialFlags(preview.context)}`;
    view.append(summary);
    const provenance = document.createElement("p");
    provenance.textContent = `Reference: ${preview.provenance?.source_name || "selected source"} · ${preview.provenance?.path || `record ${preview.provenance?.record_id || "?"}`} · lines ${preview.provenance?.start || "?"}–${preview.provenance?.end_line || "?"}; source hash ${preview.source_hash || "unavailable"}; prelude hash ${preview.prelude_hash || "unavailable"}`;
    view.append(provenance);
    const code = document.createElement("pre"); code.textContent = preview.source; view.append(code);
    for (const warning of preview.warnings || []) { const note = document.createElement("p"); note.textContent = warning; view.append(note); }
    $("trialCode").value = preview.source; $("trialPrelude").value = preview.prelude;
    // Preparation is not consent; the owner must affirm this exact fresh plan.
    $("trialConsent").checked = false; updateTrialRunButton();
    trialStatus(operation, preview.ready ? "Preview is ready. Review it and confirm before running." : "Preview is not ready. Resolve its warnings and prepare again.");
  } catch (error) { if (slug === S.slug && gen === S.gen && revision === trialRevision) trialError(operation, error); }
  finally { finishTrialOperation(operation); }
};
$("trialRun").onclick = async () => {
  const plan = trialPlan, slug = S.slug, gen = S.gen;
  if (!plan?.ready || !$("trialConsent").checked || trialRunActive) return;
  const submittedSource = $("trialCode").value, submittedPrelude = $("trialPrelude").value;
  const controls = [$("trialRun"), $("trialPrepare"), $("trialSource"), $("trialFile"), $("trialTarget"), $("trialName"), $("trialStart"), $("trialEnd"), $("trialMappings"), $("trialCode"), $("trialPrelude"), $("trialConsent"), $("trialShowSource")];
  const operation = beginTrialOperation("Running judged reference trial", controls, "Trial finished.", "run");
  trialRunActive = true;
  trialStatus(operation, "Once started, this judged trial cannot be cancelled by navigating away or closing this panel.");
  try {
    const result = await api("/api/reference-trials/run", { method: "POST", body: { slug, plan: plan.plan, source: submittedSource, prelude: submittedPrelude, accept_if_verified: true, allow_progress_copy: true } });
    if (slug !== S.slug || gen !== S.gen) return;
    if (result.matched === true) trialStatus(operation, "Verified exact match.");
    else if (result.outcome === "nonmatch") trialStatus(operation, `Not an exact match${result.percent == null ? "" : ` · ${result.percent}% similarity`}.`);
    else trialStatus(operation, `${result.outcome}: ${result.text || "Review the result and prepare again if needed."}`);
    if (result.warnings?.length) trialStatus(operation, `${operation.status.textContent} ${result.warnings.join(" · ")}`);
    trialPlan = null; $("trialConsent").checked = false;
    try { await reloadTrialHistory(slug, gen); }
    catch (error) { trialStatus(operation, `${operation.status.textContent} Trial history could not refresh: ${error.message}`); }
  } catch (error) {
    trialPlan = null; $("trialConsent").checked = false; updateTrialRunButton();
    if (slug === S.slug && gen === S.gen) trialError(operation, error);
  } finally {
    trialRunActive = false;
    finishTrialOperation(operation);
    updateTrialRunButton();
    if (slug !== S.slug || gen !== S.gen) loadReferenceTrials();
  }
};
async function reloadTrialHistory(slug = S.slug, gen = S.gen) {
  const history = await api(`/api/reference-trials?slug=${encodeURIComponent(slug)}&limit=${TRIAL_HISTORY_LIMIT}`);
  if (slug === S.slug && gen === S.gen) renderTrialHistory(history.trials || []);
}
$("trialSource").addEventListener("focus", () => {
  if (!$("trialSource").options.length) loadReferenceTrials();
});
