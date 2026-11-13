"use strict";
let referenceGeneration = 0;
let referenceSearchGeneration = 0;
let referencePending = null;
const referenceControlOwners = new Map();
const referenceOperations = new Set();
const referenceSearches = new Set();
const REFERENCE_QUERY_LIMIT = 1000;
function referenceOperationLog() {
  const root = document.createElement("div"); root.className = "reference-operation";
  const log = document.createElement("div"); log.className = "reference-operation-log";
  root.append(log);
  $("referenceLog").replaceChildren(root);  // Keep only the latest visible operation; active callers retain their detached handles.
  return { root, log };
}
function referenceOwns(slug, gen, pane) { return slug === S.slug && gen === S.gen && pane.isConnected; }
function activeReferenceOperation(slug, gen) {
  return referencePending && referencePending.slug === slug && referencePending.gen === gen ? referencePending : null;
}
function registerReferenceControls(operation, controls) {
  const fresh = controls.filter((control) => !operation.controls.includes(control));
  operation.controls.push(...fresh); claimReferenceControls(fresh);
}
function claimReferenceControls(controls) {
  controls.forEach((control) => {
    if (!referenceControlOwners.has(control)) referenceControlOwners.set(control, { disabled: control.disabled, owners: 0 });
    referenceControlOwners.get(control).owners++; control.disabled = true;
  });
}
function releaseReferenceControls(controls, operation) {
  if (operation && operation.controlsReleased) return;
  if (operation) operation.controlsReleased = true;
  controls.forEach((control) => {
    const state = referenceControlOwners.get(control);
    if (state && --state.owners === 0) { control.disabled = state.disabled; referenceControlOwners.delete(control); }
  });
}
function resetReferences() {
  referenceGeneration++; referenceSearchGeneration++;
  $("referenceList").replaceChildren(); $("referenceResults").replaceChildren(); $("referenceLog").replaceChildren();
  $("referenceQuery").value = "";
  for (const operation of referenceOperations) {
    operation.root.remove();
    releaseReferenceControls(operation.controls, operation);
  }
  referenceOperations.clear();
  for (const search of referenceSearches) releaseReferenceControls(search.controls, search);
  referenceSearches.clear(); referencePending = null;
}
window.resetReferences = resetReferences;
async function loadReferences(existingLog = null) {
  const slug = S.slug, gen = S.gen, pane = $("referencesPane"), list = $("referenceList"), active = activeReferenceOperation(slug, gen),
    { log } = existingLog ? { log: existingLog } : active ? { log: active.log } : referenceOperationLog(), request = ++referenceGeneration;
  const finish = active ? null : beginWork(log, "Loading reference sources", [], "Reference sources loaded.");
  try {
    const data = await api(`/api/references?slug=${encodeURIComponent(slug)}`);
    if (!referenceOwns(slug, gen, pane) || request !== referenceGeneration) return;
    list.replaceChildren();
    data.sources.forEach((source) => {
      const row = document.createElement("div"); row.className = "reference-row";
      const title = document.createElement("strong"); title.textContent = source.name;
      const details = document.createElement("p");
      details.textContent = `${source.kind} · ${source.status} · ${source.enabled ? "enabled" : "disabled"} · ${source.file_count} files · ${bytes(source.byte_count)} · indexed ${source.indexed_at ? new Date(source.indexed_at * 1000).toLocaleString() : "never"}${source.stale ? " · stale snapshot" : ""}`;
      row.append(title, details);
      if (source.error) { const error = document.createElement("p"); error.className = "err-msg"; error.textContent = source.error; row.append(error); }
      (source.warnings || []).forEach((warning) => { const note = document.createElement("p"); note.className = "muted small"; note.textContent = warning; row.append(note); });
      const action = (label, callback) => { const button = document.createElement("button"); button.textContent = label; button.onclick = callback; row.append(button); };
      const owner = { slug, gen };
      action("Refresh", () => changeReference("/api/references/refresh", { slug, id: source.id }, "Refresh reference source", owner));
      action(source.enabled ? "Disable" : "Enable", () => changeReference("/api/references/enabled", { slug, id: source.id, enabled: !source.enabled }, "Update reference source", owner));
      action("Remove…", async () => { if (!activeReferenceOperation(slug, gen) && referenceOwns(slug, gen, pane) && confirm("Remove this source from the app? Its original files will remain untouched.")) await changeReference("/api/references/remove", { slug, id: source.id }, "Remove reference source", owner); });
      if (active) registerReferenceControls(active, [...row.querySelectorAll("button")]);
      list.append(row);
    });
  } catch (error) { if (referenceOwns(slug, gen, pane) && request === referenceGeneration) showJobError(log, error.message); }
  finally { if (finish) finish(); }
}
async function changeReference(route, body, label, owner = { slug: S.slug, gen: S.gen }) {
  const { slug, gen } = owner, pane = $("referencesPane");
  if (slug !== S.slug || gen !== S.gen || body.slug !== slug || !referenceOwns(slug, gen, pane) || activeReferenceOperation(slug, gen)) return;
  const { root, log } = referenceOperationLog(), controls = [...pane.querySelectorAll("button")];
  const operation = { slug, gen, pane, root, log, job: null, cancelRequested: false, controls, controlsReleased: false };
  referenceOperations.add(operation); referencePending = operation;
  claimReferenceControls(controls);
  const cancelArea = document.createElement("div"); cancelArea.className = "reference-cancel"; root.append(cancelArea);
  const cancel = document.createElement("button"); cancel.textContent = "Cancel"; cancelArea.append(cancel);
  const cancelJob = async () => {
    if (!referenceOwns(slug, gen, pane)) return;
    operation.cancelRequested = true;
    if (operation.job) await api("/api/job/cancel", { method: "POST", body: { id: operation.job } });
  };
  cancel.onclick = () => cancelJob().catch((error) => { if (referenceOwns(slug, gen, pane)) showJobError(log, error.message); });
  const finish = beginWork(log, label, [], "Finished."); showJobError(log, "");
  let failure = null;
  try {
    const data = await api(route, { method: "POST", body });
    if (data.job) { operation.job = data.job; if (operation.cancelRequested) await cancelJob(); await followJob(data.job, log); }
  } catch (error) { failure = error; }
  finally {
    if (referenceOwns(slug, gen, pane)) {
      await loadReferences(log);
      if (failure) showJobError(log, failure.message);
    }
    finish(); cancel.remove();
    releaseReferenceControls(controls, operation);
    referenceOperations.delete(operation);
    if (referencePending === operation) referencePending = null;
  }
}
async function chooseReference(kind) {
  const slug = S.slug, gen = S.gen, pane = $("referencesPane");
  try {
    const picked = await api("/api/pick", { method: "POST", body: { kind, title: `Choose a reference ${kind}` } });
    if (!picked.path || !referenceOwns(slug, gen, pane)) return;
    await changeReference("/api/references/add", { slug, path: picked.path }, "Add and index reference source", { slug, gen });
  } catch (error) { if (referenceOwns(slug, gen, pane)) showJobError(referenceOperationLog().log, error.message); }
}
$("referenceAddFile").onclick = () => chooseReference("file");
$("referenceAddFolder").onclick = () => chooseReference("folder");
$("referenceSearch").onsubmit = async (event) => {
  event.preventDefault(); const slug = S.slug, gen = S.gen, pane = $("referencesPane");
  if (activeReferenceOperation(slug, gen)) return;
  const request = ++referenceSearchGeneration;
  const query = $("referenceQuery").value.slice(0, REFERENCE_QUERY_LIMIT), output = $("referenceResults"),
    { log } = referenceOperationLog(), submit = $("referenceSearchButton");
  const search = { controls: [submit], controlsReleased: false }; referenceSearches.add(search);
  claimReferenceControls(search.controls);
  const finish = beginWork(log, "Search reference sources", [], "Search finished."); showJobError(log, "");
  try {
    const data = await api(`/api/references/search?slug=${encodeURIComponent(slug)}&q=${encodeURIComponent(query)}`);
    if (!referenceOwns(slug, gen, pane) || request !== referenceSearchGeneration) return;
    output.replaceChildren();
    if (!data.results.length) { const empty = document.createElement("p"); empty.textContent = query ? "No matching text." : "Enter text to search."; output.append(empty); }
    data.results.forEach((hit) => { const article = document.createElement("article"); const title = document.createElement("strong"); title.textContent = `${hit.source_name} · ${hit.path}:${hit.line}${hit.end_line !== hit.line ? `–${hit.end_line}` : ""}${hit.stale ? " · stale" : ""}`; const excerpt = document.createElement("pre"); excerpt.textContent = hit.excerpt; article.append(title, excerpt); output.append(article); });
    if (data.truncated) { const note = document.createElement("p"); note.textContent = "More matches were found; narrow your search to see them."; output.append(note); }
  } catch (error) { if (referenceOwns(slug, gen, pane) && request === referenceSearchGeneration) showJobError(log, error.message); }
  finally { finish(); releaseReferenceControls(search.controls, search); referenceSearches.delete(search); }
};
