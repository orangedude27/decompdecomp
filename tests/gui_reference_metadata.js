// Metadata review UI against the production script: scoped responses, literal text, and explicit actions.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync("src/decompnet/app/static/js/references.js", "utf8");
const base = fs.readFileSync("src/decompnet/app/static/js/base.js", "utf8");
function element() {
  return { children: [], parent: null, disabled: false, checked: false, value: "", attrs: {}, dataset: {}, _text: "", tagName: "",
    append(...items) { for (const child of items) { child.remove(); child.parent = this; child._rootConnected = this.isConnected; this.children.push(child); } },
    replaceChildren(...items) { this.children.forEach((child) => { child.parent = null; child._rootConnected = false; }); this.children = []; this._text = ""; this.append(...items); },
    before(child) { if (!this.parent) return; const list = this.parent.children, index = list.indexOf(this); child.remove(); child.parent = this.parent; child._rootConnected = this.isConnected; list.splice(index, 0, child); },
    remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); this.parent = null; this._rootConnected = false; },
    setAttribute(key, value) { this.attrs[key] = value; },
    querySelectorAll(selector) { return this.children.flatMap((child) => [...((selector === "button" && child.tagName === "BUTTON") || (selector === "input" && child.tagName === "INPUT") || (selector === "select" && child.tagName === "SELECT") ? [child] : []), ...child.querySelectorAll(selector)]); },
    get isConnected() { return this.parent ? this.parent.isConnected : this._rootConnected !== false; },
    get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); },
    set textContent(value) { this.replaceChildren(); this._text = String(value); } };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function setup(kind, implement, confirm = () => true) {
  const nodes = new Map(), get = (id) => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
  const pane = get("referencesPane");
  ["referenceList", "referenceResults", "referenceLog", "referenceAddFile", "referenceAddFolder", "referenceSearch", "referenceSearchButton", "referenceQuery", "referenceMetadataChoose", "referenceMetadataLog", "referenceMetadataPreview", "referenceMetadataImports", "referenceMetadataRecords"].forEach((id) => pane.append(get(id)));
  ["referenceAddFile", "referenceAddFolder", "referenceSearchButton", "referenceMetadataChoose"].forEach((id) => { get(id).tagName = "BUTTON"; });
  const calls = [];
  const ctx = { $, window: {}, document: { createElement(tag) { const e = element(); e.tagName = tag.toUpperCase(); return e; } }, S: { slug: "demo", gen: 1, ov: { kind } }, bytes: String,
    confirm, Date, URLSearchParams, encodeURIComponent, Promise, setTimeout, api: (url, options) => { calls.push([url, options]); return implement(url, options); }, sleep: async () => {} };
  function $(id) { return get(id); }
  vm.createContext(ctx); vm.runInContext(base.slice(base.indexOf("const JOB_POLL_MS"), base.indexOf("/* The map's still")), ctx); vm.runInContext(source, ctx);
  return { ctx, get, calls };
}
const sourceRow = { id: 9, name: "metadata", kind: "metadata", enabled: true, agent_access: false, status: "ready", file_count: 1, byte_count: 10, warnings: [] };
const imported = { id: 3, name: "symbols.json", kind: "symbols", build: null, identity_status: "mismatch", record_count: 1, content_hash: "abc" };
const record = (status = "unbound") => ({ record_id: 55, id: "e", kind: "function", name: "<script>bad()</script>", address: "0x8000", unit: "unit.c", signature: "void <x>()", comment: "<img>", pseudocode: "alert(1)", status, target: status === "pending" ? { name: "oldName" } : null, proposed_name: status === "pending" ? "newName" : "" });
async function main() {
  for (const kind of ["rom", "fork"]) {
    let status = "unbound", importedNow = false; const calls = [];
    const h = setup(kind, async (url, options) => {
      calls.push([url, options]);
      if (url.startsWith("/api/references?")) return { sources: [sourceRow] };
      if (url.startsWith("/api/reference-metadata?")) return { builds: [], imports: importedNow ? [imported] : [] };
      if (url === "/api/pick") return { path: "/tmp/private.json" };
      if (url.endsWith("/preview")) return { content_hash: "hash1", kind: "symbols", build: null, identity_status: "mismatch", record_count: 1, records: [record()], warnings: ["<b>warning</b>"], truncated: false };
      if (url.endsWith("/import")) { importedNow = true; return { source: sourceRow, import: imported }; }
      if (url.includes("/records?")) return { records: [record(status)], offset: 0, total: 1, truncated: false };
      if (url.includes("/targets?")) return { targets: [{ target: { kind: "function", id: 12 }, name: "oldName", unit: "unit.c", address: "0x8000" }], truncated: false };
      if (url.endsWith("/map")) { status = "pending"; return { record: record(status) }; }
      if (url.endsWith("/apply")) { status = "applied"; return { record: record(status), result: "renamed" }; }
      if (url.endsWith("/reject")) { status = "rejected"; return { record: record(status) }; }
      return { source: { ...sourceRow, agent_access: options.body.agent_access } };
    });
    await h.ctx.loadReferences();
    const row = h.get("referenceList").children[0], access = row.children.find((node) => node.tagName === "LABEL").children[0];
    assert.match(row.textContent, /model you selected for agents/);
    assert.equal(access.checked, false, "agent permission defaults denied"); access.checked = true; await access.onchange();
    assert.ok(calls.some(([url, options]) => url.endsWith("/agent-access") && options.body.agent_access === true));
    access.checked = false; await access.onchange();
    assert.ok(calls.some(([url, options]) => url.endsWith("/agent-access") && options.body.agent_access === false), "permission can be revoked");
    const buttons = row.querySelectorAll("button"); assert.equal(buttons.some((button) => button.textContent === "Refresh"), false, "metadata has no ordinary refresh");
    await h.get("referenceMetadataChoose").onclick();
    assert.match(h.get("referenceMetadataPreview").textContent, /mismatch build/);
    assert.match(h.get("referenceMetadataPreview").textContent, /<script>bad/);
    assert.match(h.get("referenceMetadataPreview").textContent, /<b>warning/);
    assert.equal(calls.some(([url]) => url.endsWith("/import")), false, "chooser and preview alone never import");
    const importButton = h.get("referenceMetadataPreview").children.at(-1); await importButton.onclick();
    assert.ok(calls.some(([url, options]) => url.endsWith("/import") && options.body.content_hash === "hash1"));
    const article = h.get("referenceMetadataRecords").children[1];
    assert.match(article.textContent, /<script>bad/); assert.match(article.textContent, /<img>/, "untrusted comments remain literal text");
    const search = article.children.find((node) => node.textContent === "Find targets"); article.children.find((node) => node.tagName === "INPUT").value = "oldName"; await search.onclick();
    const proposed = article.children.filter((node) => node.tagName === "INPUT").at(-1); proposed.value = "newName";
    await article.children.find((node) => node.textContent === "Map / Prepare").onclick();
    assert.equal(calls.some(([url]) => url.endsWith("/map")), true); assert.equal(calls.some(([url]) => url.endsWith("/apply")), false, "mapping never applies");
    status = "pending"; await h.ctx.showMetadataRecords(imported, 0, "demo", 1);
    const pendingArticle = h.get("referenceMetadataRecords").children[1];
    await pendingArticle.children.find((node) => node.textContent === "Apply reviewed rename…").onclick();
    assert.ok(calls.some(([url]) => url.endsWith("/apply")));
    assert.ok(h.ctx.S.ov.kind === kind);
  }
  const reject = setup("fork", async (url) => url.includes("/records?") ? { records: [record("pending")], offset: 0, total: 1 } : {});
  await reject.ctx.showMetadataRecords(imported, 0, "demo", 1);
  await reject.get("referenceMetadataRecords").children[1].children.find((node) => node.textContent === "Reject").onclick();
  assert.ok(reject.calls.some(([url]) => url.endsWith("/reject")));
  const pending = deferred(); const stale = setup("rom", (url) => url.endsWith("/preview") ? pending.promise : Promise.resolve({}));
  const run = stale.ctx.previewReferenceMetadata("/tmp/private.json"); stale.ctx.S.slug = "other"; stale.ctx.S.gen++; stale.ctx.window.resetReferences();
  pending.resolve({ kind: "ghidra", record_count: 1, content_hash: "private", records: [{ name: "stale" }], warnings: [] }); await run;
  assert.equal(stale.get("referenceMetadataPreview").children.length, 0, "old-project preview response cannot render after reset");
  const staleImport = setup("rom", async (url) => url.endsWith("/preview") ? { kind: "symbols", content_hash: "ok", record_count: 0, records: [], warnings: [] } : {});
  await staleImport.ctx.previewReferenceMetadata("/tmp/old.json");
  const staleImportButton = staleImport.get("referenceMetadataPreview").children.at(-1);
  staleImport.ctx.S.slug = "new"; staleImport.ctx.S.gen++; staleImport.ctx.window.resetReferences(); await staleImportButton.onclick();
  assert.equal(staleImport.calls.some(([url]) => url.endsWith("/import")), false, "stale preview confirmation is blocked before import POST");
  const canceled = setup("rom", async (url) => url === "/api/pick" ? { path: "" } : {});
  await canceled.get("referenceMetadataChoose").onclick();
  assert.equal(canceled.calls.some(([url]) => url.endsWith("/preview")), false, "cancelling picker does not preview/import");
  const changedHash = setup("fork", async (url) => {
    if (url === "/api/pick") return { path: "/tmp/changed.json" };
    if (url.endsWith("/preview")) return { kind: "ghidra", content_hash: "before", record_count: 0, records: [], warnings: [] };
    if (url.endsWith("/import")) throw new Error("file changed since preview");
    return {};
  });
  await changedHash.get("referenceMetadataChoose").onclick();
  await changedHash.get("referenceMetadataPreview").children.at(-1).onclick();
  assert.match(changedHash.get("referenceMetadataLog").textContent, /file changed since preview/);
  assert.equal(changedHash.calls.some(([url]) => url.endsWith("/apply")), false);
  const paged = setup("rom", async (url) => url.includes("/records?") ? { records: [record()], offset: new URLSearchParams(url.split("?")[1]).get("offset") === "50" ? 50 : 0, total: 51 } : {});
  await paged.ctx.showMetadataRecords(imported, 0, "demo", 1);
  await paged.get("referenceMetadataRecords").children.at(-1).children.find((node) => node.textContent === "Next page").onclick();
  assert.ok(paged.calls.some(([url]) => url.includes("offset=50")), "records request is paged in bounded chunks");
  const firstPreview = deferred(); let previews = 0;
  const overlap = setup("fork", (url) => url.endsWith("/preview") ? (++previews === 1 ? firstPreview.promise : Promise.resolve({ kind: "symbols", record_count: 1, content_hash: "new", records: [{ name: "new" }], warnings: [] })) : Promise.resolve({}));
  const earlier = overlap.ctx.previewReferenceMetadata("/tmp/first.json");
  await overlap.ctx.previewReferenceMetadata("/tmp/second.json");
  firstPreview.resolve({ kind: "symbols", record_count: 1, content_hash: "old", records: [{ name: "old" }], warnings: [] }); await earlier;
  assert.match(overlap.get("referenceMetadataPreview").textContent, /new/); assert.doesNotMatch(overlap.get("referenceMetadataPreview").textContent, /old/);
  const revisitReply = deferred(); let metadataGets = 0;
  const revisit = setup("rom", (url) => url.endsWith("/preview") ? revisitReply.promise : url.startsWith("/api/references?") ? Promise.resolve({ sources: [] }) : url.startsWith("/api/reference-metadata?") ? (++metadataGets === 1 ? Promise.resolve({ imports: [], builds: [] }) : Promise.resolve({ imports: [], builds: [] })) : Promise.resolve({}));
  const previewOnTab = revisit.ctx.previewReferenceMetadata("/tmp/tab.json"); await revisit.ctx.loadReferences();
  revisitReply.resolve({ kind: "ghidra", record_count: 1, content_hash: "late", records: [{ name: "late" }], warnings: [] }); await previewOnTab;
  assert.match(revisit.get("referenceMetadataPreview").textContent, /late/, "tab revisit refreshes imports without invalidating the independent preview request");
  const applying = deferred(), applyingNew = deferred(); let newApplied = false;
  const switchApply = setup("fork", (url, options) => {
    if (url.includes("/records?")) return Promise.resolve({ records: [record(url.includes("slug=other") && newApplied ? "applied" : "pending")], offset: 0, total: 1 });
    if (url.endsWith("/apply")) { if (options.body.slug === "demo") return applying.promise; newApplied = true; return applyingNew.promise; }
    return Promise.resolve({});
  });
  await switchApply.ctx.showMetadataRecords(imported, 0, "demo", 1);
  const applyRun = switchApply.get("referenceMetadataRecords").children[1].children.find((node) => node.textContent === "Apply reviewed rename…").onclick();
  switchApply.ctx.S.slug = "other"; switchApply.ctx.S.gen++; switchApply.ctx.window.resetReferences();
  assert.equal(switchApply.get("referenceMetadataRecords").children.length, 0, "reset detaches the old apply view");
  await switchApply.ctx.showMetadataRecords(imported, 0, "other", 2);
  const newApplyButton = switchApply.get("referenceMetadataRecords").children[1].children.find((node) => node.textContent === "Apply reviewed rename…");
  const newApplyRun = newApplyButton.onclick();
  applying.resolve({ record: record("applied"), result: "old result" }); await applyRun;
  assert.ok(switchApply.calls.some(([url, options]) => url.endsWith("/apply") && options.body.slug === "other"), "new-project apply remains in flight while the old response settles");
  assert.equal(newApplyButton.disabled, true, "new apply controls remain owned during the new apply");
  applyingNew.resolve({ record: record("applied"), result: "new result" }); await newApplyRun;
  assert.doesNotMatch(switchApply.get("referenceMetadataRecords").textContent, /old result/, "late apply response cannot render into the switched project");
  assert.equal(switchApply.get("referenceMetadataRecords").children[1].querySelectorAll("button").some((node) => node.textContent === "Apply reviewed rename…"), false, "new project shows its refreshed applied status");
  const staleReject = setup("rom", async (url) => url.includes("/records?") ? { records: [record("pending")], offset: 0, total: 1 } : {});
  await staleReject.ctx.showMetadataRecords(imported, 0, "demo", 1);
  const staleRejectButton = staleReject.get("referenceMetadataRecords").children[1].children.find((node) => node.textContent === "Reject");
  staleReject.ctx.S.slug = "other"; staleReject.ctx.S.gen++; staleReject.ctx.window.resetReferences(); await staleRejectButton.onclick();
  assert.equal(staleReject.calls.some(([url]) => url.endsWith("/reject")), false, "stale Reject is blocked before POST");
  const lateTarget = deferred();
  const targetError = setup("fork", (url) => url.includes("/records?") ? Promise.resolve({ records: [record()], offset: 0, total: 1 }) : url.includes("/targets?") ? lateTarget.promise : Promise.resolve({}));
  await targetError.ctx.showMetadataRecords(imported, 0, "demo", 1);
  const oldArticle = targetError.get("referenceMetadataRecords").children[1];
  const targetSearch = oldArticle.children.find((node) => node.textContent === "Find targets"), targetRun = targetSearch.onclick();
  targetError.ctx.S.slug = "new-project"; targetError.ctx.S.gen++; targetError.ctx.window.resetReferences();
  lateTarget.reject(new Error("old project target failure")); await targetRun;
  assert.doesNotMatch(targetError.get("referenceMetadataLog").textContent, /old project target failure/, "late target-search error stays out of new project's UI");
  const requestViews = deferred();
  const independentViews = setup("rom", (url) => url.includes("/records?") ? requestViews.promise : url.endsWith("/preview") ? Promise.resolve({ kind: "symbols", record_count: 0, content_hash: "p", records: [], warnings: [] }) : Promise.resolve({ imports: [], builds: [] }));
  const recordLoad = independentViews.ctx.showMetadataRecords(imported, 0, "demo", 1);
  await independentViews.ctx.previewReferenceMetadata("/tmp/independent.json");
  await independentViews.ctx.loadReferenceMetadata("demo", 1);
  requestViews.resolve({ records: [record()], offset: 0, total: 1 }); await recordLoad;
  assert.match(independentViews.get("referenceMetadataRecords").textContent, /Reference record 55/, "preview completion does not invalidate the independent records view");
  const madeSource = { ...sourceRow, id: 21, name: "Imported metadata source", kind: "metadata" }; let hasSource = false;
  const sourceAfterImport = setup("fork", async (url) => {
    if (url.startsWith("/api/references?")) return { sources: hasSource ? [madeSource] : [] };
    if (url.startsWith("/api/reference-metadata?")) return { builds: [], imports: hasSource ? [imported] : [] };
    if (url === "/api/pick") return { path: "/tmp/new-source.json" };
    if (url.endsWith("/preview")) return { kind: "symbols", content_hash: "newhash", record_count: 0, records: [], warnings: [] };
    if (url.endsWith("/import")) { hasSource = true; return { source: madeSource, import: imported }; }
    if (url.includes("/records?")) return { records: [], offset: 0, total: 0 };
    return {};
  });
  await sourceAfterImport.get("referenceMetadataChoose").onclick(); await sourceAfterImport.get("referenceMetadataPreview").children.at(-1).onclick();
  assert.equal(sourceAfterImport.get("referenceList").children[0].children.some((node) => node.tagName === "LABEL"), true, "new import source and its consent toggle appear immediately");
  const activeReplies = Array.from({ length: 4 }, () => deferred()); let previewIndex = 0;
  const manyOperations = setup("fork", (url) => url.endsWith("/preview") ? activeReplies[previewIndex++].promise : Promise.resolve({}));
  const concurrent = activeReplies.map((_, index) => manyOperations.ctx.previewReferenceMetadata(`/tmp/${index}.json`));
  activeReplies.slice(0, 3).forEach((reply, index) => reply.resolve({ kind: "symbols", content_hash: String(index), record_count: 0, records: [], warnings: [] }));
  await Promise.all(concurrent.slice(0, 3));
  const metadataLogs = () => manyOperations.get("referenceMetadataLog").children.filter((root) => root.className === "reference-metadata-operation");
  const completedLogs = () => metadataLogs().filter((root) => !root.children.some((node) => node.className === "workbar"));
  assert.ok(completedLogs().length <= 3, "completed logs stay bounded while work overlaps");
  assert.ok(metadataLogs().some((root) => root.children.some((node) => node.className === "workbar")), "active progress survives other operations finishing");
  activeReplies[3].resolve({ kind: "symbols", content_hash: "last", record_count: 0, records: [], warnings: [] }); await concurrent[3];
  assert.ok(completedLogs().length <= 3);
  const indexedStart = deferred(), indexedRecords = deferred(); let referenceLoads = 0;
  const indexing = setup("rom", (url) => {
    if (url.startsWith("/api/references?")) { referenceLoads++; return Promise.resolve({ sources: [sourceRow, { ...sourceRow, id: 10, kind: "file", name: "text" }] }); }
    if (url.startsWith("/api/reference-metadata?")) return Promise.resolve({ builds: [], imports: [imported] });
    if (url.includes("/records?")) return indexedRecords.promise;
    if (url.endsWith("/refresh")) return indexedStart.promise;
    return Promise.resolve({});
  });
  await indexing.ctx.loadReferences();
  const pendingRecords = indexing.ctx.showMetadataRecords(imported, 0, "demo", 1);
  const indexingRun = indexing.ctx.changeReference("/api/references/refresh", { slug: "demo", id: 10 }, "Index source");
  await indexing.ctx.loadReferences();
  indexedRecords.resolve({ records: [record("pending")], offset: 0, total: 1 }); await pendingRecords;
  const indexRow = indexing.get("referenceList").children[0], indexAccess = indexRow.children.find((node) => node.tagName === "LABEL").children[0];
  const indexChooser = indexing.get("referenceMetadataChoose");
  const indexRecordButton = indexing.get("referenceMetadataRecords").children[1].children.find((node) => node.textContent === "Reject");
  assert.equal(indexChooser.disabled, true); assert.equal(indexAccess.disabled, true); assert.equal(indexRecordButton.disabled, true, "controls rendered while indexing inherit active ownership");
  await indexRecordButton.onclick(); assert.equal(indexing.calls.some(([url]) => url.endsWith("/reject")), false, "disabled stale callback cannot post during indexing");
  indexedStart.resolve({}); await indexingRun;
  assert.equal(referenceLoads >= 3, true); assert.equal(indexChooser.disabled, false); assert.equal(indexRecordButton.disabled, false, "new controls release with their owning index operation");
  // A permission request can overlap a guarded rename's exclusive controls without losing disabled ownership.
  const permissionReply = deferred();
  const permissions = setup("rom", (url) => url.endsWith("/agent-access") ? permissionReply.promise : Promise.resolve({}));
  const permissionControl = element(); permissionControl.tagName = "INPUT"; permissionControl.checked = true;
  permissions.get("referenceList").append(permissionControl);
  const permissionRun = permissions.ctx.updateReferenceAgentAccess(sourceRow, permissionControl, { slug: "demo", gen: 1 });
  const releaseExclusive = permissions.ctx.beginMetadataExclusive();
  permissionReply.resolve({ source: { ...sourceRow, agent_access: true } }); await permissionRun;
  assert.equal(permissionControl.disabled, true, "finishing consent cannot enable a control owned by an active rename");
  releaseExclusive();
  assert.equal(permissionControl.disabled, false, "rename completion restores the original enabled state");
  const denied = setup("fork", async () => ({}), () => false);
  await denied.ctx.showMetadataRecords(imported, 0, "demo", 1);
  // A failed confirmation must not dispatch apply.
  const pendingRecord = { ...record("pending") };
  denied.ctx.renderMetadataRecord(denied.get("referenceMetadataRecords"), pendingRecord, "demo", 1, denied.ctx.metadataView);
  await denied.get("referenceMetadataRecords").children.at(-1).children.find((node) => node.textContent === "Apply reviewed rename…").onclick();
  assert.equal(denied.calls.some(([url]) => url.endsWith("/apply")), false);
  console.log("reference metadata UI scenarios passed");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
