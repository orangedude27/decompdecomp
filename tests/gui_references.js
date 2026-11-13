// Reference-source UI behavior against the production script and shared job helpers.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync("src/decompnet/app/static/js/references.js", "utf8");
const base = fs.readFileSync("src/decompnet/app/static/js/base.js", "utf8");
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function el() {
  const node = { children: [], parent: null, disabled: false, value: "", dataset: {}, attrs: {}, className: "", _text: "",
    append(...nodes) { for (const child of nodes) { child.remove(); child.parent = this; child._rootConnected = this.isConnected; this.children.push(child); } },
    replaceChildren(...nodes) { for (const child of this.children) { child.parent = null; child._rootConnected = false; } this.children = []; this.append(...nodes); },
    before(child) { if (!this.parent) return; const siblings = this.parent.children, index = siblings.indexOf(this); child.remove(); child.parent = this.parent; siblings.splice(index < 0 ? 0 : index, 0, child); },
    remove() { if (this.parent) { const siblings = this.parent.children, index = siblings.indexOf(this); if (index >= 0) siblings.splice(index, 1); this.parent = null; } this._rootConnected = false; this.removed = true; },
    setAttribute(k, v) { this.attrs[k] = v; }, querySelectorAll(selector) {
      const found = [];
      for (const child of this.children) {
        if (selector === "button" && child.tagName === "BUTTON") found.push(child);
        found.push(...child.querySelectorAll(selector));
      }
      return found;
    }, scrollTop: 0, scrollHeight: 0,
    get isConnected() { return this.parent ? this.parent.isConnected : this._rootConnected !== false; },
    get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); },
    set textContent(value) { this.replaceChildren(); this._text = String(value); } };
  return node;
}
function harness(kind = "rom", apiImpl = () => Promise.resolve({ sources: [] }), confirmImpl = () => true) {
  const nodes = new Map(), get = (id) => {
    if (!nodes.has(id)) { const node = el(); if (id.startsWith("referenceAdd") || id === "referenceSearchButton") node.tagName = "BUTTON"; nodes.set(id, node); }
    return nodes.get(id);
  };
  const pane = get("referencesPane");
  for (const id of ["referenceList", "referenceResults", "referenceLog", "referenceAddFile", "referenceAddFolder", "referenceSearchButton"]) pane.append(get(id));
  const calls = [], ctx = { $, window: {}, document: { createElement(tag) { const node = el(); node.tagName = tag.toUpperCase(); return node; } }, S: { slug: "one", gen: 1, ov: { kind } }, bytes: String,
    confirm: confirmImpl, Date, URLSearchParams, encodeURIComponent, Promise, setTimeout,
    api: (url, options) => { calls.push([url, options]); return apiImpl(url, options); }, sleep: async () => {} };
  function $(id) { return get(id); }
  vm.createContext(ctx);
  vm.runInContext(base.slice(base.indexOf("const JOB_POLL_MS"), base.indexOf("/* The map's still")), ctx);
  vm.runInContext(source, ctx);
  return { ctx, get, calls };
}
const sourceRow = (extra = {}) => ({ id: 4, name: "<img onerror=x>", kind: "file", enabled: true, status: "partial", file_count: 2, byte_count: 9, indexed_at: 100, warnings: ["<script>warning</script>"], error: "<b>error</b>", stale: true, ...extra });
async function main() {
  for (const kind of ["rom", "fork"]) {
    const h = harness(kind, async (url) => url.startsWith("/api/references?") ? { sources: [sourceRow()] } : { results: [], truncated: false });
    await h.ctx.loadReferences();
    const list = h.get("referenceList");
    assert.equal(list.children[0].children[0].textContent, "<img onerror=x>");
    assert.match(list.children[0].children.map((n) => n.textContent).join(" "), /warning/);
    assert.match(list.children[0].children.map((n) => n.textContent).join(" "), /error/);
    assert.match(list.children[0].children.map((n) => n.textContent).join(" "), /stale snapshot/);
    assert.equal(h.ctx.S.ov.kind, kind);
  }
  // All listed actions call their documented endpoint; removal is confirmed and originals are not deleted.
  const actionCalls = [];
  const actions = harness("fork", async (url, opts) => {
    actionCalls.push([url, opts]);
    if (url.startsWith("/api/references?")) return { sources: [sourceRow()] };
    if (url === "/api/references/refresh" || url === "/api/references/add") return { job: "action-job" };
    if (url.startsWith("/api/job?")) return { state: "done", log: ["Indexed"], result: {} };
    return { source: sourceRow(), removed: true };
  });
  await actions.ctx.loadReferences();
  let buttons = actions.get("referenceList").children[0].children.filter((item) => typeof item.onclick === "function");
  await buttons.find((item) => item.textContent === "Refresh").onclick();
  await buttons.find((item) => item.textContent === "Disable").onclick();
  buttons = actions.get("referenceList").children[0].children.filter((item) => typeof item.onclick === "function");
  await buttons.find((item) => item.textContent === "Remove…").onclick();
  assert.ok(actionCalls.some(([url, opts]) => url === "/api/references/refresh" && opts.body.id === 4));
  assert.ok(actionCalls.some(([url, opts]) => url === "/api/references/enabled" && opts.body.enabled === false));
  assert.ok(actionCalls.some(([url, opts]) => url === "/api/references/remove" && opts.body.id === 4));
  const disabled = harness("rom", async (url) => url.startsWith("/api/references?") ? { sources: [sourceRow({ enabled: false })] } : { source: sourceRow({ enabled: true }) });
  await disabled.ctx.loadReferences();
  await disabled.get("referenceList").children[0].children.find((item) => item.textContent === "Enable").onclick();
  assert.ok(disabled.calls.some(([url, opts]) => url === "/api/references/enabled" && opts.body.enabled === true));
  const noRemove = harness("rom", async (url) => url.startsWith("/api/references?") ? { sources: [sourceRow()] } : { removed: true }, () => false);
  await noRemove.ctx.loadReferences();
  const removeButton = noRemove.get("referenceList").children[0].children.find((item) => item.textContent === "Remove…");
  await removeButton.onclick(); assert.equal(noRemove.calls.some(([url]) => url === "/api/references/remove"), false);

  for (const [id, kind] of [["referenceAddFile", "file"], ["referenceAddFolder", "folder"]]) {
    const h = harness("rom", async (url, opts) => url === "/api/pick" ? { path: "/tmp/source" } : opts?.method === "POST" ? { source: sourceRow(), job: "j" } : url.startsWith("/api/job?") ? { state: "done", log: [], result: {} } : { sources: [] });
    await h.get(id).onclick();
    assert.ok(h.calls.some(([url, opts]) => url === "/api/pick" && opts.body.kind === kind));
  }
  const canceledChooser = harness("rom", async (url) => url === "/api/pick" ? { path: "" } : { sources: [] });
  await canceledChooser.ctx.chooseReference("file");
  assert.equal(canceledChooser.calls.filter(([url]) => url.startsWith("/api/references/")).length, 0);

  // Cancellation requested while the POST is delayed is sent as soon as its job ID arrives.
  const start = deferred(), cancelHarness = harness("fork", (url) => url === "/api/references/refresh" ? start.promise : url === "/api/job/cancel" ? Promise.resolve({}) : url.startsWith("/api/job?") ? Promise.resolve({ state: "cancelled", error: "Operation was cancelled.", log: ["kept log"] }) : Promise.resolve({ sources: [] }));
  const pending = cancelHarness.ctx.changeReference("/api/references/refresh", { slug: "one", id: 4 }, "Refresh");
  await Promise.resolve();
  // Invoke cancel before the delayed start response has supplied the job ID.
  const root = cancelHarness.get("referenceLog").children.at(-1); await root.children.find((n) => n.className === "reference-cancel").children[0].onclick();
  start.resolve({ job: "job-1" }); await pending;
  assert.ok(cancelHarness.calls.some(([url, opts]) => url === "/api/job/cancel" && opts.body.id === "job-1"));

  const pendingPoll = deferred(); let pollCount = 0, terminalStatus = "indexing";
  const polledCancel = harness("rom", (url) => {
    if (url === "/api/references/refresh") return Promise.resolve({ job: "after-poll" });
    if (url.startsWith("/api/job?")) return ++pollCount === 1 ? Promise.resolve({ state: "running", log: ["indexing"] }) : pendingPoll.promise;
    if (url === "/api/job/cancel") return Promise.resolve({});
    if (url.startsWith("/api/references?")) return Promise.resolve({ sources: [sourceRow({ status: terminalStatus })] });
    return Promise.resolve({ results: [], truncated: false });
  });
  const polledRun = polledCancel.ctx.changeReference("/api/references/refresh", { slug: "one", id: 4 }, "Refresh");
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(pollCount >= 1, "job polling has begun before cancellation");
  const pollRoot = polledCancel.get("referenceLog").children.find((node) => node.className === "reference-operation");
  assert.match(pollRoot.children.find((node) => node.className === "reference-operation-log").textContent, /indexing/);
  const cancelControl = pollRoot.children.find((node) => node.className === "reference-cancel").children[0];
  assert.equal(typeof cancelControl.onclick, "function", "cancel remains available after followJob has streamed a poll");
  await polledCancel.ctx.loadReferences();  // navigating away and back calls this again
  assert.equal(polledCancel.get("referenceLog").children[0], pollRoot, "tab revisit preserves the active job root");
  assert.equal(cancelControl.isConnected, true);
  const indexingRow = polledCancel.get("referenceList").children[0];
  const indexingButtons = indexingRow.querySelectorAll("button");
  assert.ok(indexingButtons.length && indexingButtons.every((button) => button.disabled), "freshly rendered actions stay disabled");
  const postsBeforeSearch = polledCancel.calls.filter(([, options]) => options?.method === "POST").length;
  await polledCancel.get("referenceSearch").onsubmit({ preventDefault() {} });
  assert.equal(polledCancel.calls.some(([url]) => url.includes("/search?")), false, "search cannot replace an active job root");
  assert.equal(cancelControl.isConnected, true);
  await indexingButtons[0].onclick();
  assert.equal(polledCancel.calls.filter(([, options]) => options?.method === "POST").length, postsBeforeSearch, "fresh stale button callback cannot start concurrent work");
  await cancelControl.onclick();
  terminalStatus = "cancelled";
  pendingPoll.resolve({ state: "cancelled", error: "Operation was cancelled.", log: ["latest log"] });
  await polledRun;
  assert.ok(polledCancel.calls.some(([url, opts]) => url === "/api/job/cancel" && opts.body.id === "after-poll"));
  assert.match(polledCancel.get("referenceList").children[0].children[1].textContent, /cancelled/);
  assert.equal(polledCancel.get("referenceList").children[0].querySelectorAll("button")[0].disabled, false, "actions are restored after terminal reload");

  // Start and job errors leave useful diagnostics visible and clear the operation work bar.
  for (const failure of ["start", "job"]) {
    const failed = harness("rom", async (url) => {
      if (url === "/api/references/refresh") { if (failure === "start") throw new Error("Cannot start refresh"); return { job: "bad" }; }
      if (url.startsWith("/api/job?")) return { state: "error", error: "Refresh failed", log: ["kept diagnostic"] };
      return { sources: [sourceRow({ status: failure === "job" ? "error" : "registered", error: failure === "job" ? "last refresh failed" : null })] };
    });
    await failed.ctx.changeReference("/api/references/refresh", { slug: "one", id: 4 }, "Refresh");
    const opLog = failed.get("referenceLog").children[0].children.find((node) => node.className === "reference-operation-log");
    assert.ok(opLog._errorBox);
    assert.match(opLog._errorBox.textContent, failure === "start" ? /Cannot start refresh/ : /Refresh failed/);
    assert.equal(opLog.parent.children.some((node) => node.className === "workbar"), false);
    if (failure === "job") {
      assert.equal(opLog.textContent, "kept diagnostic");
      assert.match(failed.get("referenceList").children[0].children[1].textContent, /error/);
      assert.match(failed.get("referenceList").children[0].children[2].textContent, /last refresh failed/);
    }
  }

  // A slow earlier query cannot replace a later result; snippets remain literal text.
  const first = deferred(), second = deferred(); let searches = 0;
  const searchHarness = harness("rom", (url) => url.includes("/search?") ? (++searches === 1 ? first.promise : second.promise) : Promise.resolve({ sources: [] }));
  searchHarness.get("referenceQuery").value = "old"; const oldRun = searchHarness.get("referenceSearch").onsubmit({ preventDefault() {} });
  searchHarness.get("referenceQuery").value = "new"; const newRun = searchHarness.get("referenceSearch").onsubmit({ preventDefault() {} });
  second.resolve({ results: [{ source_name: "<x>", path: "<img>", line: 2, end_line: 2, excerpt: "<script>alert(1)</script>", stale: false }], truncated: true }); await newRun;
  first.resolve({ results: [], truncated: false }); await oldRun;
  const resultText = searchHarness.get("referenceResults").children.flatMap((e) => e.children || [e]).map((e) => e.textContent).concat(searchHarness.get("referenceResults").children.map((e) => e.textContent)).join(" ");
  assert.match(resultText, /<script>alert/); assert.match(resultText, /More matches/); assert.doesNotMatch(resultText, /No matching text/);
  assert.ok(searchHarness.calls.some(([url]) => url.includes("q=new")));
  const bounded = harness("fork", async () => ({ results: [], truncated: false }));
  bounded.get("referenceQuery").value = "x".repeat(1200);
  await bounded.get("referenceSearch").onsubmit({ preventDefault() {} });
  assert.ok(bounded.calls[0][0].includes(`q=${"x".repeat(1000)}`));
  assert.equal(bounded.get("referenceLog").children.length, 1, "completed search logs are bounded to one visible operation");
  assert.equal(bounded.get("referenceResults").children[0].textContent, "No matching text.");

  // Search/list/job responses for a previous project do not render into the current project.
  const pendingList = deferred(), switchHarness = harness("rom", () => pendingList.promise);
  const listRun = switchHarness.ctx.loadReferences(); switchHarness.ctx.S.slug = "two"; switchHarness.ctx.S.gen++;
  pendingList.resolve({ sources: [sourceRow({ name: "wrong project" })] }); await listRun;
  assert.equal(switchHarness.get("referenceList").children.length, 0);

  const oldCallback = harness("rom", async (url) => url.startsWith("/api/references?") ? { sources: [sourceRow()] } : { job: "unused" });
  await oldCallback.ctx.loadReferences();
  const staleRefresh = oldCallback.get("referenceList").children[0].children.find((node) => node.textContent === "Refresh");
  oldCallback.ctx.S.slug = "two"; oldCallback.ctx.S.gen++; oldCallback.ctx.window.resetReferences();
  await staleRefresh.onclick();
  assert.equal(oldCallback.calls.some(([url]) => url === "/api/references/refresh"), false);
  assert.equal(oldCallback.get("referenceList").children.length, 0);

  const oldSearch = deferred(), searchSwitch = harness("rom", () => oldSearch.promise);
  searchSwitch.get("referenceQuery").value = "old";
  const oldSearchRun = searchSwitch.get("referenceSearch").onsubmit({ preventDefault() {} });
  assert.equal(searchSwitch.get("referenceSearchButton").disabled, true);
  searchSwitch.ctx.S.slug = "new"; searchSwitch.ctx.S.gen++; searchSwitch.ctx.window.resetReferences();
  assert.equal(searchSwitch.get("referenceSearchButton").disabled, false, "reset releases in-flight search controls");
  oldSearch.resolve({ results: [{ source_name: "previous", path: "old.txt", line: 1, end_line: 1, excerpt: "old" }], truncated: false });
  await oldSearchRun;
  assert.equal(searchSwitch.get("referenceResults").children.length, 0);
  const jobStart = deferred(), jobPoll = deferred();
  const switchedJob = harness("fork", (url) => url === "/api/references/refresh" ? jobStart.promise : url.startsWith("/api/job?") ? jobPoll.promise : Promise.resolve({ sources: [] }));
  const jobRun = switchedJob.ctx.changeReference("/api/references/refresh", { slug: "one", id: 4 }, "Refresh");
  jobStart.resolve({ job: "slow" }); await Promise.resolve(); await Promise.resolve();
  switchedJob.ctx.S.slug = "two"; switchedJob.ctx.S.gen++;
  jobPoll.resolve({ state: "error", error: "old project failure", log: ["old project log"] }); await jobRun;
  assert.equal(switchedJob.calls.filter(([url]) => url.startsWith("/api/references?")).length, 0);

  const oldStart = deferred(), oldPoll = deferred();
  const resetJob = harness("rom", (url) => url === "/api/references/refresh" ? oldStart.promise : url.startsWith("/api/job?") ? oldPoll.promise : Promise.resolve({ sources: [] }));
  const resetRun = resetJob.ctx.changeReference("/api/references/refresh", { slug: "one", id: 4 }, "Refresh");
  assert.equal(resetJob.get("referenceAddFile").disabled, true);
  resetJob.ctx.S.slug = "two"; resetJob.ctx.S.gen++; resetJob.ctx.window.resetReferences();
  assert.equal(resetJob.get("referenceLog").children.length, 0);
  assert.equal(resetJob.get("referenceAddFile").disabled, false, "reset releases stale operation controls");
  oldStart.resolve({ job: "old" }); await Promise.resolve(); await Promise.resolve();
  oldPoll.resolve({ state: "error", error: "old project failure", log: ["old project private diagnostic"] }); await resetRun;
  assert.equal(resetJob.get("referenceLog").children.length, 0, "old job logs/errors stay detached after reset");
  assert.equal(resetJob.calls.filter(([url]) => url.startsWith("/api/references?")).length, 0, "old operation does not reload the new project's list");
  console.log("reference UI scenarios passed");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
