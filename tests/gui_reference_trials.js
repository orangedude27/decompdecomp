// Owner trial flow against the production script, DOM-like controls, and deferred route responses.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const script = fs.readFileSync("src/decompnet/app/static/js/reference_trials.js", "utf8");
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); promise.catch(() => {}); return { promise, resolve, reject }; }
class Element {
  constructor(tag = "div") { this.tagName = tag.toUpperCase(); this.children = []; this.parent = null; this.dataset = {}; this.disabled = false; this.checked = false; this.listeners = {}; this._value = ""; this._text = ""; this.onclick = null; }
  get options() { return this.children.filter((child) => child.tagName === "OPTION"); }
  get value() { return this.tagName === "SELECT" && !this.options.some((option) => option.value === this._value) ? (this.options[0]?.value || "") : this._value; }
  set value(value) { this._value = String(value); }
  append(...nodes) { for (const child of nodes) { child.remove(); child.parent = this; this.children.push(child); } }
  replaceChildren(...nodes) { for (const child of this.children) { child.parent = null; } this.children = []; this._text = ""; this.append(...nodes); }
  remove() { if (this.parent) { this.parent.children = this.parent.children.filter((child) => child !== this); this.parent = null; } }
  addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
  dispatch(name) { for (const fn of this.listeners[name] || []) fn({ target: this }); if (name === "change" && this.onchange) this.onchange({ target: this }); }
  get isConnected() { return this.parent ? this.parent.isConnected : true; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
}
const referenceControlOwners = new Map();
function claimReferenceControls(controls) { for (const control of controls) { if (!referenceControlOwners.has(control)) referenceControlOwners.set(control, { disabled: control.disabled, owners: 0 }); const owner = referenceControlOwners.get(control); owner.owners++; control.disabled = true; } }
function releaseReferenceControls(controls, operation) {
  if (operation?.controlsReleased) return;
  if (operation) operation.controlsReleased = true;
  for (const control of controls) { const owner = referenceControlOwners.get(control); if (owner && --owner.owners === 0) { control.disabled = owner.disabled; referenceControlOwners.delete(control); } }
}
const sourceText = 'int target(void) { const char *s = "<script>literal</script>"; return 0; }';
const origin = { kind: "file", source_id: 5, path: "a.c", content_hash: "a".repeat(64) };
const sources = { sources: [{ id: 5, name: "Reference", kind: "file", status: "ready", enabled: true, stale: false }, { id: 6, name: "stale", status: "ready", enabled: true, stale: true }] };
const files = { files: [{ origin, name: "a.c", has_code: true }] };
const targets = { targets: [{ id: 8, name: "target", unit: "u.c", eligible: true }, { id: 9, name: "claimed", eligible: false, reason: "claimed" }] };
function harness(kind, apiImpl) {
  const ids = ["referencesPane", "trialSource", "trialFile", "trialTarget", "trialShowSource", "trialName", "trialStart", "trialEnd", "trialMappings", "trialCode", "trialPrelude", "trialPrepare", "trialPreview", "trialConsent", "trialRun", "trialLog", "trialHistory"];
  const nodes = new Map(ids.map((id) => [id, new Element(["trialSource", "trialFile", "trialTarget"].includes(id) ? "select" : id === "trialPrepare" || id === "trialRun" || id === "trialShowSource" ? "button" : "div")]));
  const pane = nodes.get("referencesPane"); for (const [id, node] of nodes) if (id !== "referencesPane") pane.append(node);
  nodes.get("trialConsent").disabled = true;
  const calls = [], ctx = { S: { slug: "project", gen: 1, ov: { kind } }, window: {}, document: { createElement: (tag) => new Element(tag) },
    referenceControlOwners, claimReferenceControls, releaseReferenceControls, Promise, JSON, encodeURIComponent,
    beginWork: (log, label) => { const bar = new Element("div"); bar.textContent = label; log.append(bar); return () => bar.remove(); },
    showJobError: (log, message) => { const error = new Element("p"); error.textContent = message; log.append(error); },
    api: (url, options = {}) => { calls.push({ url, options }); return apiImpl(url, options, ctx); } };
  ctx.$ = (id) => nodes.get(id);
  vm.createContext(ctx); vm.runInContext(script, ctx);
  return { ctx, nodes, calls };
}
function defaultApi(url, options, ctx) {
  if (url.startsWith("/api/references?")) return Promise.resolve(sources);
  if (url.startsWith("/api/reference-trials/files")) return Promise.resolve(files);
  if (url.startsWith("/api/reference-trials/targets")) return Promise.resolve(targets);
  if (url.startsWith("/api/reference-trials?") || url.startsWith("/api/reference-trials/detail?")) return Promise.resolve({ trials: [] });
  if (url === "/api/reference-trials/source") return Promise.resolve({ text: sourceText });
  if (url === "/api/reference-trials/prepare") return Promise.resolve({ plan: "signed", ready: true, source: sourceText, prelude: "", source_hash: "hash", prelude_hash: "prehash", context: { mode: ctx?.S.ov.kind || "project", compiler: "cc", flags: "-O2" }, provenance: { source_name: "Reference", path: "a.c", start: 1, end_line: 1 }, target: { name: "target", unit: "u.c" }, warnings: [] });
  if (url === "/api/reference-trials/run") return Promise.resolve({ outcome: "nonmatch", matched: false, percent: 100, trial: null, text: "not identical" });
  throw new Error(`Unexpected API call ${url} ${JSON.stringify(options)}`);
}
async function prepare(h) { await h.nodes.get("trialPrepare").onclick(); }
function readyConsent(h) { const consent = h.nodes.get("trialConsent"); assert.equal(consent.disabled, false); assert.equal(consent.checked, false); consent.checked = true; consent.onchange(); }
async function main() {
  for (const mode of ["rom", "fork"]) {
    const h = harness(mode, defaultApi), n = h.nodes;
    await h.ctx.loadReferenceTrials();
    assert.equal(n.get("trialSource").options.length, 1, "stale source is excluded");
    assert.equal(n.get("trialTarget").options.length, 2);
    assert.equal(n.get("trialConsent").checked, false); assert.equal(n.get("trialConsent").disabled, true);
    n.get("trialFile").value = JSON.stringify(origin); n.get("trialTarget").value = "8";
    await n.get("trialShowSource").onclick();
    assert.equal(h.calls.some((call) => call.url === "/api/reference-trials/run"), false, "source preview never runs code");
    assert.match(n.get("trialPreview").textContent, /<script>literal/);
    await prepare(h);
    assert.ok(n.get("trialPreview").textContent.includes(`mode ${mode}`)); assert.ok(n.get("trialPreview").textContent.includes("compiler cc"));
    assert.equal(n.get("trialConsent").checked, false); assert.equal(n.get("trialConsent").disabled, false);
    assert.equal(n.get("trialRun").disabled, true);
    readyConsent(h); n.get("trialCode").value = "edited"; n.get("trialCode").dispatch("input");
    assert.equal(n.get("trialConsent").checked, false); assert.equal(n.get("trialConsent").disabled, true); assert.equal(n.get("trialRun").disabled, true);
    await prepare(h); assert.equal(n.get("trialConsent").checked, false, "reprepare requires fresh consent");
    readyConsent(h); await n.get("trialRun").onclick();
    assert.ok(h.calls.some((call) => call.url === "/api/reference-trials/run" && call.options.body.accept_if_verified === true && call.options.body.allow_progress_copy === true));
    assert.match(n.get("trialLog").textContent, /Not an exact match · 100% similarity/);
    assert.doesNotMatch(n.get("trialLog").textContent, /Verified exact match/);
  }

  // Every editable plan field invalidates the token and its previous consent.
  const invalidations = harness("fork", defaultApi);
  await invalidations.ctx.loadReferenceTrials(); invalidations.nodes.get("trialFile").value = JSON.stringify(origin); invalidations.nodes.get("trialTarget").value = "8"; await prepare(invalidations); readyConsent(invalidations);
  for (const [id, event] of [["trialName", "input"], ["trialStart", "input"], ["trialEnd", "input"], ["trialMappings", "input"], ["trialPrelude", "input"], ["trialCode", "input"]]) {
    invalidations.nodes.get(id).dispatch(event);
    assert.equal(invalidations.nodes.get("trialConsent").checked, false, `${id} clears consent`);
    assert.equal(invalidations.nodes.get("trialConsent").disabled, true, `${id} disables consent until a fresh plan`);
  }
  invalidations.nodes.get("trialConsent").checked = true;
  invalidations.nodes.get("trialSource").onchange();
  assert.equal(invalidations.nodes.get("trialCode").value, ""); assert.equal(invalidations.nodes.get("trialPrelude").value, "");

  // Missing flags differ from explicit empty flag lists in a reviewed preview.
  let flagPreview = 0;
  const flags = harness("project", (url, options, ctx) => {
    if (url === "/api/reference-trials/prepare") {
      flagPreview++;
      return defaultApi(url, options, ctx).then((preview) => {
        const context = { ...preview.context };
        if (flagPreview === 1) delete context.flags;
        else if (flagPreview === 2) context.flags = [];
        else context.flags = "";
        return { ...preview, context };
      });
    }
    return defaultApi(url, options, ctx);
  });
  await flags.ctx.loadReferenceTrials(); flags.nodes.get("trialFile").value = JSON.stringify(origin); flags.nodes.get("trialTarget").value = "8";
  await prepare(flags); assert.match(flags.nodes.get("trialPreview").textContent, /flags not shown/);
  flags.nodes.get("trialName").value = "same target"; flags.nodes.get("trialName").dispatch("input");
  await prepare(flags); assert.match(flags.nodes.get("trialPreview").textContent, /flags \[\]/);
  flags.nodes.get("trialName").value = "empty flags"; flags.nodes.get("trialName").dispatch("input");
  await prepare(flags); assert.match(flags.nodes.get("trialPreview").textContent, /flags "" \(empty string\)/);

  // Owner history still loads when there are no currently usable reference sources.
  const noSources = harness("rom", (url) => url.startsWith("/api/references?") ? Promise.resolve({ sources: [] }) : url.startsWith("/api/reference-trials?") ? Promise.resolve({ trials: [{ id: 3, outcome: "failed", target_name: "old" }] }) : defaultApi(url));
  await noSources.ctx.loadReferenceTrials();
  assert.equal(noSources.nodes.get("trialHistory").children.length, 1);
  assert.equal(noSources.nodes.get("trialSource").options[0].disabled, true);

  // A plan response arriving after any edit must not replace the user's newer inputs.
  const delayedPrepare = deferred(), h = harness("rom", (url, options) => url === "/api/reference-trials/prepare" ? delayedPrepare.promise : defaultApi(url, options));
  await h.ctx.loadReferenceTrials(); h.nodes.get("trialFile").value = JSON.stringify(origin); h.nodes.get("trialTarget").value = "8";
  const pending = prepare(h);
  for (const [id, value] of [["trialName", "new name"], ["trialStart", "14"], ["trialEnd", "18"], ["trialMappings", "old=new"], ["trialPrelude", "new prelude"], ["trialCode", "newer code"]]) {
    h.nodes.get(id).value = value; h.nodes.get(id).dispatch("input");
  }
  delayedPrepare.resolve({ plan: "old", ready: true, source: "old response", prelude: "old prelude", target: { name: "target" }, context: {}, provenance: {}, warnings: [] });
  await pending;
  assert.equal(h.nodes.get("trialCode").value, "newer code"); assert.equal(h.nodes.get("trialPrelude").value, "new prelude");
  assert.equal(h.nodes.get("trialName").value, "new name"); assert.equal(h.nodes.get("trialStart").value, "14"); assert.equal(h.nodes.get("trialEnd").value, "18");
  assert.equal(h.nodes.get("trialConsent").checked, false);

  // Changing origin or target clears reviewed code and a late files response cannot populate a different source.
  const oldFiles = deferred(); let fileCalls = 0;
  const stale = harness("fork", (url, options) => url.startsWith("/api/reference-trials/files") ? (++fileCalls === 1 ? Promise.resolve(files) : oldFiles.promise) : defaultApi(url, options));
  await stale.ctx.loadReferenceTrials(); stale.nodes.get("trialCode").value = "old candidate"; stale.nodes.get("trialPrelude").value = "old prelude";
  stale.nodes.get("trialTarget").dispatch("change"); assert.equal(stale.nodes.get("trialCode").value, "");
  stale.nodes.get("trialCode").value = "candidate again"; stale.nodes.get("trialFile").value = JSON.stringify({ ...origin, path: "b.c" }); stale.nodes.get("trialFile").dispatch("change");
  assert.equal(stale.nodes.get("trialCode").value, "", "file changes clear source from the old origin");
  stale.nodes.get("trialSource").onchange(); stale.ctx.S.slug = "other"; stale.ctx.S.gen++;
  stale.ctx.window.resetReferenceTrials(); oldFiles.resolve(files); await Promise.resolve();
  assert.equal(stale.nodes.get("trialFile").options.length, 0);

  // Delayed old-project source/target failures cannot write errors or choices into the new project.
  const staleTargetResponse = deferred(), staleTarget = harness("rom", (url, options) => url.startsWith("/api/reference-trials/targets") ? staleTargetResponse.promise : defaultApi(url, options));
  const targetLoad = staleTarget.ctx.loadReferenceTrials();
  for (let turn = 0; turn < 5 && !staleTarget.calls.some((call) => call.url.startsWith("/api/reference-trials/targets")); turn++) await Promise.resolve();
  staleTarget.ctx.S.slug = "next"; staleTarget.ctx.S.gen++; staleTarget.ctx.window.resetReferenceTrials();
  staleTargetResponse.reject(new Error("old target request")); await targetLoad;
  assert.equal(staleTarget.nodes.get("trialTarget").options.length, 0); assert.equal(staleTarget.nodes.get("trialLog").textContent, "");
  const staleSourceResponse = deferred(), staleSource = harness("fork", (url, options) => url === "/api/reference-trials/source" ? staleSourceResponse.promise : defaultApi(url, options));
  await staleSource.ctx.loadReferenceTrials(); staleSource.nodes.get("trialFile").value = JSON.stringify(origin);
  const sourceRead = staleSource.nodes.get("trialShowSource").onclick(); staleSource.ctx.S.slug = "next"; staleSource.ctx.S.gen++; staleSource.ctx.window.resetReferenceTrials();
  staleSourceResponse.reject(new Error("old source request")); await sourceRead;
  assert.equal(staleSource.nodes.get("trialLog").textContent, "");

  // Exactness follows matched=true, not a score of 100; the result is a normal status, not an error.
  const exact = harness("fork", (url, options) => url === "/api/reference-trials/run" ? Promise.resolve({ outcome: "matched", matched: true, score: 0, percent: 100 }) : defaultApi(url, options));
  await exact.ctx.loadReferenceTrials(); exact.nodes.get("trialFile").value = JSON.stringify(origin); exact.nodes.get("trialTarget").value = "8"; await prepare(exact); readyConsent(exact); await exact.nodes.get("trialRun").onclick();
  assert.match(exact.nodes.get("trialLog").textContent, /Verified exact match/);

  // A same-project refresh while an admitted run is pending must preserve choices, progress and shared control ownership.
  const runResponse = deferred(), active = harness("rom", (url, options) => url === "/api/reference-trials/run" ? runResponse.promise : defaultApi(url, options));
  await active.ctx.loadReferenceTrials(); active.nodes.get("trialFile").value = JSON.stringify(origin); active.nodes.get("trialTarget").value = "8"; await prepare(active); readyConsent(active);
  const external = active.nodes.get("trialRun"), consent = active.nodes.get("trialConsent"); claimReferenceControls([external, consent]);
  const run = active.nodes.get("trialRun").onclick(); await active.ctx.loadReferenceTrials();
  assert.equal(active.nodes.get("trialSource").value, "5"); assert.equal(active.nodes.get("trialCode").value, sourceText);
  assert.equal(external.disabled, true, "another owner's control remains disabled");
  runResponse.resolve({ outcome: "failed", matched: false, percent: null, text: "build failed" }); await run;
  assert.equal(external.disabled, true, "trial cleanup cannot release another owner's control");
  assert.equal(consent.disabled, true, "trial cleanup cannot release the shared consent control");
  assert.match(active.nodes.get("trialLog").textContent, /build failed/);
  releaseReferenceControls([external, consent]);

  // Project reset hides an admitted run without cancelling it or allowing its result to write into the next project.
  const switchedRun = deferred(), switched = harness("fork", (url, options) => url === "/api/reference-trials/run" ? switchedRun.promise : defaultApi(url, options));
  await switched.ctx.loadReferenceTrials(); switched.nodes.get("trialFile").value = JSON.stringify(origin); switched.nodes.get("trialTarget").value = "8"; await prepare(switched); readyConsent(switched);
  const inFlight = switched.nodes.get("trialRun").onclick();
  switched.ctx.S.slug = "different-project"; switched.ctx.S.gen++; switched.ctx.window.resetReferenceTrials();
  assert.equal(switched.calls.filter((call) => call.url === "/api/reference-trials/run").length, 1);
  await switched.ctx.loadReferenceTrials(); assert.equal(switched.nodes.get("trialSource").options.length, 0);
  switchedRun.resolve({ outcome: "matched", matched: true, percent: 100 }); await inFlight; await Promise.resolve();
  assert.doesNotMatch(switched.nodes.get("trialLog").textContent, /Verified exact match/);

  // Historical details are text, and errors stay visible without turning data into markup.
  const history = harness("rom", (url) => url.startsWith("/api/reference-trials?") ? Promise.resolve({ trials: [{ id: 4, status: "nonmatch", outcome: { matched: false, percent: 100, text: "not identical" }, target_name: "f" }] }) : url.startsWith("/api/reference-trials/detail?") ? Promise.resolve({ source: "<img src=x onerror=alert(1)>", prelude: "", outcome: "nonmatch" }) : defaultApi(url));
  await history.ctx.loadReferenceTrials();
  const historyText = history.nodes.get("trialHistory").children[0].children[0].textContent;
  assert.match(historyText, /nonmatch · 100% · not identical · f/); assert.doesNotMatch(historyText, /\[object Object\]/);
  await history.nodes.get("trialHistory").children[0].children[1].onclick();
  assert.equal(history.nodes.get("trialPreview").children[2].textContent, "<img src=x onerror=alert(1)>");
  const errors = harness("rom", (url) => url === "/api/reference-trials/prepare" ? Promise.reject(new Error("stale plan")) : defaultApi(url));
  await errors.ctx.loadReferenceTrials(); errors.nodes.get("trialFile").value = JSON.stringify(origin); errors.nodes.get("trialTarget").value = "8"; await prepare(errors);
  assert.match(errors.nodes.get("trialLog").textContent, /stale plan/);
  console.log("reference trial UI acceptance checks passed");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
