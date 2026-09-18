// Tests for release-watch.js — plain node (no dependencies):
//   node test_release_watch.mjs
// Every case follows Given-When-Then.

import test from "node:test";
import assert from "node:assert/strict";

import worker, {
  DEFAULTS,
  binaryUrlFor,
  decodeEntities,
  latestVersionFromAtom,
  runCheck,
} from "./release-watch.js";

const FEED_URL = DEFAULTS.FEED_URL;
const API_URL = `${DEFAULTS.GITHUB_API}/repos/${DEFAULTS.GITHUB_REPO}/dispatches`;
const ASSET_URL = (v) => DEFAULTS.BINARY_URL_TEMPLATE.replaceAll("{version}", v);

function feedXml(latestTitle, olderTitle = "v2.1.273") {
  return `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en-US">
  <id>tag:github.com,2008:https://github.com/anthropics/claude-code/releases</id>
  <title>Release notes from claude-code</title>
  <updated>2026-09-17T00:11:55Z</updated>
  <entry>
    <id>tag:github.com,2008:Repository/937253475/${latestTitle}</id>
    <updated>2026-09-17T00:12:02Z</updated>
    <title>${latestTitle}</title>
  </entry>
  <entry>
    <id>tag:github.com,2008:Repository/937253475/${olderTitle}</id>
    <updated>2026-09-16T00:00:00Z</updated>
    <title>${olderTitle}</title>
  </entry>
</feed>`;
}

// A fetch stand-in: rules match by (url, method); every call is recorded.
function mockFetch(rules) {
  const calls = [];
  const f = async (url, init = {}) => {
    const method = init.method ?? "GET";
    calls.push({ url, method, init });
    for (const rule of rules) {
      if (rule.test(url, method)) {
        const r = typeof rule.respond === "function" ? rule.respond(url, method) : rule.response;
        if (r.throw) throw new Error(r.throw);
        // 204-style statuses take no body (undici rejects a non-null one).
        return new Response(r.body === undefined ? null : r.body, { status: r.status ?? 200 });
      }
    }
    return new Response(null, { status: 404 });
  };
  f.calls = calls;
  return f;
}

function mockKv() {
  const store = new Map();
  return {
    store,
    async get(key) {
      return store.has(key) ? JSON.parse(store.get(key)) : null;
    },
    async put(key, value) {
      store.set(key, value);
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

const env = {
  GITHUB_REPO: DEFAULTS.GITHUB_REPO,
  BRANCH: DEFAULTS.BRANCH,
  GITHUB_TOKEN: "test-token",
};

const baseRules = (latest = "v2.1.274") => [
  { test: (u, m) => u === FEED_URL && m === "GET", response: { body: feedXml(latest) } },
  { test: (u, m) => u === API_URL && m === "POST", response: { status: 204 } },
  { test: (u, m) => m === "HEAD", response: { status: 200 } },
];

function state(kvs, doc) {
  kvs.store.set(DEFAULTS.STATE_KEY, JSON.stringify(doc));
}

const request = (path, { method = "GET", headers = {} } = {}) =>
  new Request(`https://worker.test${path}`, { method, headers });

test("decodeEntities decodes the feed title entities", () => {
  // Given: a title with the entities GitHub may emit. When: decoded.
  // Then: the raw text is back, untouched text passes through.
  assert.equal(decodeEntities("v2.1.2&#56; &amp; more"), "v2.1.28 & more");
  assert.equal(decodeEntities("v2.1.2&#x38;"), "v2.1.28");
  assert.equal(decodeEntities("unknown &#x110000; stays"), "unknown &#x110000; stays");
  assert.equal(decodeEntities("plain"), "plain");
});

test("latestVersionFromAtom picks the newest entry (first one, v-prefixed)", () => {
  // Given: the real feed shape (v-prefixed titles, newest first).
  // When: parsed. Then: the FIRST entry's version, v stripped.
  assert.equal(latestVersionFromAtom(feedXml("v2.1.274")), "2.1.274");
});

test("latestVersionFromAtom accepts a bare semver title", () => {
  // Given: a title without the v prefix. When: parsed. Then: the version.
  assert.equal(latestVersionFromAtom(feedXml("2.1.274")), "2.1.274");
});

test("latestVersionFromAtom accepts pre-release suffixes", () => {
  // Given: a v-prefixed pre-release title. When: parsed. Then: the semver.
  assert.equal(latestVersionFromAtom(feedXml("v2.1.274-beta.1")), "2.1.274-beta.1");
});

test("latestVersionFromAtom returns null when there is no entry", () => {
  // Given: a feed with no <entry> blocks. When: parsed. Then: null (refused).
  assert.equal(latestVersionFromAtom("<feed><title>x</title></feed>"), null);
});

test("latestVersionFromAtom returns null for a non-version title", () => {
  // Given: an entry whose title is not a version (no-guess: never invent).
  // When: parsed. Then: null.
  assert.equal(latestVersionFromAtom(feedXml("Unstable build 42")), null);
});

test("latestVersionFromAtom decodes entities in the title", () => {
  // Given: a title with a numeric entity (&#48; = 8).
  // When: parsed. Then: the decoded version.
  assert.equal(latestVersionFromAtom(feedXml("v2.1.27&#56;")), "2.1.278");
});

test("binaryUrlFor substitutes the version into the default template", () => {
  // Given: a semver. When: resolved against the default template.
  // Then: the release-asset URL for that version's tag.
  assert.equal(binaryUrlFor("2.1.274"), ASSET_URL("2.1.274"));
});

test("binaryUrlFor honors a custom template", () => {
  // Given: a template for a different distribution shape (npm tarball).
  // When: resolved. Then: the substituted URL.
  assert.equal(
    binaryUrlFor("2.1.274", "https://example.test/pkg-{version}.tgz"),
    "https://example.test/pkg-2.1.274.tgz",
  );
});

test("binaryUrlFor passes through a placeholder-free template", () => {
  // Given: a static URL (no {version}). When: resolved. Then: the URL as-is.
  assert.equal(binaryUrlFor("2.1.274", "https://example.test/binary"), "https://example.test/binary");
});

test("binaryUrlFor refuses a non-semver version", () => {
  // Given: a version that is not a semver. When: resolved. Then: null.
  assert.equal(binaryUrlFor("latest"), null);
  assert.equal(binaryUrlFor(undefined), null);
});

test("runCheck dispatches a new release and records it", async () => {
  // Given: an empty state and a feed whose newest release is unrecorded.
  const kvs = mockKv();
  const f = mockFetch(baseRules());
  // When: a watch tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: the repository_dispatch event kick-off-patcher was sent with the
  // version + binary URL in client_payload (the workflow reads them from
  // github.event.client_payload), and the state now records it as dispatched.
  assert.equal(result.action, "dispatched");
  const post = f.calls.find((c) => c.url === API_URL);
  assert.ok(post);
  const body = JSON.parse(await new Response(post.init.body).text());
  assert.equal(body.event_type, "kick-off-patcher");
  assert.deepEqual(body.client_payload, { version: "2.1.274", binary_url: ASSET_URL("2.1.274") });
  const st = await kvs.get(DEFAULTS.STATE_KEY);
  assert.equal(st.version, "2.1.274");
  assert.equal(st.dispatched, true);
});

test("runCheck is a no-op when the latest version was already dispatched", async () => {
  // Given: state recording the current latest as dispatched.
  const kvs = mockKv();
  state(kvs, { version: "2.1.274", binaryUrl: ASSET_URL("2.1.274"), dispatched: true });
  const f = mockFetch(baseRules());
  // When: a watch tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: the feed was read but nothing else happened (no asset check, no
  // dispatch, no state rewrite).
  assert.equal(result.action, "up-to-date");
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, FEED_URL);
});

test("runCheck force re-dispatches an already-dispatched version", async () => {
  // Given: state recording the current latest as dispatched.
  const kvs = mockKv();
  state(kvs, { version: "2.1.274", binaryUrl: ASSET_URL("2.1.274"), dispatched: true });
  const f = mockFetch(baseRules());
  // When: a tick runs with force.
  const result = await runCheck({ env, kv: kvs, fetch: f, force: true });
  // Then: the dispatch is attempted again.
  assert.equal(result.action, "dispatched");
  assert.ok(f.calls.some((c) => c.url === API_URL));
});

test("runCheck skips dispatch when the release has no asset yet", async () => {
  // Given: a new version whose asset returns 404 (still uploading).
  const kvs = mockKv();
  const f = mockFetch([
    { test: (u, m) => u === FEED_URL && m === "GET", response: { body: feedXml("v2.1.274") } },
    { test: (u, m) => u === API_URL && m === "POST", response: { status: 204 } },
    { test: (u, m) => m === "HEAD", response: { status: 404 } },
  ]);
  // When: a watch tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: no dispatch and no state written (the next tick rechecks the asset).
  assert.equal(result.action, "no-asset");
  assert.ok(!f.calls.some((c) => c.url === API_URL));
  assert.equal(await kvs.get(DEFAULTS.STATE_KEY), null);
});

test("runCheck records a failed dispatch for retry", async () => {
  // Given: a new version and a GitHub API that answers 401 (bad token).
  const kvs = mockKv();
  const f = mockFetch([
    { test: (u, m) => u === FEED_URL && m === "GET", response: { body: feedXml("v2.1.274") } },
    { test: (u, m) => u === API_URL && m === "POST", response: { status: 401, body: "bad token" } },
    { test: (u, m) => m === "HEAD", response: { status: 200 } },
  ]);
  // When: a watch tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: the failure is reported and the state says NOT dispatched, so the
  // next tick retries.
  assert.equal(result.action, "dispatch-failed");
  assert.equal(result.status, 401);
  const st = await kvs.get(DEFAULTS.STATE_KEY);
  assert.equal(st.dispatched, false);
});

test("runCheck retries a previously failed dispatch", async () => {
  // Given: state with the current latest recorded as NOT dispatched.
  const kvs = mockKv();
  state(kvs, { version: "2.1.274", binaryUrl: ASSET_URL("2.1.274"), dispatched: false });
  const f = mockFetch(baseRules());
  // When: the next tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: the dispatch is attempted again and, on 204, now recorded dispatched.
  assert.equal(result.action, "dispatched");
  assert.ok(f.calls.some((c) => c.url === API_URL));
  assert.equal((await kvs.get(DEFAULTS.STATE_KEY)).dispatched, true);
});

test("runCheck survives a feed outage without writing state", async () => {
  // Given: a feed that cannot be reached.
  const kvs = mockKv();
  const f = mockFetch([{ test: (u, m) => u === FEED_URL, response: { throw: "network down" } }]);
  // When: a watch tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: it reports the error, writes no state, and dispatches nothing.
  assert.equal(result.action, "feed-error");
  assert.equal(await kvs.get(DEFAULTS.STATE_KEY), null);
  assert.ok(!f.calls.some((c) => c.url === API_URL));
});

test("runCheck survives an asset-check outage", async () => {
  // Given: a new version whose asset HEAD throws (not a 404, a network error).
  const kvs = mockKv();
  const f = mockFetch([
    { test: (u, m) => u === FEED_URL && m === "GET", response: { body: feedXml("v2.1.274") } },
    { test: (u, m) => u === API_URL && m === "POST", response: { status: 204 } },
    { test: (u, m) => m === "HEAD", response: { throw: "connection reset" } },
  ]);
  // When: a watch tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: no dispatch and no state (the next tick rechecks from scratch).
  assert.equal(result.action, "asset-check-error");
  assert.ok(!f.calls.some((c) => c.url === API_URL));
  assert.equal(await kvs.get(DEFAULTS.STATE_KEY), null);
});

test("runCheck records a dispatch network error as not dispatched", async () => {
  // Given: a new version and a dispatch that throws (not an HTTP error).
  const kvs = mockKv();
  const f = mockFetch([
    { test: (u, m) => u === FEED_URL && m === "GET", response: { body: feedXml("v2.1.274") } },
    { test: (u, m) => u === API_URL && m === "POST", response: { throw: "tls reset" } },
    { test: (u, m) => m === "HEAD", response: { status: 200 } },
  ]);
  // When: a watch tick runs.
  const result = await runCheck({ env, kv: kvs, fetch: f });
  // Then: reported as failed and recorded not-dispatched (retried next tick).
  assert.equal(result.action, "dispatch-failed");
  assert.equal(result.status, 0);
  assert.equal((await kvs.get(DEFAULTS.STATE_KEY)).dispatched, false);
});

test("handler: a cron tick (scheduled event) performs the check and records it", async () => {
  // Given: the ScheduledEvent a cron trigger delivers (no HTTP request).
  const kvs = mockKv();
  const realFetch = globalThis.fetch;
  globalThis.fetch = mockFetch(baseRules());
  try {
    // When: the tick runs.
    await worker.scheduled({ cron: "*/15 * * * *", scheduledTime: Date.now() },
                           { ...env, STATE: kvs });
    // Then: the dispatch was attempted and the state records it.
    assert.ok(globalThis.fetch.calls.some((c) => c.url === API_URL));
    const st = await kvs.get(DEFAULTS.STATE_KEY);
    assert.equal(st.version, "2.1.274");
    assert.equal(st.dispatched, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("handler: a cron tick on an up-to-date worker is a no-op", async () => {
  // Given: state already recording the current latest as dispatched.
  const kvs = mockKv();
  state(kvs, { version: "2.1.274", binaryUrl: ASSET_URL("2.1.274"), dispatched: true });
  const f = mockFetch(baseRules());
  const realFetch = globalThis.fetch;
  globalThis.fetch = f;
  try {
    await worker.scheduled({ cron: "*/15 * * * *", scheduledTime: Date.now() },
                           { ...env, STATE: kvs });
    // When: the tick runs. Then: only the feed was read; nothing dispatched.
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].url, FEED_URL);
    assert.ok(!f.calls.some((c) => c.url === API_URL));
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("handler: GET /status reports feed, state, and dispatch config", async () => {
  // Given: a recorded state.
  const kvs = mockKv();
  state(kvs, { version: "2.1.273", binaryUrl: ASSET_URL("2.1.273"), dispatched: true });
  const realFetch = globalThis.fetch;
  globalThis.fetch = mockFetch(baseRules());
  try {
    const res = await worker.fetch(request("/status"), { ...env, STATE: kvs });
    // When: queried. Then: feed (2.1.274), state (2.1.273), ref + workflow.
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.feed, "2.1.274");
    assert.equal(body.state.version, "2.1.273");
    assert.equal(body.branch, DEFAULTS.BRANCH);
    assert.equal(body.workflow, DEFAULTS.WORKFLOW);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("handler: POST /run with the right secret performs a forced check", async () => {
  // Given: a SECRET-protected worker, state already dispatched, and the
  // matching bearer token.
  const kvs = mockKv();
  state(kvs, { version: "2.1.274", binaryUrl: ASSET_URL("2.1.274"), dispatched: true });
  const f = mockFetch(baseRules());
  const realFetch = globalThis.fetch;
  globalThis.fetch = f;
  try {
    const res = await worker.fetch(
      request("/run?force=1", {
        method: "POST",
        headers: { authorization: "Bearer the-secret" },
      }),
      { ...env, SECRET: "the-secret", STATE: kvs },
    );
    // When: run with force. Then: dispatched again despite the recorded state.
    assert.equal(res.status, 200);
    assert.equal((await res.json()).action, "dispatched");
    assert.ok(f.calls.some((c) => c.url === API_URL));
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("handler: POST /run with a wrong secret is refused", async () => {
  // Given: a SECRET-protected worker and a token that does not match.
  const kvs = mockKv();
  const f = mockFetch(baseRules());
  const realFetch = globalThis.fetch;
  globalThis.fetch = f;
  try {
    const res = await worker.fetch(
      request("/run", { method: "POST", headers: { authorization: "Bearer nope" } }),
      { ...env, SECRET: "the-secret", STATE: kvs },
    );
    // When: run. Then: 401, and nothing was fetched or dispatched.
    assert.equal(res.status, 401);
    assert.equal(f.calls.length, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("handler: POST /reset clears the state", async () => {
  // Given: a recorded state, no SECRET set (routes are open).
  const kvs = mockKv();
  state(kvs, { version: "2.1.273", binaryUrl: ASSET_URL("2.1.273"), dispatched: true });
  const realFetch = globalThis.fetch;
  globalThis.fetch = mockFetch(baseRules());
  try {
    const res = await worker.fetch(request("/reset", { method: "POST" }), { ...env, STATE: kvs });
    // When: reset. Then: 200 and the state is gone.
    assert.equal(res.status, 200);
    assert.equal(await kvs.get(DEFAULTS.STATE_KEY), null);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("handler: unknown paths are 404", async () => {
  // Given: an unknown route.
  const kvs = mockKv();
  const res = await worker.fetch(request("/nope"), { ...env, STATE: kvs });
  // When: requested. Then: 404.
  assert.equal(res.status, 404);
});
