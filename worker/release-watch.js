// release-watch: a Cloudflare Worker that watches the claude-code release
// feed and, when a new version ships, dispatches the repository's
// bind-new-version workflow with that version and its binary URL. The
// workflow (on a runner) then downloads the build, binds it through the
// no-guess oracle binder, and commits the record into verified_sites.json.
//
// Plain JS, no build step: deploy from this directory with
//   npx wrangler deploy            (after wrangler kv namespace create STATE)
//   npx wrangler secret put GITHUB_TOKEN
// and test the pure logic locally with
//   node test_release_watch.mjs
//
// Env (set in wrangler.toml / dashboard):
//   GITHUB_REPO         owner/repo to dispatch into (default: the patcher repo)
//   BRANCH              ref the dispatch runs on (default: develop)
//   FEED_URL            atom feed to watch (default: claude-code releases.atom)
//   BINARY_URL_TEMPLATE release-asset URL template with a {version} placeholder
//   GITHUB_TOKEN        SECRET: a token with the `workflow` scope (required)
//   SECRET              optional bearer token protecting the manual routes
//
// No-guess invariants, same contract as the patcher:
//   - a release without a linux-x64 asset is NOT dispatched (HEAD 404);
//   - a feed that cannot be parsed is NOT dispatched;
//   - state (the last seen version) is written only after the dispatch
//     answer is known, so a failed dispatch is retried on the next tick and
//     an unmeasurable build (refused by the workflow) is not re-dispatched.

export const DEFAULTS = {
  FEED_URL: "https://github.com/anthropics/claude-code/releases.atom",
  BINARY_URL_TEMPLATE:
    "https://github.com/anthropics/claude-code/releases/download/v{version}/claude-linux-x64.tar.gz",
  GITHUB_REPO: "crazyrokr/claude-code-patcher",
  BRANCH: "develop",
  WORKFLOW: "bind-new-version.yml",
  STATE_KEY: "release-watch",
  GITHUB_API: "https://api.github.com",
};

export const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

const ENTITIES = {
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
  "&apos;": "'",
  "&amp;": "&",
};

export function decodeEntities(text) {
  // Numeric references first (&#48;, &#x30;), then the named set; an unknown
  // reference (or one outside the code-point range) is left as-is.
  return text
    .replace(/&#(\d+);/g, (m, n) => {
      const cp = Number(n);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    })
    .replace(/&#x([0-9a-fA-F]+);/g, (m, h) => {
      const cp = parseInt(h, 16);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    })
    .replace(/&(?:lt|gt|quot|#39|apos|amp);/g, (m) => ENTITIES[m] ?? m);
}

// The feed lists releases newest first; the first entry is the latest one.
// A title like `v2.1.274` becomes `2.1.274`; anything that is not a
// version is refused (null) rather than guessed.
export function latestVersionFromAtom(xml) {
  if (typeof xml !== "string") return null;
  const start = xml.indexOf("<entry>");
  const end = xml.indexOf("</entry>", start);
  if (start === -1 || end === -1) return null;
  const m = xml.slice(start, end).match(/<title[^>]*>([\s\S]*?)<\/title>/);
  if (!m) return null;
  const version = decodeEntities(m[1]).trim().replace(/^v/i, "");
  return SEMVER.test(version) ? version : null;
}

// The binary URL is a data input (template), not code: the exact asset
// Claude Code ships under is the one swappable detail, like CLAUDE_BINARY_URL.
export function binaryUrlFor(version, template) {
  if (typeof version !== "string" || !SEMVER.test(version)) return null;
  const t = template ?? DEFAULTS.BINARY_URL_TEMPLATE;
  return t.includes("{version}") ? t.replaceAll("{version}", version) : t;
}

export async function fetchLatestVersion(fetchImpl, feedUrl) {
  const res = await fetchImpl(feedUrl ?? DEFAULTS.FEED_URL, { method: "GET" });
  if (!res.ok) throw new Error(`feed HTTP ${res.status}`);
  const version = latestVersionFromAtom(await res.text());
  if (!version) throw new Error("feed has no parseable release entry");
  return version;
}

export async function assetAvailable(fetchImpl, url) {
  const res = await fetchImpl(url, { method: "HEAD" });
  return res.status < 400;
}

export async function dispatchWorkflow(fetchImpl, env, { version, binaryUrl }) {
  const repo = env.GITHUB_REPO ?? DEFAULTS.GITHUB_REPO;
  const res = await fetchImpl(`${DEFAULTS.GITHUB_API}/repos/${repo}/dispatches`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "claude-code-release-watcher",
      "X-GitHub-Api-Version": "2026-03-10",
      Authorization: `Bearer ${env.GITHUB_TOKEN ?? ""}`,
    },
    body: JSON.stringify({
      "event_type": "kick-off-patcher",
      "client_payload": { "version": version, "binary_url": binaryUrl },
    }),
  });
  if (res.status === 204) return { ok: true, status: 204 };
  const body = await res.text().catch(() => "");
  return { ok: false, status: res.status, body };
}

// One watch tick: read the feed, resolve the binary URL, check the asset
// exists, dispatch the workflow, and record what happened in KV. Every
// failure mode returns a reason instead of throwing; the cron handler logs
// it and the next tick (15 min later) simply runs again.
export async function runCheck({ env, kv, force = false, log = () => {}, fetch: f }) {
  const fImpl = f ?? globalThis.fetch;
  const key = DEFAULTS.STATE_KEY;
  const now = new Date().toISOString();

  let version;
  try {
    version = await fetchLatestVersion(fImpl, env.FEED_URL);
  } catch (err) {
    log(`feed error: ${err}`);
    return { action: "feed-error", error: String(err) };
  }

  const state = await kv.get(key, "json").catch(() => null);
  if (state && state.version === version && state.dispatched && !force) {
    log(`up-to-date: ${version} was already dispatched`);
    return { action: "up-to-date", version };
  }

  const binaryUrl = binaryUrlFor(version, env.BINARY_URL_TEMPLATE);
  if (!binaryUrl) {
    log(`refused: no binary URL for ${version}`);
    return { action: "refused", version, reason: "binary URL unresolved" };
  }

  let available;
  try {
    available = await assetAvailable(fImpl, binaryUrl);
  } catch (err) {
    log(`asset check error: ${err}`);
    return { action: "asset-check-error", version, error: String(err) };
  }
  if (!available) {
    // Not recorded: the asset may still be uploading; the next tick rechecks.
    log(`release ${version} has no asset at ${binaryUrl} yet - not dispatched`);
    return { action: "no-asset", version, binaryUrl };
  }

  const result = await dispatchWorkflow(fImpl, env, { version, binaryUrl })
    .catch((err) => ({ ok: false, status: 0, body: String(err) }));

  // Recorded either way: dispatched:true ends the watch for this version
  // (the workflow is idempotent - a rebind is a no-op); dispatched:false
  // retries the dispatch on the next tick until GitHub answers.
  await kv
    .put(key, JSON.stringify({ version, binaryUrl, dispatched: result.ok, at: now }))
    .catch((err) => log(`state write error: ${err}`));

  if (result.ok) {
    log(`dispatched ${DEFAULTS.WORKFLOW} on ${env.BRANCH ?? DEFAULTS.BRANCH} for ${version}`);
    return { action: "dispatched", version, binaryUrl };
  }
  log(`dispatch failed (HTTP ${result.status}): ${result.body}`);
  return { action: "dispatch-failed", version, status: result.status, body: result.body };
}

function jsonBody(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function authorized(request, env) {
  if (!env.SECRET) return true;
  return (request.headers.get("authorization") ?? "") === `Bearer ${env.SECRET}`;
}

export default {
  // Cron trigger: Cloudflare delivers a ScheduledEvent to this export (not an
  // HTTP request), so this is where the 15-minute tick runs. No response is
  // returned; the KV state (and `GET /status`) tells the story.
  async scheduled(event, env) {
    const result = await runCheck({
      env,
      kv: env.STATE,
      log: (line) => console.log(`[release-watch] cron: ${line}`),
    });
    console.log(`[release-watch] cron tick -> ${JSON.stringify(result)}`);
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const kv = env.STATE;
    const log = (line) => console.log(`[release-watch] ${line}`);

    if (url.pathname === "/status" && request.method === "GET") {
      const state = await kv.get(DEFAULTS.STATE_KEY, "json").catch(() => null);
      const feed = await fetchLatestVersion(globalThis.fetch, env.FEED_URL).catch(() => null);
      return jsonBody(200, {
        feed,
        state,
        repo: env.GITHUB_REPO ?? DEFAULTS.GITHUB_REPO,
        branch: env.BRANCH ?? DEFAULTS.BRANCH,
        workflow: DEFAULTS.WORKFLOW,
      });
    }

    if (!authorized(request, env)) {
      return jsonBody(401, { error: "unauthorized" });
    }

    if (url.pathname === "/run" && request.method === "POST") {
      const force = url.searchParams.get("force") === "1";
      const result = await runCheck({ env, kv, force, log });
      return jsonBody(result.action === "dispatch-failed" ? 502 : 200, result);
    }

    if (url.pathname === "/reset" && request.method === "POST") {
      await kv.delete(DEFAULTS.STATE_KEY);
      return jsonBody(200, { action: "reset" });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return jsonBody(200, {
        service: "claude-code release-watch",
        routes: ["GET /status", "POST /run[?force=1]", "POST /reset"],
      });
    }

    return jsonBody(404, { error: "not found" });
  },
};
