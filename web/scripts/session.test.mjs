import ts from "typescript";

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
function moduleFor(name, globals = {}) {
  const output = ts.transpileModule(fs.readFileSync(path.join(web, "src/lib", name + ".ts"), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const exports = {};
  vm.runInNewContext(output, { exports, ...globals });
  return exports;
}
const { sendWithSession, signOut, isCredentialPath } = moduleFor("session");

// browser fakes the parts of the browser the policy touches: the stored
// token, its removal and the redirect to /login. respond lists, per send, the
// status to answer and optionally a token another tab stores meanwhile.
function browser(stored, respond) {
  const b = {
    stored,
    sent: [],
    cleared: 0,
    redirects: 0,
    deps: {
      readToken: () => b.stored,
      clearToken: () => {
        b.cleared++;
        b.stored = null;
      },
      toLogin: () => {
        b.redirects++;
      },
    },
    send: async (token) => {
      b.sent.push(token);
      const next = respond.shift();
      assert.ok(next, `unexpected send #${b.sent.length}`);
      if ("store" in next) b.stored = next.store;
      return { status: next.status };
    },
  };
  return b;
}

test("a 401 from login or init is the caller's to show: no retry, no sign-out", async () => {
  for (const p of ["/auth/login", "/auth/init", "/auth/login?next=1"]) {
    const b = browser("tok-a", [{ status: 401, store: "tok-b" }]);
    const r = await sendWithSession(p, b.send, b.deps);
    assert.equal(r.status, 401);
    assert.deepEqual(b.sent, ["tok-a"]);
    assert.equal(b.cleared, 0);
    assert.equal(b.redirects, 0);
    assert.equal(b.stored, "tok-b");
  }
});

test("a 401 with the token still stored clears it and goes to /login", async () => {
  const b = browser("tok-a", [{ status: 401 }]);
  const r = await sendWithSession("/tasks", b.send, b.deps);
  assert.equal(r.status, 401);
  assert.deepEqual(b.sent, ["tok-a"]);
  assert.equal(b.cleared, 1);
  assert.equal(b.stored, null);
  assert.equal(b.redirects, 1);
});

test("a 401 after another tab stored a new token retries once with it", async () => {
  const b = browser("tok-a", [{ status: 401, store: "tok-b" }, { status: 200 }]);
  const r = await sendWithSession("/tasks", b.send, b.deps);
  assert.equal(r.status, 200);
  assert.deepEqual(b.sent, ["tok-a", "tok-b"]);
  assert.equal(b.cleared, 0);
  assert.equal(b.redirects, 0);
  assert.equal(b.stored, "tok-b");
});

test("the retry happens once: a second 401 signs out with the retried token", async () => {
  const b = browser("tok-a", [{ status: 401, store: "tok-b" }, { status: 401 }]);
  const r = await sendWithSession("/tasks", b.send, b.deps);
  assert.equal(r.status, 401);
  assert.deepEqual(b.sent, ["tok-a", "tok-b"]);
  assert.equal(b.cleared, 1);
  assert.equal(b.redirects, 1);
});

test("a token stored after the rejected one is never cleared", async () => {
  // The retry with tok-b is rejected while a third login stores tok-c.
  const b = browser("tok-a", [
    { status: 401, store: "tok-b" },
    { status: 401, store: "tok-c" },
  ]);
  await sendWithSession("/tasks", b.send, b.deps);
  assert.deepEqual(b.sent, ["tok-a", "tok-b"]);
  assert.equal(b.cleared, 0);
  assert.equal(b.stored, "tok-c");
  assert.equal(b.redirects, 1);

  const direct = browser("tok-new", []);
  signOut("tok-old", direct.deps);
  assert.equal(direct.cleared, 0);
  assert.equal(direct.stored, "tok-new");
  assert.equal(direct.redirects, 1);
});

test("a token removed meanwhile (sign-out in another tab) is not retried", async () => {
  for (const removed of [null, ""]) {
    const b = browser("tok-a", [{ status: 401, store: removed }]);
    await sendWithSession("/tasks", b.send, b.deps);
    assert.deepEqual(b.sent, ["tok-a"]);
    assert.equal(b.cleared, 0);
    assert.equal(b.redirects, 1);
  }
});

test("without a token a 401 goes to /login, and a token stored meanwhile is tried", async () => {
  const none = browser(null, [{ status: 401 }]);
  await sendWithSession("/tasks", none.send, none.deps);
  assert.deepEqual(none.sent, [null]);
  assert.equal(none.redirects, 1);

  const empty = browser("", [{ status: 401 }]);
  await sendWithSession("/tasks", empty.send, empty.deps);
  assert.deepEqual(empty.sent, [null]);
  assert.equal(empty.redirects, 1);

  const late = browser(null, [{ status: 401, store: "tok-b" }, { status: 200 }]);
  const r = await sendWithSession("/tasks", late.send, late.deps);
  assert.equal(r.status, 200);
  assert.deepEqual(late.sent, [null, "tok-b"]);
  assert.equal(late.redirects, 0);
});

test("503 and every other status never sign out", async () => {
  for (const status of [200, 204, 400, 403, 404, 429, 500, 502, 503]) {
    const b = browser("tok-a", [{ status, store: "tok-b" }]);
    const r = await sendWithSession("/tasks", b.send, b.deps);
    assert.equal(r.status, status);
    assert.deepEqual(b.sent, ["tok-a"]);
    assert.equal(b.cleared, 0);
    assert.equal(b.redirects, 0);
  }
});

test("only login and init are credential paths", () => {
  assert.equal(isCredentialPath("/auth/login"), true);
  assert.equal(isCredentialPath("/auth/init"), true);
  assert.equal(isCredentialPath("/auth/init?x=1"), true);
  for (const p of ["/auth/change-password", "/auth/status", "/auth/login/x", "/health", "/tasks", "auth/login"]) {
    assert.equal(isCredentialPath(p), false, p);
  }
});
