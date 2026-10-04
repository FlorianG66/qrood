import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let PORT;
let ORIGIN;

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      const port = typeof address === "object" && address ? address.port : 0;
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function browser() {
  return { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" };
}

function sessionCookie(response) {
  const setCookie = response.headers.getSetCookie?.()[0] || response.headers.get("set-cookie") || "";
  return setCookie.split(";", 1)[0];
}

// Le transport `outbox` écrit un fichier JSON par message. On lit le corps des
// fichiers, jamais leur nom : il ne contient ni adresse ni jeton.
async function waitForOutbox(directory, needle, timeoutMs = 3_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const files = readdirSync(directory).sort();
    for (let i = files.length - 1; i >= 0; i -= 1) {
      const raw = readFileSync(path.join(directory, files[i]), "utf8");
      if (raw.includes(needle)) return JSON.parse(raw);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`aucun courrier contenant « ${needle} » dans ${directory}`);
}

function tokenFromUrl(text, queryKey) {
  const match = text.match(new RegExp(`[?&]${queryKey}=([A-Za-z0-9_-]+)`));
  assert.ok(match, `l'e-mail doit contenir ${queryKey}`);
  return match[1];
}

async function errorCode(response) {
  return (await response.json()).error.code;
}

// Les deux aides ci-dessous rejouent l'algorithme du serveur plutôt que d'appeler
// une route d'activation : un test qui réutiliserait l'implémentation ne prouverait
// rien sur la compatibilité avec une vraie application d'authentification.
function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const character of base32.replace(/=+$/, "").toUpperCase()) {
    const index = alphabet.indexOf(character);
    assert.notEqual(index, -1, `caractère base32 inattendu : ${character}`);
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

function totpCodeFor(secret, at = Date.now()) {
  const counter = Math.floor(at / 1_000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", base32ToBytes(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}

function readTwoFactor(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    const row = database.prepare(`
      SELECT t.secret, t.confirmed_at, t.pending_secret, t.pending_expires_at, t.recovery_codes
      FROM two_factor_auth t JOIN users u ON u.id = t.user_id
      WHERE u.email = ?
    `).get(email);
    if (!row) return { enrolled: false, pending: false, recoveryCodes: 0 };
    return {
      enrolled: Boolean(row.secret && row.confirmed_at),
      pending: Boolean(row.pending_secret && row.pending_expires_at > Date.now()),
      recoveryCodes: JSON.parse(row.recovery_codes || "[]").length,
    };
  } finally {
    database.close();
  }
}

function countSessions(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare(`
      SELECT COUNT(*) AS c FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = ?
    `).get(email).c;
  } finally {
    database.close();
  }
}

async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.cookie) headers.set("Cookie", options.cookie);
  if (options.csrf) headers.set("X-CSRF-Token", options.csrf);
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  return fetch(url.startsWith("http") ? url : `${ORIGIN}${url}`, {
    ...options,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    redirect: "manual",
  });
}

async function waitForServer(child) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error("Le serveur de test s'est arrêté avant son démarrage.");
    try {
      const response = await request("/api/health");
      if (response.ok) return;
    } catch {
      // Le socket n'est pas encore prêt.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Délai de démarrage du serveur de test dépassé.");
}

function buildChildEnvironment(overrides = {}) {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.startsWith("QROOD_")) delete environment[key];
  }
  return Object.assign(environment, {
    QROOD_PORT: String(PORT),
    QROOD_HOST: "127.0.0.1",
    QROOD_PUBLIC_ORIGIN: ORIGIN,
    QROOD_IDLE_TIMEOUT_MINUTES: "5",
    NODE_ENV: "test",
  }, overrides);
}

async function startServer(environment, logSink) {
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: ROOT,
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => { logSink.value += chunk; });
  child.stderr.on("data", (chunk) => { logSink.value += chunk; });
  await waitForServer(child);
  return child;
}

async function stopServer(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    if (child.exitCode !== null) resolve();
    else child.once("exit", resolve);
  });
}

async function registerUser(email, password = "MotDePassePlan789") {
  const response = await request("/api/auth/register", {
    method: "POST",
    headers: browser(),
    body: { displayName: "Compte Plan", email, password },
  });
  assert.equal(response.status, 201, `l'inscription de ${email} doit aboutir`);
  const body = await response.json();
  return { cookie: sessionCookie(response), csrf: body.csrfToken, email, password };
}

test("gestion du compte : profil, adresse, mot de passe, export, suppression", async () => {
  PORT = await getFreePort();
  ORIGIN = `http://localhost:${PORT}`;
  const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "qrood-compte-"));
  const logSink = { value: "" };
  const databasePath = path.join(temporaryDirectory, "test.sqlite");
  const outbox = path.join(temporaryDirectory, "outbox");
  const server = await startServer(
    buildChildEnvironment({ QROOD_DB_PATH: databasePath, QROOD_MAIL_OUTBOX_DIR: outbox }),
    logSink,
  );

  try {
    // La page est servie publiquement : c'est le script, et non le fichier, qui
    // refuse d'afficher quoi que ce soit sans session.
    const page = await request("/compte");
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Mon compte/);
    assert.equal((await request("/compte.js")).status, 200);

    // Aucune route de compte ne répond sans session : ni lecture, ni écriture.
    for (const [method, path] of [
      ["PATCH", "/api/account/profile"],
      ["POST", "/api/account/email"],
      ["POST", "/api/account/email/confirm"],
      ["POST", "/api/account/password"],
      ["POST", "/api/account/export"],
      ["POST", "/api/account/delete"],
    ]) {
      const denied = await request(path, { method, headers: browser(), body: {} });
      assert.equal(denied.status, 401, `${method} ${path} doit exiger une session`);
    }

    const account = await registerUser("compte@exemple.test");

    // Le jeton CSRF est obligatoire, même avec une session valide.
    const withoutCsrf = await request("/api/account/profile", {
      method: "PATCH",
      headers: browser(),
      cookie: account.cookie,
      body: { displayName: "Nom usurpe" },
    });
    assert.equal(withoutCsrf.status, 403);

    // -- Profil ------------------------------------------------------------
    const renamed = await request("/api/account/profile", {
      method: "PATCH",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { displayName: "Camille Renard" },
    });
    assert.equal(renamed.status, 200);
    assert.equal((await renamed.json()).user.displayName, "Camille Renard");

    const tooShort = await request("/api/account/profile", {
      method: "PATCH",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { displayName: "x" },
    });
    assert.equal(tooShort.status, 400);
    assert.equal((await tooShort.json()).error.code, "invalid_name");

    // -- Adresse e-mail ----------------------------------------------------
    // Le mot de passe courant conditionne le changement : sans lui, un cookie
    // volé ne suffit pas à s'approprier le compte.
    const withoutPassword = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { email: "nouveau@exemple.test" },
    });
    assert.equal(withoutPassword.status, 400);
    assert.equal((await withoutPassword.json()).error.code, "current_password_required");

    const wrongPassword = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { email: "nouveau@exemple.test", currentPassword: "MauvaisMotDePasse1" },
    });
    assert.equal(wrongPassword.status, 403);
    assert.equal((await wrongPassword.json()).error.code, "invalid_current_password");

    const unchanged = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { email: account.email, currentPassword: account.password },
    });
    assert.equal(unchanged.status, 400);
    assert.equal((await unchanged.json()).error.code, "email_unchanged");

    const asked = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { email: "nouveau@exemple.test", currentPassword: account.password },
    });
    assert.equal(asked.status, 200);
    assert.equal((await asked.json()).pendingEmail, "nouveau@exemple.test");

    // Tant que le lien n'est pas ouvert, l'ancienne adresse reste la seule
    // valable : c'est elle qui reçoit la réinitialisation de mot de passe.
    const mail = await waitForOutbox(outbox, "confirmation-email");
    assert.equal(mail.purpose, "email_change");
    assert.equal(mail.to, "nouveau@exemple.test");
    const token = tokenFromUrl(mail.text, "confirmation-email");

    const beforeConfirm = await request("/api/auth/me", { cookie: account.cookie });
    const before = await beforeConfirm.json();
    assert.equal(before.user.email, account.email, "l'adresse ne change qu'après confirmation");
    assert.equal(before.user.pendingEmail, "nouveau@exemple.test");

    // L'export reflète l'attente en cours, sans jamais laisser fuir le mot de
    // passe ni le jeton.
    const pendingExport = await (await request("/api/account/export", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
    })).json();
    assert.equal(pendingExport.account.pendingEmail, "nouveau@exemple.test");
    assert.equal(pendingExport.account.password, undefined);
    assert.doesNotMatch(JSON.stringify(pendingExport), /MotDePassePlan789/);
    assert.doesNotMatch(JSON.stringify(pendingExport), new RegExp(token));

    // Un jeton vaut pour son seul titulaire. Leandy tiers ne doit ni le
    //confirmer ni — surtout — le brûler : le propriétaire doit pouvoir l'ouvrir
    // après coup, sinon n'importe quel lien égaré bloquerait le changement à jamais.
    const other = await registerUser("autre@exemple.test");
    const stolen = await request("/api/account/email/confirm", {
      method: "POST",
      headers: browser(),
      cookie: other.cookie,
      csrf: other.csrf,
      body: { token },
    });
    assert.equal(stolen.status, 400);
    assert.equal((await stolen.json()).error.code, "invalid_token");

    const confirmed = await request("/api/account/email/confirm", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { token },
    });
    assert.equal(confirmed.status, 200, "le jeton doit rester valable après l'échec d'un tiers");
    const confirmedUser = (await confirmed.json()).user;
    assert.equal(confirmedUser.email, "nouveau@exemple.test");
    assert.equal(confirmedUser.pendingEmail, null);

    const afterConfirm = await request("/api/auth/me", { cookie: account.cookie });
    const after = await afterConfirm.json();
    assert.equal(after.user.email, "nouveau@exemple.test");
    assert.equal(after.user.pendingEmail, null);

    // Le jeton est à usage unique : le rejouer échoue.
    const replay = await request("/api/account/email/confirm", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { token },
    });
    assert.equal(replay.status, 400);

    // L'adresse vient d'être confirmée : elle sert désormais à se reconnecter.
    // Cette seconde session du même compte sert de témoin pour la révocation.
    const relogin = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: "nouveau@exemple.test", password: account.password },
    });
    assert.equal(relogin.status, 200);
    const secondSession = sessionCookie(relogin);
    assert.notEqual(secondSession, account.cookie);

    // -- Mot de passe ------------------------------------------------------
    const samePassword = await request("/api/account/password", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { currentPassword: account.password, newPassword: account.password },
    });
    assert.equal(samePassword.status, 400);
    assert.equal((await samePassword.json()).error.code, "password_unchanged");

    const weakPassword = await request("/api/account/password", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { currentPassword: account.password, newPassword: "tropcourt1" },
    });
    assert.equal(weakPassword.status, 400);
    assert.equal((await weakPassword.json()).error.code, "invalid_password");

    const newPassword = "NouveauMotDePasse456";
    const changed = await request("/api/account/password", {
      method: "POST",
      headers: browser(),
      cookie: account.cookie,
      csrf: account.csrf,
      body: { currentPassword: account.password, newPassword },
    });
    assert.equal(changed.status, 200);

    // Les autres sessions du même compte tombent, mais pas celle qui a agi : à
    // défaut, l'écran en cours se retrouverait déconnecté et l'utilisateur
    // croirait s'être déconnecté lui-même. Les sessions d'un autre compte, elles,
    // n'ont rien à voir ici et doivent survivre.
    assert.equal((await (await request("/api/auth/me", { cookie: account.cookie })).json()).user.email,
      "nouveau@exemple.test");
    assert.equal((await (await request("/api/auth/me", { cookie: secondSession })).json()).user, null);
    assert.equal((await (await request("/api/auth/me", { cookie: other.cookie })).json()).user.email,
      "autre@exemple.test");

    const oldPassword = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: "nouveau@exemple.test", password: account.password },
    });
    assert.equal(oldPassword.status, 401);

    const withNewPassword = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: "nouveau@exemple.test", password: newPassword },
    });
    assert.equal(withNewPassword.status, 200);
    const reloginBody = await withNewPassword.json();
    const fresh = { cookie: sessionCookie(withNewPassword), csrf: reloginBody.csrfToken };

    // -- Export ------------------------------------------------------------
    const exported = await request("/api/account/export", {
      method: "POST",
      headers: browser(),
      cookie: fresh.cookie,
      csrf: fresh.csrf,
    });
    assert.equal(exported.status, 200);
    assert.match(exported.headers.get("content-disposition") || "", /attachment; filename="qrood-donnees-/);
    const dump = await exported.json();
    assert.equal(dump.account.email, "nouveau@exemple.test");
    assert.equal(dump.account.displayName, "Camille Renard");
    assert.equal(dump.account.password, undefined, "l'export ne doit jamais contenir le mot de passe");
    assert.ok(Array.isArray(dump.qrcodes));
    assert.ok(Array.isArray(dump.statistics));

    // -- Suppression -------------------------------------------------------
    // Un compte souscripteur ne peut pas partir avant la résiliation.
    const database = new DatabaseSync(databasePath);
    const target = database.prepare("SELECT id FROM users WHERE email = ?").get("nouveau@exemple.test");
    const timestamp = Date.now();
    database.prepare(`
      INSERT INTO subscriptions (
        user_id, plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id,
        current_period_end, cancel_at_period_end, grace_until, created_at, updated_at
      ) VALUES (?, 'pro', 'active', 'cus_test', 'sub_test', 'price_test_pro', ?, 0, NULL, ?, ?)
    `).run(target.id, timestamp + 86_400_000, timestamp, timestamp);
    database.close();

    const blocked = await request("/api/account/delete", {
      method: "POST",
      headers: browser(),
      cookie: fresh.cookie,
      csrf: fresh.csrf,
      body: { currentPassword: newPassword, confirmation: "SUPPRIMER" },
    });
    assert.equal(blocked.status, 409);
    assert.equal((await blocked.json()).error.code, "subscription_active");

    const canceled = new DatabaseSync(databasePath);
    canceled.prepare("UPDATE subscriptions SET status = 'canceled' WHERE user_id = ?").run(target.id);
    canceled.close();

    const noConfirmation = await request("/api/account/delete", {
      method: "POST",
      headers: browser(),
      cookie: fresh.cookie,
      csrf: fresh.csrf,
      body: { currentPassword: newPassword, confirmation: "supprimer" },
    });
    assert.equal(noConfirmation.status, 400);
    assert.equal((await noConfirmation.json()).error.code, "confirmation_required");

    const deleted = await request("/api/account/delete", {
      method: "POST",
      headers: browser(),
      cookie: fresh.cookie,
      csrf: fresh.csrf,
      body: { currentPassword: newPassword, confirmation: "SUPPRIMER" },
    });
    assert.equal(deleted.status, 200);
    assert.match((deleted.headers.getSetCookie?.()[0] || deleted.headers.get("set-cookie") || ""),
      /qrood_session=;/);

    assert.equal((await (await request("/api/auth/me", { cookie: fresh.cookie })).json()).user, null);

    const afterDelete = new DatabaseSync(databasePath);
    assert.equal(afterDelete.prepare("SELECT COUNT(*) AS c FROM users WHERE id = ?").get(target.id).c, 0);
    assert.equal(
      afterDelete.prepare("SELECT COUNT(*) AS c FROM sessions WHERE user_id = ?").get(target.id).c,
      0,
      "les sessions doivent partir en cascade",
    );
    assert.equal(
      afterDelete.prepare("SELECT COUNT(*) AS c FROM subscriptions WHERE user_id = ?").get(target.id).c,
      0,
      "l'abonnement doit partir en cascade",
    );
    afterDelete.close();

    // Ni mot de passe ni jeton ne doivent avoir atterri dans les journaux.
    assert.doesNotMatch(logSink.value, /MotDePassePlan789|NouveauMotDePasse456/);
    assert.doesNotMatch(logSink.value, new RegExp(token));
  } finally {
    await stopServer(server);
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test("le changement d'adresse refuse une adresse déjà prise", async () => {
  PORT = await getFreePort();
  ORIGIN = `http://localhost:${PORT}`;
  const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "qrood-compte-"));
  const logSink = { value: "" };
  const databasePath = path.join(temporaryDirectory, "test.sqlite");
  const outbox = path.join(temporaryDirectory, "outbox");
  const server = await startServer(
    buildChildEnvironment({ QROOD_DB_PATH: databasePath, QROOD_MAIL_OUTBOX_DIR: outbox }),
    logSink,
  );

  try {
    const first = await registerUser("premier@exemple.test");
    const second = await registerUser("second@exemple.test");

    // L'adresse d'un autre compte ne peut être ni visée ni confirmée.
    const taken = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: second.cookie,
      csrf: second.csrf,
      body: { email: "premier@exemple.test", currentPassword: second.password },
    });
    assert.equal(taken.status, 409);
    assert.equal((await taken.json()).error.code, "email_taken");

    // Deux comptes ne peuvent pas non plus viser la même adresse en attente.
    const asked = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: second.cookie,
      csrf: second.csrf,
      body: { email: "commune@exemple.test", currentPassword: second.password },
    });
    assert.equal(asked.status, 200);
    await waitForOutbox(outbox, "confirmation-email");

    const reserved = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: first.cookie,
      csrf: first.csrf,
      body: { email: "commune@exemple.test", currentPassword: first.password },
    });
    assert.equal(reserved.status, 409);

    // La comparaison ignore la casse : l'unicité de la colonne est NOCASE.
    const upperCase = await request("/api/account/email", {
      method: "POST",
      headers: browser(),
      cookie: first.cookie,
      csrf: first.csrf,
      body: { email: "COMMUNE@exemple.test", currentPassword: first.password },
    });
    assert.equal(upperCase.status, 409);

    // Le titre du message d'attente porte bien la bonne adresse, et celle-ci
    // reste celle du compte tant que le lien n'a pas été ouvert.
    assert.equal((await (await request("/api/auth/me", { cookie: second.cookie })).json()).user.email,
      "second@exemple.test");
  } finally {
    await stopServer(server);
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test("double authentification : elle protège la connexion et se pilote depuis le compte", async () => {
  PORT = await getFreePort();
  ORIGIN = `http://localhost:${PORT}`;
  const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "qrood-a2f-"));
  const logSink = { value: "" };
  const databasePath = path.join(temporaryDirectory, "test.sqlite");
  const outbox = path.join(temporaryDirectory, "outbox");
  const server = await startServer(
    buildChildEnvironment({ QROOD_DB_PATH: databasePath, QROOD_MAIL_OUTBOX_DIR: outbox }),
    logSink,
  );

  const twoFactor = (options) => request("/api/auth/2fa", options);
  const call = (path, body, cookie, csrf) =>
    request(`/api/auth/2fa${path}`, {
      method: "POST",
      headers: browser(),
      cookie,
      csrf,
      body,
    });

  try {
    // ── Aucune route de second facteur ne répond sans session ────────────────
    for (const [method, path] of [
      ["GET", "/api/auth/2fa"],
      ["POST", "/api/auth/2fa/setup"],
      ["POST", "/api/auth/2fa/confirm"],
      ["POST", "/api/auth/2fa/recovery-codes"],
      ["POST", "/api/auth/2fa/disable"],
    ]) {
      const denied = await request(path, { method, headers: browser(), body: method === "POST" ? {} : undefined });
      assert.equal(denied.status, 401, `${method} ${path} doit exiger une session`);
    }

    const account = await registerUser("a2f@exemple.test");

    // ── Activation ───────────────────────────────────────────────────────────
    const initial = await (await twoFactor({ cookie: account.cookie })).json();
    assert.equal(initial.enrolled, false);
    assert.equal(initial.recoveryCodesRemaining, 0);
    assert.equal(initial.setupPending, false);

    // Le jeton CSRF reste obligatoire : une session seule ne suffit pas à écrire.
    const withoutCsrf = await call("/setup", { currentPassword: account.password }, account.cookie, undefined);
    assert.equal(withoutCsrf.status, 403);

    // Sur une session volée, le mot de passe est le seul facteur restant connu de la
    // victime : le poser sans lui reviendrait à lui céder le compte.
    const withoutPassword = await call("/setup", {}, account.cookie, account.csrf);
    assert.equal(withoutPassword.status, 400);
    assert.equal(await errorCode(withoutPassword), "current_password_required");

    const wrongPassword = await call("/setup", { currentPassword: "MauvaisMotDePasse1" }, account.cookie, account.csrf);
    assert.equal(wrongPassword.status, 403);
    assert.equal(await errorCode(wrongPassword), "invalid_current_password");

    const setup = await call("/setup", { currentPassword: account.password }, account.cookie, account.csrf);
    assert.equal(setup.status, 200, logSink.value);
    const { secret, uri } = await setup.json();
    assert.match(secret, /^[A-Z2-7]{32}$/, "le secret est base32, comme l'attend le standard");
    assert.ok(uri.startsWith("otpauth://totp/"), `URI inattendue : ${uri}`);
    assert.ok(uri.includes(`secret=${secret}`), "le QR code doit porter le secret présenté");

    // Tant que le code n'est pas confirmé, le secret n'est pas actif : c'est ce qui
    // empêche un secret jeté au hasard de fermer l'accès au compte.
    const pending = readTwoFactor(databasePath, account.email);
    assert.equal(pending.enrolled, false);
    assert.equal(pending.pending, true);
    assert.equal((await (await twoFactor({ cookie: account.cookie })).json()).setupPending, true);

    // Une connexion réussit encore : l'activation commencée n'a pas changé l'état.
    const stillReachable = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password },
    });
    assert.equal(stillReachable.status, 200, "un secret non confirmé ne doit rien changer à la connexion");

    const wrongConfirm = await call("/confirm", { code: "000000" }, account.cookie, account.csrf);
    assert.equal(wrongConfirm.status, 403);
    assert.equal(await errorCode(wrongConfirm), "invalid_two_factor_code");

    const confirmed = await call("/confirm", { code: totpCodeFor(secret) }, account.cookie, account.csrf);
    assert.equal(confirmed.status, 200, logSink.value);
    const recoveryCodes = (await confirmed.json()).recoveryCodes;
    assert.equal(recoveryCodes.length, 8);
    assert.equal(new Set(recoveryCodes).size, 8, "chaque code de récupération est unique");
    assert.ok(recoveryCodes.every((code) => /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code)), recoveryCodes.join(" "));
    // Les codes ne vivent qu'hachés : une copie de la base ne donne rien.
    assert.equal(readTwoFactor(databasePath, account.email).recoveryCodes, 8);

    const afterConfirm = await (await twoFactor({ cookie: account.cookie })).json();
    assert.equal(afterConfirm.enrolled, true);
    assert.equal(afterConfirm.recoveryCodesRemaining, 8);
    assert.equal(afterConfirm.setupPending, false);
    assert.ok(afterConfirm.confirmedAt);

    // ── Le mot de passe seul ne suffit plus à entrer ─────────────────────────
    const sessionsBefore = countSessions(databasePath, account.email);
    const passwordOnly = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password },
    });
    assert.equal(passwordOnly.status, 401);
    assert.equal(await errorCode(passwordOnly), "two_factor_required");
    assert.equal(
      countSessions(databasePath, account.email),
      sessionsBefore,
      "aucune session ne doit être créée avant la validation du second facteur",
    );
    assert.equal(
      (await (await request("/api/auth/me", { cookie: sessionCookie(passwordOnly) })).json()).user,
      null,
      "et aucun cookie ne doit être renvoyé",
    );

    // Un code erroné se distingue du code absent par un seul mot : l'interface doit
    // savoir s'il a à afficher le champ de saisie ou à refuser la tentative.
    const wrongCode = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password, twoFactorCode: "000000" },
    });
    assert.equal(wrongCode.status, 401);
    assert.equal(await errorCode(wrongCode), "invalid_two_factor_code");

    // ── Le code de l'application ────────────────────────────────────────────
    const liveCode = totpCodeFor(secret);
    const withCode = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password, twoFactorCode: liveCode },
    });
    assert.equal(withCode.status, 200, logSink.value);
    const reconnected = { cookie: sessionCookie(withCode), csrf: (await withCode.clone().json()).csrfToken };

    // Le même code, une seconde fois : la fenêtre de tolérance (±30 s) le rendrait
    // encore valable sans le compteur mémorisé.
    const replayed = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password, twoFactorCode: liveCode },
    });
    assert.equal(replayed.status, 401);
    assert.equal(await errorCode(replayed), "invalid_two_factor_code");

    // ── Un code de récupération, une seule fois ─────────────────────────────
    const recovery = recoveryCodes[0];
    const withRecovery = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password, twoFactorCode: recovery },
    });
    assert.equal(withRecovery.status, 200, logSink.value);
    assert.equal(readTwoFactor(databasePath, account.email).recoveryCodes, 7);

    const reusedRecovery = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password, twoFactorCode: recovery },
    });
    assert.equal(reusedRecovery.status, 401);
    assert.equal(await errorCode(reusedRecovery), "invalid_two_factor_code");

    // ── Régénération : mot de passe puis second facteur, jamais l'inverse ────
    const regeneratePasswordOnly = await call("/recovery-codes", { currentPassword: account.password },
      reconnected.cookie, reconnected.csrf);
    assert.equal(regeneratePasswordOnly.status, 403);
    assert.equal(await errorCode(regeneratePasswordOnly), "two_factor_required");

    const wrongRegenerateCode = await call("/recovery-codes",
      { currentPassword: account.password, twoFactorCode: "000000" }, reconnected.cookie, reconnected.csrf);
    assert.equal(wrongRegenerateCode.status, 403);
    assert.equal(await errorCode(wrongRegenerateCode), "invalid_two_factor_code");

    const regenerated = await call("/recovery-codes",
      { currentPassword: account.password, twoFactorCode: recoveryCodes[1] }, reconnected.cookie, reconnected.csrf);
    assert.equal(regenerated.status, 200, logSink.value);
    const freshCodes = (await regenerated.json()).recoveryCodes;
    assert.equal(freshCodes.length, 8);
    // Les anciens tombent avec la régénération : c'est tout son objet, sinon un code
    // déjà dérobé continuerait de servir après que l'utilisateur a réagi.
    assert.ok(!freshCodes.includes(recovery), "un code déjà consommé ne doit pas revenir");
    assert.equal(readTwoFactor(databasePath, account.email).recoveryCodes, 8);

    // ── La session d'origine survit à la désactivation d'un facteur ──────────
    const withoutFactor = await call("/disable", { currentPassword: account.password },
      reconnected.cookie, reconnected.csrf);
    assert.equal(withoutFactor.status, 403);
    assert.equal(await errorCode(withoutFactor), "two_factor_required");

    // Le téléphone est perdu : c'est le cas d'usage des codes de récupération. Le
    // mot de passe seul ne désactive rien, et un code déjà consommé plus haut non plus.
    const staleCode = await call("/disable",
      { currentPassword: account.password, twoFactorCode: recovery }, reconnected.cookie, reconnected.csrf);
    assert.equal(staleCode.status, 403);
    assert.equal(await errorCode(staleCode), "invalid_two_factor_code");

    const disabled = await call("/disable",
      { currentPassword: account.password, twoFactorCode: freshCodes[0] }, reconnected.cookie, reconnected.csrf);
    assert.equal(disabled.status, 200, logSink.value);
    assert.equal(readTwoFactor(databasePath, account.email).enrolled, false);
    assert.equal((await (await twoFactor({ cookie: reconnected.cookie })).json()).enrolled, false);

    // Le repli revient : sans second facteur, le mot de passe suffit de nouveau.
    const backToPassword = await request("/api/auth/login", {
      method: "POST",
      headers: browser(),
      body: { email: account.email, password: account.password },
    });
    assert.equal(backToPassword.status, 200);

    // Désactiver deux fois n'est pas une erreur utile : la seconde n'a plus rien à
    // protéger et doit le dire clairement plutôt que d'échouer sur un secret absent.
    const alreadyDisabled = await call("/disable",
      { currentPassword: account.password, twoFactorCode: "000000" }, reconnected.cookie, reconnected.csrf);
    assert.equal(alreadyDisabled.status, 409);
    assert.equal(await errorCode(alreadyDisabled), "two_factor_not_enrolled");

    // Ni mot de passe ni code ne doivent avoir atterri dans les journaux.
    assert.doesNotMatch(logSink.value, /MotDePassePlan789/);
    assert.ok(!logSink.value.includes(secret), "le secret d'authentification ne doit jamais être journalisé");
  } finally {
    await stopServer(server);
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});
