import assert from "node:assert/strict";
import { spawn } from "node:child_process";
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
