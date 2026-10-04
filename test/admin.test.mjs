import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";

// La seule adresse qui peut porter le rôle, exactement comme
// `enforceUniqueSuperAdmin` l'écrit dans le serveur. Les tests l'utilisent telle
// quelle, dans une base jetable : vérifier la politique réelle plutôt qu'un double
// de test, sinon le test passerait aussi bien sur une politique qui n'existe plus.
const SUPER_ADMIN_EMAIL = "florian.guichard66@gmail.com";
const PASSWORD = "MotDePasseBackOffice789";
// Le secret du compte avant la généralisation : le test de migration en a besoin,
// et le graver ici évite de le laisser se déduire de la ligne SQL qui l'insère.
const LEGACY_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
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
      probe.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function sessionCookie(response) {
  const setCookie = response.headers.getSetCookie?.()[0] || response.headers.get("set-cookie") || "";
  return setCookie.split(";", 1)[0];
}

// `Origin` et `Sec-Fetch-Site` sont posés ici, et non capturés à l'inscription :
// la politique du rôle se vérifie au redémarrage, donc le serveur change de port en
// cours de route. Un en-tête figé au moment de l'inscription porterait l'ancienne
// origine et chaque écriture se ferait refuser pour `invalid_origin`.
async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Origin", ORIGIN);
  headers.set("Sec-Fetch-Site", "same-origin");
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
    if (hasExited(child)) throw new Error("Le serveur de test s’est arrêté avant son démarrage.");
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

// Sous Windows, un processus tué par un signal renseigne `signalCode` et laisse
// `exitCode` à `null`. Tester le seul `exitCode` ferait croire que le serveur
// tourne encore : le second `stopServer` repartirait sur un `once("exit")` d'un
// événement déjà émis, et le test expirerait sans jamais rien signaler.
function hasExited(child) {
  return !child || child.exitCode !== null || child.signalCode !== null;
}

async function stopServer(child) {
  if (hasExited(child)) return;
  // L'écoute est posée avant le signal : sans cela un arrêt survenu entre les deux
  // laisserait la promesse sans jamais être résolue.
  await new Promise((resolve) => {
    child.once("exit", resolve);
    child.kill("SIGTERM");
  });
}

// L'exigence de vérification n'est pas l'objet de ces tests : le compte est
// confirmé en base, sur le modèle de `verifyEmail` dans `api.test.mjs`.
function verifyEmail(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    database.exec("PRAGMA busy_timeout = 5000;");
    const user = database.prepare("SELECT id FROM users WHERE email = ?").get(email);
    assert.ok(user, `le compte ${email} doit exister avant d’être confirmé`);
    database.prepare("UPDATE users SET email_verified_at = ? WHERE id = ?").run(Date.now(), user.id);
    return user.id;
  } finally {
    database.close();
  }
}

function readUser(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare("SELECT id, email, email_verified_at, is_super_admin FROM users WHERE email = ?").get(email);
  } finally {
    database.close();
  }
}

// Écrit le rôle en base, comme le ferait une reprise de données ou une promotion
// manuelle : c'est le seul moyen de fabriquer un second porteur du rôle, puisque le
// serveur refuse de le créer tout seul.
function setSuperAdmin(databasePath, email, value) {
  const database = new DatabaseSync(databasePath);
  try {
    database.exec("PRAGMA busy_timeout = 5000;");
    const result = database.prepare("UPDATE users SET is_super_admin = ? WHERE email = ?").run(value ? 1 : 0, email);
    assert.equal(result.changes, 1, `le compte ${email} doit exister avant d’être promu`);
  } finally {
    database.close();
  }
}

// Insère un abonnement en base, sans passer par Stripe : le back-office lit l'état
// de la base, il faut donc pouvoir lui en donner un.
function grantSubscription(databasePath, email, { plan = "pro", status = "active", graceUntil = null } = {}) {
  const database = new DatabaseSync(databasePath);
  try {
    database.exec("PRAGMA busy_timeout = 5000;");
    const user = database.prepare("SELECT id FROM users WHERE email = ?").get(email);
    assert.ok(user, `le compte ${email} doit exister avant de porter un abonnement`);
    const timestamp = Date.now();
    database.prepare(`
      INSERT INTO subscriptions (
        user_id, plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id,
        current_period_end, cancel_at_period_end, grace_until, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
    `).run(
      user.id,
      plan,
      status,
      `cus_test_${user.id}`,
      `sub_test_${user.id}`,
      `price_test_${plan}`,
      timestamp - 24 * 3_600 * 1_000,
      graceUntil,
      timestamp,
      timestamp,
    );
  } finally {
    database.close();
  }
}

function readSubscription(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare(
      "SELECT plan, status, grace_until FROM subscriptions WHERE user_id = (SELECT id FROM users WHERE email = ?) ORDER BY updated_at DESC LIMIT 1",
    ).get(email);
  } finally {
    database.close();
  }
}

function countSubscriptions(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare(
      "SELECT COUNT(*) AS n FROM subscriptions WHERE user_id = (SELECT id FROM users WHERE email = ?)",
    ).get(email).n;
  } finally {
    database.close();
  }
}

// Recule l'échéance d'une ligne d'abonnement : le temps n'est pas injectable depuis
// les tests, alors on déplace la date que le serveur va lire.
function expireSubscription(databasePath, email, { days = 1, cancelAtPeriodEnd = null } = {}) {
  const database = new DatabaseSync(databasePath);
  try {
    database.exec("PRAGMA busy_timeout = 5000;");
    const user = database.prepare("SELECT id FROM users WHERE email = ?").get(email);
    const past = Date.now() - days * 24 * 3_600 * 1_000;
    // L'ordre suit l'ordre des `?` de la requête : échéance, puis arrêt éventuel.
    const stop = cancelAtPeriodEnd === null ? "" : ", cancel_at_period_end = ?";
    const params = cancelAtPeriodEnd === null ? [past, user.id] : [past, cancelAtPeriodEnd ? 1 : 0, user.id];
    database
      .prepare(`
        UPDATE subscriptions SET current_period_end = ?${stop} WHERE user_id = ?
      `)
      .run(...params);
  } finally {
    database.close();
  }
}

// Ajoute une ligne d'abonnement terminée, comme en laisse une résiliation Stripe.
// L'index unique n'interdit qu'une seule ligne non terminale par compte : un
// historique de lignes terminées est donc possible et normal.
function addTerminalSubscription(databasePath, email, { plan = "pro", periodEnd = null } = {}) {
  const database = new DatabaseSync(databasePath);
  try {
    database.exec("PRAGMA busy_timeout = 5000;");
    const user = database.prepare("SELECT id FROM users WHERE email = ?").get(email);
    const timestamp = Date.now();
    database.prepare(`
      INSERT INTO subscriptions (
        user_id, plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id,
        current_period_end, cancel_at_period_end, grace_until, created_at, updated_at
      ) VALUES (?, ?, 'canceled', ?, ?, ?, ?, 1, NULL, ?, ?)
    `).run(
      user.id,
      plan,
      `cus_historique_${user.id}`,
      `sub_historique_${user.id}_${timestamp}`,
      `price_historique_${plan}`,
      periodEnd ?? timestamp - 30 * 24 * 3_600 * 1_000,
      timestamp,
      timestamp,
    );
  } finally {
    database.close();
  }
}

function readPlans(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database
      .prepare("SELECT plan, status FROM subscriptions WHERE user_id = (SELECT id FROM users WHERE email = ?)")
      .all(email);
  } finally {
    database.close();
  }
}

function readPeriodEnd(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare(
      `SELECT current_period_end FROM subscriptions
        WHERE user_id = (SELECT id FROM users WHERE email = ?)
        ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1`,
    ).get(email).current_period_end;
  } finally {
    database.close();
  }
}

function countSessions(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare(
      "SELECT COUNT(*) AS n FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)",
    ).get(email).n;
  } finally {
    database.close();
  }
}

function readQrcodeRow(databasePath, qrcodeId) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare("SELECT id, user_id, is_active FROM qrcodes WHERE id = ?").get(qrcodeId);
  } finally {
    database.close();
  }
}

function readAuditRows(databasePath, columns = null) {
  const database = new DatabaseSync(databasePath);
  try {
    // `metadata` n'est pas relu par défaut : les tests qui comparent la forme des
    // lignes ne doivent pas voir une colonne de plus.
    const selected = columns
      ? "actor_email, target_email, action, reason, metadata"
      : "actor_email, target_email, action, reason";
    return database.prepare(`SELECT ${selected} FROM admin_actions ORDER BY id`).all();
  } finally {
    database.close();
  }
}

function errorCode(response) {
  return response.json().then((body) => body.error.code);
}

async function register(email) {
  const response = await request("/api/auth/register", {
    method: "POST",
    body: { displayName: email.split("@")[0], email, password: PASSWORD },
  });
  assert.equal(response.status, 201, `l'inscription de ${email} doit aboutir`);
  const body = await response.json();
  return { email, cookie: sessionCookie(response), csrf: body.csrfToken };
}

async function login(email, password = PASSWORD) {
  const response = await request("/api/auth/login", {
    method: "POST",
    body: { email, password },
  });
  assert.equal(response.status, 200, `la connexion de ${email} doit aboutir`);
  const body = await response.json();
  return { cookie: sessionCookie(response), csrf: body.csrfToken };
}

// Un compte du back-office prêt à l'emploi : la page `/back-office` est publique et
// ne rend aucune donnée, donc elle se sert sans session — mais toutes ses données
// passent par `/api/admin/*`, qui relit le rôle en base à chaque requête.
async function bootBackOffice() {
  PORT = await getFreePort();
  ORIGIN = `http://localhost:${PORT}`;
  const directory = mkdtempSync(path.join(os.tmpdir(), "qrood-admin-test-"));
  const databasePath = path.join(directory, "test.sqlite");
  const logSink = { value: "" };
  let server = await startServer(buildChildEnvironment({ QROOD_DB_PATH: databasePath }), logSink);

  // La politique du rôle est appliquée au démarrage : le compte designated est
  // promu, tout autre porteur est rétrogradé. Il faut donc un redémarrage pour que
  // la session obtenue à l'inscription devienne celle d'un super-admin.
  const owner = await register(SUPER_ADMIN_EMAIL);
  const client = await register("client@example.test");
  verifyEmail(databasePath, SUPER_ADMIN_EMAIL);
  verifyEmail(databasePath, client.email);

  const restart = async () => {
    // L'ancien serveur est arrêté avant le nouveau : sans cela il garde le fichier
    // SQLite ouvert, le dossier temporaire devient impossible à supprimer sous
    // Windows, et le processus fantôme survit à la fin du fichier de tests.
    await stopServer(server);
    // Un nouveau port à chaque redémarrage : sur Windows, réutiliser celui qu'on
    // vient de libérer peut échouer sur EADDRINUSE. Le cookie est posé sur
    // `localhost` sans port, il survit donc au changement.
    PORT = await getFreePort();
    ORIGIN = `http://localhost:${PORT}`;
    server = await startServer(buildChildEnvironment({ QROOD_DB_PATH: databasePath }), logSink);
    return server;
  };

  server = await restart();

  // Arrêter le serveur sans supprimer la base : c'est ce qu'exige un test de
  // migration, qui doit écrire le fichier entre deux démarrages. `stop` reste le
  // geste de fin, celui qui nettoie le dossier temporaire.
  const halt = async () => {
    await stopServer(server);
  };

  const stop = async () => {
    await stopServer(server);
    rmSync(directory, { recursive: true, force: true });
  };

  return { databasePath, directory, logSink, owner, client, restart, halt, stop };
}

test("le back-office est servi sans session, ses données jamais", async () => {
  const harness = await bootBackOffice();
  const { client, logSink } = harness;

  try {
    // La page ne contient aucun compte : la masquer ici ne sécuriserait rien et
    // ferait dépendre l'affichage d'une variable d'environnement.
    const page = await request("/back-office");
    assert.equal(page.status, 200, logSink.value);
    assert.match(page.headers.get("content-security-policy"), /default-src 'self'/);
    assert.doesNotMatch(await page.text(), /client@example\.test/);

    const anonymous = await request("/api/admin/users");
    assert.equal(anonymous.status, 401);

    const refused = await request("/api/admin/users", { cookie: client.cookie });
    assert.equal(refused.status, 403, logSink.value);
    assert.equal(await errorCode(refused), "super_admin_required");

    // Un compte sans rôle ne doit même pas pouvoir énumérer les routes : le 403
    // arrive avant le 404.
    const unknown = await request("/api/admin/quelque-chose", { cookie: client.cookie });
    assert.equal(unknown.status, 403);
    assert.equal(await errorCode(unknown), "super_admin_required");
  } finally {
    await harness.stop();
  }
});

test("la politique de rôle tient au démarrage : un seul super-admin, sans usurpation", async () => {
  const harness = await bootBackOffice();
  const { databasePath, client, logSink } = harness;

  try {
    const promoted = readUser(databasePath, SUPER_ADMIN_EMAIL);
    assert.equal(promoted.is_super_admin, 1, "le compte designated doit être promu au démarrage");
    assert.equal(readUser(databasePath, client.email).is_super_admin, 0);

    const asOwner = await request("/api/auth/me", { cookie: harness.owner.cookie });
    assert.equal((await asOwner.json()).user.isSuperAdmin, true);
    const asClient = await request("/api/auth/me", { cookie: client.cookie });
    assert.equal((await asClient.json()).user.isSuperAdmin, false);

    // Une promotion écrite à la main, sans passer par le serveur : le redémarrage
    // doit la défaire. C'est le test de l'absence d'usurpation.
    setSuperAdmin(databasePath, client.email, true);
    assert.equal(readUser(databasePath, client.email).is_super_admin, 1);
    await harness.restart();
    assert.equal(readUser(databasePath, client.email).is_super_admin, 0, "un second super-admin doit être rétrogradé");
    assert.equal(readUser(databasePath, SUPER_ADMIN_EMAIL).is_super_admin, 1);

    // Rétrogradé en base, il perd l'accès immédiatement : le rôle est relu à chaque
    // requête et non mis en cache dans la session.
    const afterDemotion = await request("/api/admin/users", { cookie: client.cookie });
    assert.equal(afterDemotion.status, 403, logSink.value);
    assert.equal(await errorCode(afterDemotion), "super_admin_required");
  } finally {
    await harness.stop();
  }
});

test("le super-admin a Ultra de droit, sans abonnement et sans passer par Stripe", async () => {
  const harness = await bootBackOffice();
  const { owner, client, databasePath, logSink } = harness;

  try {
    const me = await request("/api/auth/me", { cookie: owner.cookie });
    const { entitlement } = await me.json();
    assert.equal(entitlement.plan, "ultra", logSink.value);
    // La page « Mon compte » nomme l'offre avec ce libellé, pas avec le plan stocké
    // en base : sans lui, elle afficherait « Découverte » sous des quotas illimités.
    assert.equal(entitlement.label, "Ultra");
    assert.equal(entitlement.maxQrcodes, null, "le quota de QR codes doit être illimité");
    assert.equal(entitlement.maxActive, null, "le quota d'actifs doit être illimité");
    assert.equal(entitlement.statsDays, 730);
    assert.equal(entitlement.features.logo, true);
    assert.ok(entitlement.features.moduleShapes.includes("dot"));
    assert.ok(entitlement.features.eyeShapes.includes("leaf"));

    // Aucun abonnement n'existe pour ce compte : l'avantage ne doit pas en dépendre.
    assert.equal(readSubscription(databasePath, SUPER_ADMIN_EMAIL), undefined);
    // Le résumé de facturation reste donc vide : pas de client Stripe, pas de
    // statut. C'est ce que lit la page « Mon compte », et c'est pourquoi elle doit
    // afficher l'offre effective plutôt que ce résumé pour nommer l'offre.
    const billing = (await (await request("/api/auth/me", { cookie: owner.cookie })).json()).subscription;
    assert.equal(billing.hasBillingAccount, false);
    assert.equal(billing.status, null);
    assert.equal(billing.currentPeriodEnd, null);

    // Les options Ultra sont réellement acceptées, sans les payer.
    const ultraPayload = {
      name: "QR ultra",
      mode: "link",
      destination: "https://example.test/ultra",
      style: {
        moduleShape: "dot",
        eyeShape: "leaf",
        margin: 2,
        logoSizePct: 28,
        gradient: { from: "#101b33", to: "#bd3c34", angle: 45 },
      },
      logo: `data:image/png;base64,${Buffer.from(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
        "base64",
      ).toString("base64")}`,
    };
    const created = await request("/api/qrcodes", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: ultraPayload,
    });
    assert.equal(created.status, 201, logSink.value);
    const qrcode = (await created.json()).qrcode;
    assert.equal(qrcode.style.moduleShape, "dot");
    assert.equal(qrcode.style.eyeShape, "leaf");
    assert.equal(qrcode.statsDays, 730);

    // Le quota d'actifs ne bloque pas : plusieurs QR codes actifs simultanés.
    for (const index of [1, 2]) {
      const extra = await request("/api/qrcodes", {
        method: "POST",
        cookie: owner.cookie,
        csrf: owner.csrf,
        body: { name: `QR ${index}`, mode: "link", destination: `https://example.test/ultra-${index}` },
      });
      assert.equal(extra.status, 201, "aucun quota ne doit s'appliquer au super-admin");
    }

    // Le même contenu est refusé à un compte Découverte : la différence ne vient
    // donc pas d'un contournement du back-office, mais de l'offre effective.
    const refused = await request("/api/qrcodes", {
      method: "POST",
      cookie: client.cookie,
      csrf: client.csrf,
      body: ultraPayload,
    });
    assert.equal(refused.status, 402);
    assert.equal(await errorCode(refused), "plan_upgrade_required");
  } finally {
    await harness.stop();
  }
});

test("la liste et le détail n'exposent ni secret ni donnée personnelle", async () => {
  const harness = await bootBackOffice();
  const { owner, client, logSink } = harness;

  try {
    const list = await request("/api/admin/users", { cookie: owner.cookie });
    assert.equal(list.status, 200, logSink.value);
    const body = await list.json();
    assert.equal(body.total, 2);
    assert.ok(body.users.length >= 2);

    for (const entry of body.users) {
      assert.deepEqual(
        Object.keys(entry).sort(),
        [
          "activeCount", "createdAt", "displayName", "email", "emailVerified",
          "id", "isSuperAdmin", "plan", "qrcodeCount", "sessionCount", "status",
        ].sort(),
        "la forme de la liste est stable : une colonne ajoutée par oubli apparaîtrait ici",
      );
    }
    // `password_hash`, `contact_data` et `vcard` n'apparaissent nulle part : ni en
    // valeur, ni en clé.
    const serialized = JSON.stringify(body);
    for (const forbidden of ["password_hash", "passwordHash", "contact_data", "contactData", "vcard"]) {
      assert.equal(serialized.includes(forbidden), false, `${forbidden} ne doit jamais sortir du back-office`);
    }

    const rows = body.users;
    const ownerRow = rows.find((entry) => entry.email === SUPER_ADMIN_EMAIL);
    const clientRow = rows.find((entry) => entry.email === client.email);
    assert.equal(ownerRow.isSuperAdmin, true);
    assert.equal(clientRow.isSuperAdmin, false);
    // L'offre affichée est l'offre effective : Ultra pour le rôle, Découverte pour
    // l'autre. C'est la même règle que celle de la page du compte.
    assert.equal(ownerRow.plan, "ultra");
    assert.equal(clientRow.plan, "decouverte");

    // La recherche filtre, et les jokers de `LIKE` sont échappés.
    const filtered = await request("/api/admin/users?search=client", { cookie: owner.cookie });
    const filteredBody = await filtered.json();
    assert.equal(filteredBody.total, 1);
    assert.equal(filteredBody.users[0].email, client.email);

    const wildcard = await request("/api/admin/users?search=100%25", { cookie: owner.cookie });
    assert.equal((await wildcard.json()).total, 0, "« 100% » doit être cherché littéralement");

    const paginated = await request("/api/admin/users?limit=1&offset=0", { cookie: owner.cookie });
    const page = await paginated.json();
    assert.equal(page.users.length, 1);
    assert.equal(page.limit, 1);

    const detail = await request(`/api/admin/users/${clientRow.id}`, { cookie: owner.cookie });
    assert.equal(detail.status, 200, logSink.value);
    const detailBody = await detail.json();
    assert.equal(detailBody.user.email, client.email);
    assert.equal(detailBody.entitlement.plan, "decouverte");
    assert.ok(Array.isArray(detailBody.qrcodes));
    assert.equal(JSON.stringify(detailBody).includes("vcard"), false);

    const missing = await request("/api/admin/users/999999", { cookie: owner.cookie });
    assert.equal(missing.status, 404);
    assert.equal(await errorCode(missing), "user_not_found");
  } finally {
    await harness.stop();
  }
});

test("toute écriture exige le rôle, le CSRF et une raison", async () => {
  const harness = await bootBackOffice();
  const { owner, client, databasePath, logSink } = harness;

  try {
    const clientId = readUser(databasePath, client.email).id;
    const ownerId = readUser(databasePath, SUPER_ADMIN_EMAIL).id;

    const anonymous = await request(`/api/admin/users/${clientId}/verify-email`, {
      method: "POST",
      body: { currentPassword: PASSWORD, reason: "motif de maintenance" },
    });
    assert.equal(anonymous.status, 401);

    const withoutRole = await request(`/api/admin/users/${clientId}/verify-email`, {
      method: "POST",
      cookie: client.cookie,
      csrf: client.csrf,
      body: { currentPassword: PASSWORD, reason: "motif de maintenance" },
    });
    assert.equal(withoutRole.status, 403);
    assert.equal(await errorCode(withoutRole), "super_admin_required");

    const withoutCsrf = await request(`/api/admin/users/${clientId}/verify-email`, {
      method: "POST",
      cookie: owner.cookie,
      body: { currentPassword: PASSWORD, reason: "motif de maintenance" },
    });
    assert.equal(withoutCsrf.status, 403, logSink.value);
    assert.equal(await errorCode(withoutCsrf), "invalid_csrf_token");

    for (const reason of [undefined, "", "court"]) {
      const tooShort = await request(`/api/admin/users/${clientId}/verify-email`, {
        method: "POST",
        cookie: owner.cookie,
        csrf: owner.csrf,
        body: { currentPassword: PASSWORD, reason },
      });
      assert.equal(tooShort.status, 400, `une raison ${JSON.stringify(reason)} doit être refusée`);
      assert.equal(await errorCode(tooShort), "reason_required");
    }

    // Une action inconnue est un 404, pas une écriture : elle doit être sondée sur
    // une cible ordinaire, car une cible protégée est refusée avant même qu'on
    // regarde de quelle action il s'agit.
    const unknownAction = await request(`/api/admin/users/${clientId}/inconnu`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason: "motif de maintenance" },
    });
    assert.equal(unknownAction.status, 404);
    assert.equal(await errorCode(unknownAction), "not_found");

    // Le super-admin ne s'attaque pas à lui-même : la page du compte reste le
    // chemin normal pour son propre compte.
    const onSelf = await request(`/api/admin/users/${ownerId}/sessions/revoke`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason: "motif de maintenance" },
    });
    assert.equal(onSelf.status, 400);
    assert.equal(await errorCode(onSelf), "admin_self_action");

    // Un second porteur du rôle, écrit en base, reste protégé : même une base
    // altérée ne donne pas accès au seul compte qui peut administrer.
    setSuperAdmin(databasePath, client.email, true);
    const onOtherAdmin = await request(`/api/admin/users/${clientId}/sessions/revoke`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason: "motif de maintenance" },
    });
    assert.equal(onOtherAdmin.status, 403, logSink.value);
    assert.equal(await errorCode(onOtherAdmin), "super_admin_protected");

    // Aucune de ces tentatives n'a rien écrit : ni dans la base, ni dans le journal.
    assert.equal(readAuditRows(databasePath).length, 0);
    assert.ok(readUser(databasePath, client.email).email_verified_at);
  } finally {
    await harness.stop();
  }
});

test("les actions d'exploitation s'appliquent et se justifient", async () => {
  const harness = await bootBackOffice();
  const { owner, client, databasePath, logSink } = harness;

  try {
    const clientId = readUser(databasePath, client.email).id;
    const reason = "compte de test, demande explicite du titulaire";

    // ── Confirmation d'adresse ────────────────────────────────────────────────
    const unverified = await register("inconnu@example.test");
    verifyEmail(databasePath, unverified.email);
    const cleared = new DatabaseSync(databasePath);
    cleared.exec("UPDATE users SET email_verified_at = NULL WHERE id = (SELECT id FROM users WHERE email = 'inconnu@example.test')");
    cleared.close();
    const unverifiedId = readUser(databasePath, unverified.email).id;

    const verified = await request(`/api/admin/users/${unverifiedId}/verify-email`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason },
    });
    assert.equal(verified.status, 200, logSink.value);
    assert.ok(readUser(databasePath, unverified.email).email_verified_at);

    // ── Fermeture des sessions ────────────────────────────────────────────────
    assert.ok(countSessions(databasePath, client.email) >= 1);
    const revoked = await request(`/api/admin/users/${clientId}/sessions/revoke`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason },
    });
    assert.equal(revoked.status, 200, logSink.value);
    assert.equal((await revoked.json()).count >= 1, true);
    assert.equal(countSessions(databasePath, client.email), 0);
    const closed = await request("/api/auth/me", { cookie: client.cookie });
    assert.equal((await closed.json()).user, null, "la session révoquée ne doit plus servir");

    // ── Réinitialisation de mot de passe ──────────────────────────────────────
    const NEW_PASSWORD = "NouveauMotDePasse456";
    const target = await login(client.email);
    const reset = await request(`/api/admin/users/${clientId}/password`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, newPassword: NEW_PASSWORD },
    });
    assert.equal(reset.status, 200, logSink.value);
    assert.equal(countSessions(databasePath, client.email), 0, "les sessions tombent avec le mot de passe");
    // L'adresse repart à zéro : elle ne prouve plus qui que ce soit.
    assert.equal(readUser(databasePath, client.email).email_verified_at, null);

    const oldLogin = await request("/api/auth/login", {
      method: "POST",
      body: { email: client.email, password: PASSWORD },
    });
    assert.notEqual(oldLogin.status, 200, "l'ancien mot de passe ne doit plus fonctionner");
    await login(client.email, NEW_PASSWORD);

    const weak = await request(`/api/admin/users/${clientId}/password`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, newPassword: "court" },
    });
    assert.equal(weak.status, 400);

    // ── Prolongation de grâce ─────────────────────────────────────────────────
    const withoutSubscription = await request(`/api/admin/users/${clientId}/subscription/grace`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, hours: 48 },
    });
    assert.equal(withoutSubscription.status, 404);
    assert.equal(await errorCode(withoutSubscription), "no_subscription");

    grantSubscription(databasePath, client.email, { status: "canceled", graceUntil: Date.now() - 1000 });
    const onCanceled = await request(`/api/admin/users/${clientId}/subscription/grace`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, hours: 48 },
    });
    assert.equal(onCanceled.status, 200, logSink.value);
    const graceBody = await onCanceled.json();
    assert.equal(graceBody.effective, true);
    assert.ok(readSubscription(databasePath, client.email).grace_until > Date.now());

    // Sur un abonnement actif, la grâce ne sert à rien : l'action le dit au lieu
    // d'écrire une ligne qui ferait croire à un accord.
    const active = await register("actif@example.test");
    verifyEmail(databasePath, active.email);
    const activeId = readUser(databasePath, active.email).id;
    grantSubscription(databasePath, active.email, { status: "active" });
    const onActive = await request(`/api/admin/users/${activeId}/subscription/grace`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, hours: 48 },
    });
    assert.equal(onActive.status, 200);
    assert.equal((await onActive.json()).effective, false);
    assert.equal(readSubscription(databasePath, active.email).grace_until, null);

    const invalidHours = await request(`/api/admin/users/${activeId}/subscription/grace`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, hours: 0 },
    });
    assert.equal(invalidHours.status, 400);

    // ── Suppression ───────────────────────────────────────────────────────────
    const unconfirmed = await request(`/api/admin/users/${activeId}/delete`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason },
    });
    assert.equal(unconfirmed.status, 400);
    assert.equal(await errorCode(unconfirmed), "confirmation_required");

    const withLiveSubscription = await request(`/api/admin/users/${activeId}/delete`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, confirmation: "SUPPRIMER" },
    });
    assert.equal(withLiveSubscription.status, 409, logSink.value);
    assert.equal(await errorCode(withLiveSubscription), "subscription_active");

    const cancelled = new DatabaseSync(databasePath);
    cancelled.exec("UPDATE subscriptions SET status = 'canceled' WHERE user_id = (SELECT id FROM users WHERE email = 'actif@example.test')");
    cancelled.close();

    const deleted = await request(`/api/admin/users/${activeId}/delete`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, confirmation: "SUPPRIMER" },
    });
    assert.equal(deleted.status, 200, logSink.value);
    assert.equal(readUser(databasePath, active.email), undefined);
  } finally {
    await harness.stop();
  }
});

test("la modération d'un QR code est justifiée, et le journal survit aux comptes supprimés", async () => {
  const harness = await bootBackOffice();
  const { owner, client, databasePath, logSink } = harness;

  try {
    const reason = "signalement abuse, lien litigieux";

    // Un QR code du client, un QR code du super-admin.
    const clientQrcode = (await (await request("/api/qrcodes", {
      method: "POST",
      cookie: client.cookie,
      csrf: client.csrf,
      body: { name: "QR du client", mode: "link", destination: "https://example.test/client" },
    })).json()).qrcode;
    const ownerQrcode = (await (await request("/api/qrcodes", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { name: "QR du super-admin", mode: "link", destination: "https://example.test/owner" },
    })).json()).qrcode;

    const ambiguous = await request(`/api/admin/qrcodes/${clientQrcode.id}/activity`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason },
    });
    assert.equal(ambiguous.status, 400, logSink.value);
    assert.equal(await errorCode(ambiguous), "invalid_active");
    assert.equal(readQrcodeRow(databasePath, clientQrcode.id).is_active, 1);

    const onProtected = await request(`/api/admin/qrcodes/${ownerQrcode.id}/activity`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, active: false },
    });
    assert.equal(onProtected.status, 403);
    assert.equal(await errorCode(onProtected), "super_admin_protected");
    assert.equal(readQrcodeRow(databasePath, ownerQrcode.id).is_active, 1);

    const disabled = await request(`/api/admin/qrcodes/${clientQrcode.id}/activity`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, active: false },
    });
    assert.equal(disabled.status, 200, logSink.value);
    assert.equal(readQrcodeRow(databasePath, clientQrcode.id).is_active, 0);

    const missing = await request("/api/admin/qrcodes/999999/activity", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, active: false },
    });
    assert.equal(missing.status, 404);

    // ── Le journal ────────────────────────────────────────────────────────────
    const audit = await request("/api/admin/audit", { cookie: owner.cookie });
    assert.equal(audit.status, 200, logSink.value);
    const auditBody = await audit.json();
    // Une seule tentative a abouti : les refus (motif trop court, cible protégée,
    // QR code du super-admin, identifiant inconnu) ne doivent rien laisser dans le
    // journal, sans quoi une trace d'action examinerait des écritures jamais faites.
    assert.equal(auditBody.total, 1);
    const deactivation = auditBody.actions.find((entry) => entry.action === "qrcode_deactivated");
    assert.ok(deactivation, "l'action doit être journalisée");
    assert.equal(deactivation.actorEmail, SUPER_ADMIN_EMAIL);
    assert.equal(deactivation.targetEmail, client.email);
    assert.equal(deactivation.reason, reason);
    assert.ok(deactivation.createdAt);

    // L'adresse de la cible est dénormalisée : la ligne doit survivre à la
    // suppression du compte qu'elle décrit, sinon l'histoire s'écrit avec les
    // comptes qu'elle a effacés.
    const clientId = readUser(databasePath, client.email).id;
    const cancelled = new DatabaseSync(databasePath);
    cancelled.exec("UPDATE subscriptions SET status = 'canceled' WHERE user_id = ?", clientId);
    cancelled.close();
    const deleted = await request(`/api/admin/users/${clientId}/delete`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, confirmation: "SUPPRIMER" },
    });
    assert.equal(deleted.status, 200, logSink.value);
    assert.equal(readUser(databasePath, client.email), undefined);

    const rows = readAuditRows(databasePath);
    const deletion = rows.find((entry) => entry.action === "account_deleted");
    assert.ok(deletion, "la suppression doit rester journalisée après le compte");
    assert.equal(deletion.actor_email, SUPER_ADMIN_EMAIL);
    assert.equal(deletion.target_email, client.email);
    assert.equal(deletion.reason, reason);

    const afterDeletion = await request("/api/admin/audit", { cookie: owner.cookie });
    const afterBody = await afterDeletion.json();
    assert.ok(afterBody.actions.some((entry) => entry.action === "qrcode_deactivated"));
    assert.ok(afterBody.actions.some((entry) => entry.action === "account_deleted"));
  } finally {
    await harness.stop();
  }
});

// ── Double authentification ─────────────────────────────────────────────────
//
// Le code TOTP est recalculé ici à partir de la RFC 6238, et non réutilisé depuis
// le serveur : un test qui partagerait l'implémentation validerait le code même
// qu'il est censé contester, et passerait pour une vérification qui n'en est pas
// une.
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBytes(secret) {
  const cleaned = String(secret).toUpperCase().replace(/=+$/, "");
  const bytes = [];
  let value = 0;
  let bits = 0;
  for (const character of cleaned) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
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
      SELECT t.secret, t.confirmed_at, t.pending_secret, t.recovery_codes
      FROM two_factor_auth t JOIN users u ON u.id = t.user_id
      WHERE u.email = ?
    `).get(email);
    if (!row) return { enrolled: false, recoveryCodes: 0 };
    return {
      enrolled: Boolean(row.secret && row.confirmed_at),
      pending: Boolean(row.pending_secret),
      recoveryCodes: JSON.parse(row.recovery_codes || "[]").length,
    };
  } finally {
    database.close();
  }
}

test("l'administration peut offrir une offre, et seulement à un compte sans abonnement Stripe", async () => {
  const harness = await bootBackOffice();
  const { owner, client, databasePath, logSink } = harness;
  const reason = "offre offerte pour la démonstration du 14 octobre";

  try {
    const clientId = readUser(databasePath, client.email).id;
    const gift = (body) =>
      request(`/api/admin/users/${clientId}/subscription/plan`, {
        method: "POST",
        cookie: owner.cookie,
        csrf: owner.csrf,
        body: { currentPassword: PASSWORD, reason, ...body },
      });

    const before = await (await request(`/api/admin/users/${clientId}`, { cookie: owner.cookie })).json();
    assert.equal(before.subscription.status, null, "le compte part sans abonnement");
    assert.equal(before.entitlement.plan, "decouverte");
    assert.equal(before.entitlement.maxQrcodes, 5);

    // Une durée hors bornes ou une offre inconnue n'écrit rien : une erreur de
    // saisie ne doit pas accorder un accès sans limite.
    for (const body of [{ plan: "inconnu", days: 30 }, { plan: "pro", days: 0 }, { plan: "pro", days: 4000 }]) {
      const refused = await gift(body);
      assert.equal(refused.status, 400, logSink.value);
    }
    const untouched = await (await request(`/api/admin/users/${clientId}`, { cookie: owner.cookie })).json();
    assert.equal(untouched.subscription.status, null, "un refus ne doit laisser aucune ligne derrière lui");
    assert.equal(countSubscriptions(databasePath, client.email), 0);

    const granted = await gift({ plan: "pro", days: 30 });
    assert.equal(granted.status, 200, logSink.value);
    const result = await granted.json();
    assert.equal(result.plan, "pro");
    assert.match(result.message, /sans facturation/);

    const after = await (await request(`/api/admin/users/${clientId}`, { cookie: owner.cookie })).json();
    assert.equal(after.subscription.plan, "pro");
    assert.equal(after.subscription.status, "active");
    assert.equal(after.subscription.manual, true, "sans identifiant Stripe, l'offre n'est pas un abonnement");
    assert.equal(
      after.subscription.cancelAtPeriodEnd,
      false,
      "elle se renouvelle d'un an à chaque échéance, ce qui exige de ne pas demander son arrêt",
    );
    assert.equal(after.subscription.autoRenew, true, "l'offre manuelle se prolonge toute seule");
    assert.equal(after.entitlement.plan, "pro");
    assert.equal(after.entitlement.maxQrcodes, 25);

    // La période est bien celle demandée, à la minute près près.
    const requested = Date.now() + 30 * 24 * 3_600 * 1_000;
    assert.ok(
      Math.abs(new Date(after.subscription.currentPeriodEnd).getTime() - requested) < 60_000,
      `échéance inattendue : ${after.subscription.currentPeriodEnd}`,
    );

    // Offrir par-dessus un accès existant le remplace, au lieu d'accumuler des
    // lignes concurrentes dont personne ne saurait laquelle fait foi.
    const upgraded = await gift({ plan: "ultra", days: 90 });
    assert.equal(upgraded.status, 200, logSink.value);
    const afterUpgrade = await (await request(`/api/admin/users/${clientId}`, { cookie: owner.cookie })).json();
    assert.equal(afterUpgrade.subscription.plan, "ultra");
    assert.equal(afterUpgrade.entitlement.plan, "ultra");
    assert.equal(afterUpgrade.entitlement.maxQrcodes, null);
    assert.equal(countSubscriptions(databasePath, client.email), 1, "une seule ligne d'abonnement par compte");

    // Une échéance dépassée ne doit pas faire tomber l'accès : l'offre est
    // renouvelée d'un an au premier accès qui la constate, et c'est bien une année
    // entière à partir de maintenant, pas le reliquat de la période dépassée.
    expireSubscription(databasePath, client.email, { days: 1 });
    const renewedAt = Date.now();
    const renewed = await (await request(`/api/admin/users/${clientId}`, { cookie: owner.cookie })).json();
    assert.equal(renewed.entitlement.plan, "ultra", "l'offre survit à son échéance");
    assert.equal(renewed.subscription.autoRenew, true);
    const renewedEnd = new Date(renewed.subscription.currentPeriodEnd).getTime();
    const oneYear = 365 * 24 * 3_600 * 1_000;
    assert.ok(
      renewedEnd > renewedAt + oneYear - 60_000 && renewedEnd <= renewedAt + oneYear + 60_000,
      `le renouvellement doit porter un an depuis maintenant : ${renewed.subscription.currentPeriodEnd}`,
    );

    // Un compte peut garder des lignes terminées d'anciens abonnements : l'offre
    // écrite ici ne doit toucher que la ligne courante, sinon elle ressusciterait
    // des abonnements que Stripe a clos.
    addTerminalSubscription(databasePath, client.email, { plan: "pro" });
    assert.equal(countSubscriptions(databasePath, client.email), 2, "l'historique est bien conservé");
    const regrant = await gift({ plan: "pro", days: 30 });
    assert.equal(regrant.status, 200, logSink.value);
    const afterRegrant = await (await request(`/api/admin/users/${clientId}`, { cookie: owner.cookie })).json();
    assert.equal(afterRegrant.subscription.plan, "pro");
    const historical = readPlans(databasePath, client.email).filter((row) => row.status === "canceled");
    assert.equal(historical.length, 1, "la ligne terminée n'a pas été réécrite");
    assert.equal(historical[0].plan, "pro", "elle garde l'offre qu'elle portait, pas celle du dessus");

    // Un arrêt demandé prime sur le renouvellement : c'est le geste explicite de
    // retrait, et il doit survivre au passage du temps.
    expireSubscription(databasePath, client.email, { days: 1, cancelAtPeriodEnd: true });
    const stopped = await (await request(`/api/admin/users/${clientId}`, { cookie: owner.cookie })).json();
    assert.equal(stopped.entitlement.plan, "decouverte", "une offre arrêtée retombe sur Découverte");
    assert.equal(stopped.subscription.autoRenew, false);
    const stillStopped = readPeriodEnd(databasePath, client.email);
    assert.ok(
      stillStopped < Date.now(),
      "l'échéance dépassée n'est pas repoussée quand l'arrêt est demandé",
    );

    // Un vrai abonnement Stripe reste maître : écrire par-dessus créerait un
    // écart que le prochain webhook refermerait sans prévenir personne.
    const subscriber = await register("abonne@example.test");
    grantSubscription(databasePath, subscriber.email, { plan: "pro" });
    const subscriberId = readUser(databasePath, subscriber.email).id;
    const conflict = await request(`/api/admin/users/${subscriberId}/subscription/plan`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, plan: "ultra", days: 30 },
    });
    assert.equal(conflict.status, 409, logSink.value);
    assert.equal(await errorCode(conflict), "stripe_subscription_active");
    const kept = await (await request(`/api/admin/users/${subscriberId}`, { cookie: owner.cookie })).json();
    assert.equal(kept.subscription.plan, "pro", "l'abonnement Stripe est resté intact");

    // Le compte du super-admin reste hors d'atteinte : s'attribuer une offre n'a
    // rien à faire du rôle, qui accorde déjà Ultra sans abonnement.
    const ownerId = readUser(databasePath, SUPER_ADMIN_EMAIL).id;
    const onOwner = await request(`/api/admin/users/${ownerId}/subscription/plan`, {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD, reason, plan: "pro", days: 30 },
    });
    assert.equal(onOwner.status, 400, logSink.value);
    assert.equal(await errorCode(onOwner), "admin_self_action");
    assert.equal(countSubscriptions(databasePath, SUPER_ADMIN_EMAIL), 0);

    const rows = readAuditRows(databasePath, "metadata");
    const grants = rows.filter((row) => row.action === "subscription_granted");
    assert.equal(grants.length, 3, "les trois offres accordées, et rien d'autre");
    assert.equal(grants[0].actor_email, SUPER_ADMIN_EMAIL);
    assert.equal(grants[0].target_email, client.email);
    assert.equal(grants[0].reason, reason);
    // Le renouvellement paresseux n'écrit rien dans le journal : il ne correspond à
    // aucune décision humaine, et le motif « offrir une offre » ne vaudrait pas
    // preuve d'une nouvelle intervention du super-admin.
    assert.ok(
      !rows.some((row) => row.action === "subscription_renewed"),
      "le renouvellement automatique reste hors du journal des interventions",
    );
    const meta = JSON.parse(grants[1].metadata);
    assert.equal(meta.plan, "ultra");
    assert.equal(meta.days, 90);
    assert.equal(meta.previousPlan, "pro");
    assert.equal(meta.autoRenew, true, "l'offre est journalisée comme renouvelée d'office");
    assert.equal(meta.factor, "password");
    const last = JSON.parse(grants[2].metadata);
    assert.equal(last.plan, "pro");
    assert.equal(last.previousPlan, "ultra", "l'historique n'a pas défini la ligne courante");
  } finally {
    await harness.stop();
  }
});

test("la double authentification devient la condition de chaque écriture", async () => {
  const harness = await bootBackOffice();
  const { owner, client, databasePath, logSink } = harness;
  const reason = "mise en place de la double authentification";
  const clientId = readUser(databasePath, client.email).id;

  try {
    const initial = await (await request("/api/admin/2fa", { cookie: owner.cookie })).json();
    assert.equal(initial.enrolled, false);
    assert.equal(initial.recoveryCodesRemaining, 0);

    // ── Activation ───────────────────────────────────────────────────────────
    const anonymousSetup = await request("/api/admin/2fa/setup", {
      method: "POST",
      body: { reason, currentPassword: PASSWORD },
    });
    assert.equal(anonymousSetup.status, 401);

    // Poser un secret d'authentification sur une session volée donnerait le
    // contrôle du compte à qui l'a volée : le mot de passe est exigé d'emblée.
    const setupWithoutPassword = await request("/api/admin/2fa/setup", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { reason },
    });
    assert.equal(setupWithoutPassword.status, 400);
    assert.equal(await errorCode(setupWithoutPassword), "current_password_required");

    const setupWithoutReason = await request("/api/admin/2fa/setup", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { currentPassword: PASSWORD },
    });
    assert.equal(setupWithoutReason.status, 400);
    assert.equal(await errorCode(setupWithoutReason), "reason_required");

    const setup = await request("/api/admin/2fa/setup", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { reason, currentPassword: PASSWORD },
    });
    assert.equal(setup.status, 200, logSink.value);
    const { secret, uri } = await setup.json();
    assert.match(secret, /^[A-Z2-7]{32}$/, "le secret est base32, comme l'attend le standard");
    assert.ok(uri.startsWith("otpauth://totp/"), `URI inattendue : ${uri}`);
    assert.ok(uri.includes(`secret=${secret}`));
    // Tant que le code n'est pas confirmé, le secret presented n'est pas actif :
    // c'est ce qui empêche un secret jeté au hasard de bloquer le compte.
    assert.equal(readTwoFactor(databasePath, SUPER_ADMIN_EMAIL).enrolled, false);
    assert.equal(readTwoFactor(databasePath, SUPER_ADMIN_EMAIL).pending, true);

    const wrongConfirm = await request("/api/admin/2fa/confirm", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { reason, code: "000000" },
    });
    assert.equal(wrongConfirm.status, 403, logSink.value);
    assert.equal(await errorCode(wrongConfirm), "invalid_two_factor_code");

    const confirmed = await request("/api/admin/2fa/confirm", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { reason, code: totpCodeFor(secret) },
    });
    assert.equal(confirmed.status, 200, logSink.value);
    const recoveryCodes = (await confirmed.json()).recoveryCodes;
    assert.equal(recoveryCodes.length, 8);
    assert.equal(new Set(recoveryCodes).size, 8, "chaque code de récupération est unique");
    assert.ok(recoveryCodes.every((code) => /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code)), recoveryCodes.join(" "));
    // Les codes ne vivent qu'hachés : une copie de la base ne donne rien.
    assert.equal(readTwoFactor(databasePath, SUPER_ADMIN_EMAIL).recoveryCodes, 8);

    const afterConfirm = await (await request("/api/admin/2fa", { cookie: owner.cookie })).json();
    assert.equal(afterConfirm.enrolled, true);
    assert.equal(afterConfirm.recoveryCodesRemaining, 8);
    assert.equal(afterConfirm.setupPending, false);
    assert.ok(afterConfirm.confirmedAt);

    // ── Le mot de passe ne suffit plus ───────────────────────────────────────
    const write = (body) =>
      request(`/api/admin/users/${clientId}/sessions/revoke`, {
        method: "POST",
        cookie: owner.cookie,
        csrf: owner.csrf,
        body,
      });

    const withoutCode = await write({ reason });
    assert.equal(withoutCode.status, 403, logSink.value);
    assert.equal(await errorCode(withoutCode), "two_factor_required");

    const passwordOnly = await write({ reason, currentPassword: PASSWORD });
    assert.equal(passwordOnly.status, 403);
    assert.equal(await errorCode(passwordOnly), "two_factor_required");

    const wrongCode = await write({ reason, currentPassword: PASSWORD, twoFactorCode: "000000" });
    assert.equal(wrongCode.status, 403);
    assert.equal(await errorCode(wrongCode), "invalid_two_factor_code");
    assert.equal(countSessions(databasePath, client.email), 1, "aucune écriture sans second facteur");

    // ── Le code de l'application ────────────────────────────────────────────
    const liveCode = totpCodeFor(secret);
    const accepted = await write({ reason, currentPassword: PASSWORD, twoFactorCode: liveCode });
    assert.equal(accepted.status, 200, logSink.value);
    assert.equal(countSessions(databasePath, client.email), 0);

    // Le même code, une seconde fois : la fenêtre de tolérance (±30 s) le rendrait
    // encore valable sans le compteur mémorisé.
    const replayed = await write({ reason, currentPassword: PASSWORD, twoFactorCode: liveCode });
    assert.equal(replayed.status, 403);
    assert.equal(await errorCode(replayed), "invalid_two_factor_code");

    // ── Un code de récupération, une seule fois ─────────────────────────────
    const recovery = recoveryCodes[0];
    const withRecovery = await write({ reason, currentPassword: PASSWORD, twoFactorCode: recovery });
    assert.equal(withRecovery.status, 200, logSink.value);
    assert.equal(readTwoFactor(databasePath, SUPER_ADMIN_EMAIL).recoveryCodes, 7);

    const reusedRecovery = await write({ reason, currentPassword: PASSWORD, twoFactorCode: recovery });
    assert.equal(reusedRecovery.status, 403);
    assert.equal(await errorCode(reusedRecovery), "invalid_two_factor_code");

    // ── Le journal dit quel facteur a réellement servi ───────────────────────
    const rows = readAuditRows(databasePath, "metadata");
    assert.ok(rows.some((row) => row.action === "two_factor_setup"));
    const enabled = rows.find((row) => row.action === "two_factor_enabled");
    assert.ok(enabled, "l'activation doit être journalisée");
    assert.equal(enabled.actor_email, SUPER_ADMIN_EMAIL);
    assert.equal(enabled.target_email, SUPER_ADMIN_EMAIL);
    assert.equal(JSON.parse(enabled.metadata).recoveryCodes, 8);
    const byTotp = rows.find((row) => row.action === "sessions_revoked" && JSON.parse(row.metadata).factor === "totp");
    const byRecovery = rows.find((row) => row.action === "sessions_revoked" && JSON.parse(row.metadata).factor === "recovery");
    assert.ok(byTotp, "une écriture validée par code doit le dire");
    assert.ok(byRecovery, "une écriture validée par code de récupération doit le dire");

    // ── Désactivation ────────────────────────────────────────────────────────
    const disableWithoutFactor = await request("/api/admin/2fa/disable", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { reason, currentPassword: PASSWORD },
    });
    assert.equal(disableWithoutFactor.status, 403);
    assert.equal(await errorCode(disableWithoutFactor), "two_factor_required");

    // Le téléphone est perdu : c'est le cas d'usage des codes de récupération.
    // Le mot de passe seul ne désactive rien, et le code déjà utilisé deux fois
    // plus haut ne peut pas servir non plus.
    const disabled = await request("/api/admin/2fa/disable", {
      method: "POST",
      cookie: owner.cookie,
      csrf: owner.csrf,
      body: { reason, currentPassword: PASSWORD, twoFactorCode: recoveryCodes[1] },
    });
    assert.equal(disabled.status, 200, logSink.value);
    assert.equal(readTwoFactor(databasePath, SUPER_ADMIN_EMAIL).enrolled, false);

    // Le repli revient : sans double authentification, le mot de passe suffit.
    const backToPassword = await write({ reason, currentPassword: PASSWORD });
    assert.equal(backToPassword.status, 200, logSink.value);
  } finally {
    await harness.stop();
  }
});

test("la généralisation de la double authentification migrate une base existante", async () => {
  const harness = await bootBackOffice();
  const { databasePath, logSink, restart, halt } = harness;

  try {
    // ── Une base d'avant la généralisation ─────────────────────────────────
    // La table est reconstruite à l'identique de l'ancienne version, puis remplie :
    // c'est le seul moyen de prouver que le secret survit, puisque le serveur n'a
    // jamais écrit sous l'ancien nom. Le serveur est arrêté avant : SQLite refuse
    // d'écrire dans un fichier ouvert, et surtout le démarrage suivant doit être le
    // premier à voir la base dans son état d'avant.
    await halt();
    const legacy = new DatabaseSync(databasePath);
    legacy.exec(`
      BEGIN;
      DROP INDEX IF EXISTS idx_two_factor_auth_pending;
      ALTER TABLE two_factor_auth RENAME TO admin_two_factor;
      CREATE INDEX idx_admin_two_factor_pending ON admin_two_factor(pending_expires_at);
      COMMIT;
    `);
    const superAdmin = legacy.prepare("SELECT id FROM users WHERE email = ?").get(SUPER_ADMIN_EMAIL);
    legacy.prepare(`
      INSERT INTO admin_two_factor (user_id, secret, confirmed_at, pending_secret, pending_expires_at, last_counter, recovery_codes, updated_at)
      VALUES (?, ?, ?, NULL, NULL, NULL, '["haché"]', ?)
    `).run(superAdmin.id, LEGACY_SECRET, Date.now(), Date.now());
    legacy.close();

    // ── Le redémarrage doit aboutir ─────────────────────────────────────────
    await restart();
    assert.doesNotMatch(logSink.value, /SQL logic error|already exists/i, logSink.value);

    // Le secret est resté, sans réenrôlement : le compte ne doit pas être verrouillé
    // hors de chez lui par une simple mise à jour.
    const migrated = readTwoFactor(databasePath, SUPER_ADMIN_EMAIL);
    assert.equal(migrated.enrolled, true, "le secret existant doit survivre à la migration");
    assert.equal(migrated.recoveryCodes, 1);

    // La table legacy a disparu, et l'index suit le nouveau nom.
    const check = new DatabaseSync(databasePath);
    const tables = check
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all()
      .map((row) => row.name);
    assert.ok(!tables.includes("admin_two_factor"), "l'ancienne table doit avoir disparu");
    assert.ok(tables.includes("two_factor_auth"));
    const indexes = check
      .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'two_factor_auth'")
      .all()
      .map((row) => row.name);
    assert.ok(indexes.includes("idx_two_factor_auth_pending"), "l'index doit porter le nouveau nom");
    check.close();

    // ── Le secret migré sert réellement ─────────────────────────────────────
    // Le mot de passe seul ne redonne plus de session : la preuve que le second
    // facteur a survécu n'est pas la ligne en base, c'est le fait qu'il refuse
    // d'entrer.
    const loginWithoutCode = await request("/api/auth/login", {
      method: "POST",
      body: { email: SUPER_ADMIN_EMAIL, password: PASSWORD },
    });
    assert.equal(loginWithoutCode.status, 401, logSink.value);
    assert.equal(await errorCode(loginWithoutCode), "two_factor_required");

    const loginWithCode = await request("/api/auth/login", {
      method: "POST",
      body: {
        email: SUPER_ADMIN_EMAIL,
        password: PASSWORD,
        twoFactorCode: totpCodeFor(LEGACY_SECRET),
      },
    });
    assert.equal(loginWithCode.status, 200, logSink.value);

    const status = await (await request("/api/admin/2fa", { cookie: sessionCookie(loginWithCode) })).json();
    assert.equal(status.enrolled, true);
    assert.equal(status.recoveryCodesRemaining, 1);
  } finally {
    await harness.stop();
  }
});