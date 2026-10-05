import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLIENT_ID = "client-de-test.apps.googleusercontent.com";
const CLIENT_SECRET = "secret-de-test";
const PASSWORD = "MotDePassePlan789";
const REDIRECT_URI_PATH = "/api/auth/google/callback";
let PORT;
let ORIGIN;

// ── Faux fournisseur Google ─────────────────────────────────────────────────
//
// Google n'est pas joignable depuis un test : les trois points d'appel sont donc
// remplacés par un serveur local qui répond comme lui. C'est ce qui permet de suivre
// le flux de bout en bout, échange de jeton et lecture du profil compris, sans
// qu'aucun test ne dépende du réseau ni d'un compte réel.
function startFakeGoogle(profile = {}) {
  const calls = {
    profile: { sub: "sub-camille", email: "camille@example.test", email_verified: true, name: "Camille Martin", ...profile },
    tokenStatus: 200,
    userinfoStatus: 200,
    tokenRequest: null,
    profileAuthorization: null,
  };

  const server = http.createServer((request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const send = (status, payload) => {
        const body = Buffer.from(JSON.stringify(payload));
        response.writeHead(status, { "Content-Type": "application/json", "Content-Length": body.length });
        response.end(body);
      };
      if (url.pathname === "/token") {
        calls.tokenRequest = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        if (calls.tokenStatus !== 200) {
          send(calls.tokenStatus, { error: "invalid_grant" });
          return;
        }
        send(200, { access_token: "jeton-de-test", token_type: "Bearer", expires_in: 3600 });
        return;
      }
      if (url.pathname === "/userinfo") {
        calls.profileAuthorization = request.headers.authorization;
        send(calls.userinfoStatus, calls.userinfoStatus === 200 ? calls.profile : { error: "invalid_token" });
        return;
      }
      send(404, { error: "not_found" });
    });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve({
        calls,
        origin: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

// ── Harnais ─────────────────────────────────────────────────────────────────

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

function buildChildEnvironment(overrides = {}) {
  const environment = { ...process.env };
  // Les variables du poste sont écartées : un développeur qui a configuré Google pour
  // autre chose ne doit pas voir ses identifiants arriver dans un test, ni voir un
  // test démarrer un serveur configuré alors qu'il veut l'inverse.
  for (const key of Object.keys(environment)) {
    if (key.startsWith("QROOD_") || key.startsWith("GOOGLE_")) delete environment[key];
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
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Le serveur de test s'est arrêté : ${logSink.value}`);
    try {
      const response = await request("/api/health");
      if (response.ok) return child;
    } catch {
      // Le socket n'est pas encore prêt.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Délai de démarrage du serveur de test dépassé.");
}

async function stopServer(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    if (child.exitCode !== null) resolve();
    else child.once("exit", resolve);
  });
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

async function errorCode(response) {
  const payload = await response.json();
  return payload?.error?.code;
}

function cookiePair(response) {
  return response.headers.getSetCookie().map((entry) => entry.split(";", 1)[0]).join("; ");
}

function sessionCookie(response) {
  const entry = response.headers.getSetCookie().find((value) => value.startsWith("qrood_session="));
  return entry ? entry.split(";", 1)[0] : "";
}

function readUser(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare(`
      SELECT id, display_name, email, password_hash, email_verified_at, is_super_admin, auth_provider, provider_id
      FROM users WHERE email = ?
    `).get(email);
  } finally {
    database.close();
  }
}

function countUsers(databasePath) {
  const database = new DatabaseSync(databasePath);
  try {
    return database.prepare("SELECT COUNT(*) AS total FROM users").get().total;
  } finally {
    database.close();
  }
}

// Démarre un faux Google puis le serveur QROOD branché dessus. `configured: false`
// démarre le serveur sans aucun identifiant, ce qui est l'état par défaut d'une
// installation : le fournisseur n'existe pas et la route doit le dire.
async function bootOauth({ profile = {}, configured = true } = {}) {
  const google = await startFakeGoogle(profile);
  const directory = mkdtempSync(path.join(os.tmpdir(), "qrood-oauth-test-"));
  const databasePath = path.join(directory, "test.sqlite");
  const logSink = { value: "" };

  const environment = { QROOD_DB_PATH: databasePath };
  if (configured) {
    Object.assign(environment, {
      GOOGLE_CLIENT_ID: CLIENT_ID,
      GOOGLE_CLIENT_SECRET: CLIENT_SECRET,
      QROOD_GOOGLE_AUTH_URL: `${google.origin}/o/oauth2/v2/auth`,
      QROOD_GOOGLE_TOKEN_URL: `${google.origin}/token`,
      QROOD_GOOGLE_USERINFO_URL: `${google.origin}/userinfo`,
    });
  }

  PORT = await getFreePort();
  ORIGIN = `http://localhost:${PORT}`;
  let server = await startServer(buildChildEnvironment(environment), logSink);

  const restart = async () => {
    await stopServer(server);
    // Un nouveau port à chaque redémarrage : sur Windows, réutiliser celui qu'on vient
    // de libérer peut échouer sur EADDRINUSE.
    PORT = await getFreePort();
    ORIGIN = `http://localhost:${PORT}`;
    server = await startServer(buildChildEnvironment(environment), logSink);
    return server;
  };

  return {
    google,
    databasePath,
    logSink,
    restart,
    stop: async () => {
      await stopServer(server);
      rmSync(directory, { recursive: true, force: true });
      await google.close();
    },
  };
}

// Le début du flux : le serveur renvoie vers le fournisseur et pose ses cookies. Le
// `state` est relu ici, car c'est lui que le callback devra présenter.
async function startFlow(query = "") {
  const start = await request(`/api/auth/google/start${query}`, {
    headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
  });
  return {
    response: start,
    location: start.headers.get("location") ? new URL(start.headers.get("location")) : null,
    state: start.headers.get("location")
      ? new URL(start.headers.get("location")).searchParams.get("state")
      : null,
    cookie: cookiePair(start),
  };
}

// ── La page du compte ──────────────────────────────────────────────────────
//
// Relier une identité, la retirer, se ré-authentifier : ces gestes partent tous d'un
// POST protégé par le jeton de session et le CSRF, et aboutissent à un aller-retour par
// le fournisseur. Le serveur renvoie l'adresse à ouvrir et pose le cookie d'état ; ces
// deux helpers rejouent ce que ferait le navigateur, cookie de session compris.

async function registerLocal(email, password = PASSWORD) {
  const response = await request("/api/auth/register", {
    method: "POST",
    headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: { displayName: "Camille Martin", email, password },
  });
  const session = sessionCookie(response);
  const me = await request("/api/auth/me", { cookie: session });
  const payload = await me.json();
  return { response, session, csrf: payload.csrfToken, me: payload };
}

// L'interface ne peut pas suivre une `Location` vers un autre site depuis une requête
// faite en JavaScript : le serveur renvoie donc l'adresse, et c'est la page qui
// l'ouvre. Un refus n'a rien à ouvrir.
async function startAccountFlow(path, account, body = {}) {
  const response = await accountAction(path, account, body);
  if (response.status !== 200) return { response, url: null, state: null, flowCookie: null, cookie: null };
  const url = new URL((await response.json()).url);
  return {
    response,
    url,
    state: url.searchParams.get("state"),
    flowCookie: cookiePair(response),
    cookie: `${account.session}; ${cookiePair(response)}`,
  };
}

// Délier ne renvoie pas d'adresse : rien à ouvrir chez le fournisseur, la décision est
// prise sur place. Un compte sans jeton passe par là aussi : c'est ainsi qu'on éprouve
// le refus du jeton manquant.
async function accountAction(path, account, body = {}) {
  return request(path, {
    method: "POST",
    cookie: account.session,
    csrf: account.csrf || undefined,
    headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body,
  });
}

async function finishAccountFlow(flow) {
  return request(`${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`, {
    cookie: flow.cookie,
  });
}

// Changer l'identité que renvoie le fournisseur, en gardant le reste du profil : c'est
// ainsi qu'on éprouve un compte Google différent du premier, et non une adresse en
// général non vérifiée — que le serveur, à raison, refuserait d'abord.
function swapProfile(harness, profile) {
  harness.google.calls.profile = { ...harness.google.calls.profile, ...profile };
}

// La double authentification s'active par l'API, avec un code recalculé ici à partir de
// la RFC 6238 et non réutilisé depuis le serveur : un test qui partagerait
// l'implémentation validerait le code même qu'il est censé contester, et passerait pour
// une vérification qui n'en est pas une.
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

async function enrollTwoFactor(account, password = PASSWORD) {
  const setup = await request("/api/auth/2fa/setup", {
    method: "POST",
    cookie: account.session,
    csrf: account.csrf,
    headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: { currentPassword: password },
  });
  const { secret } = await setup.json();
  const confirmed = await request("/api/auth/2fa/confirm", {
    method: "POST",
    cookie: account.session,
    csrf: account.csrf,
    headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: { code: totpCodeFor(secret) },
  });
  return { setup, confirmed, secret };
}

function readFreshness(databasePath, email) {
  const database = new DatabaseSync(databasePath);
  try {
    const row = database.prepare(`
      SELECT s.fresh_until FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = ?
    `).get(email);
    return row ? row.fresh_until : null;
  } finally {
    database.close();
  }
}

// La fenêtre de fraîcheur est une donnée, pas un état en mémoire : la faire expirer ici
// permet d'en éprouver la fin sans attendre quinze minutes de test.
function expireFreshness(databasePath) {
  const database = new DatabaseSync(databasePath);
  try {
    database.prepare("UPDATE sessions SET fresh_until = 0").run();
  } finally {
    database.close();
  }
}

// Le numéro de session que le cookie d'état emporte. Le test ne le devine pas : il le
// lit, comme le ferait un attaquant qui énumère des identifiants courts. Ce que le
// cookie ne doit jamais permettre, c'est de s'en servir — pas de le connaître.
function readLatestSessionId(databasePath, userId) {
  const database = new DatabaseSync(databasePath);
  try {
    const row = database.prepare(`
      SELECT id FROM sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1
    `).get(userId);
    return row ? row.id : null;
  } finally {
    database.close();
  }
}

// ── Tests ───────────────────────────────────────────────────────────────────

test("connexion Google : le flux crée un compte sans mot de passe et ouvre une session", async () => {
  const harness = await bootOauth();
  const { google, databasePath, logSink } = harness;

  try {
    // ── L'aller ──────────────────────────────────────────────────────────────
    const flow = await startFlow();
    assert.equal(flow.response.status, 302, logSink.value);
    assert.equal(flow.location.origin, google.origin);
    assert.equal(flow.location.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(flow.location.searchParams.get("redirect_uri"), `${ORIGIN}${REDIRECT_URI_PATH}`);
    assert.equal(flow.location.searchParams.get("response_type"), "code");
    assert.equal(flow.location.searchParams.get("scope"), "openid email profile");
    assert.ok(flow.state && flow.state.length >= 32, "le state doit être tiré au hasard");

    // Le cookie d'état est le seul lien entre les deux temps : `HttpOnly` pour que la
    // page ne le forge pas, `Lax` seul mode qui accompagne le retour de Google. Il
    // porte le nonce - le `state` que le fournisseur recopie - puis l'intention du
    // parcours et le compte et la session concernes : `0.0` pour une connexion.
    const stateCookie = flow.response.headers.getSetCookie()
      .find((entry) => entry.startsWith("qrood_oauth_state="));
assert.ok(stateCookie, "le cookie d'état doit être posé");
    assert.match(stateCookie, /HttpOnly/);
    assert.match(stateCookie, /SameSite=Lax/);
    assert.match(stateCookie, /Path=\/api\/auth\/google/);
    // Le nonce, l'intention, le compte et la session, puis la signature : `0.0` pour
    // une connexion, et une signature que le test ne peut pas fabriquer.
    const cookieValue = stateCookie.split("=", 2)[1].split(";")[0];
    assert.ok(
      cookieValue.startsWith(`${flow.state}.login.0.0.`),
      `cookie d'état inattendu : ${cookieValue}`,
    );

    // ── Le retour ────────────────────────────────────────────────────────────
    const callback = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: flow.cookie },
    );
    assert.equal(callback.status, 302, logSink.value);
    assert.equal(callback.headers.get("location"), "/");
    assert.ok(sessionCookie(callback), "une session doit être ouverte");

    // L'échange est un échange de code authentifié, jamais un mot de passe : le secret
    // est côté serveur, et l'adresse de retour est celle déclarée au fournisseur.
    assert.equal(google.calls.tokenRequest.get("code"), "code-valide");
    assert.equal(google.calls.tokenRequest.get("client_id"), CLIENT_ID);
    assert.equal(google.calls.tokenRequest.get("client_secret"), CLIENT_SECRET);
    assert.equal(google.calls.tokenRequest.get("redirect_uri"), `${ORIGIN}${REDIRECT_URI_PATH}`);
    assert.equal(google.calls.tokenRequest.get("grant_type"), "authorization_code");
    assert.equal(google.calls.profileAuthorization, "Bearer jeton-de-test");

    // ── Le compte ────────────────────────────────────────────────────────────
    const user = readUser(databasePath, "camille@example.test");
    assert.ok(user, "le compte doit exister");
    assert.equal(user.auth_provider, "google");
    assert.equal(user.provider_id, "sub-camille");
    assert.equal(user.display_name, "Camille Martin");
    assert.equal(user.password_hash, null, "un compte Google n'a pas de mot de passe");
    assert.ok(user.email_verified_at, "l'adresse déclarée vérifiée par Google est retenue");

    // Les cookies d'état ne survivent pas au retour.
    const cleared = callback.headers.getSetCookie().filter((entry) => entry.startsWith("qrood_oauth_"));
    assert.equal(cleared.length, 2, "les deux cookies d'état doivent être effacés");
    for (const entry of cleared) {
      assert.match(entry, /Max-Age=0/);
    }

    // ── La session ───────────────────────────────────────────────────────────
    const me = await request("/api/auth/me", { cookie: sessionCookie(callback) });
    const meBody = await me.json();
    assert.equal(me.status, 200, logSink.value);
    assert.equal(meBody.user.email, "camille@example.test");
    assert.equal(meBody.user.emailVerified, true);
    assert.equal(meBody.googleEnabled, true);

    // ── Le retour suivant ────────────────────────────────────────────────────
    // Le compte se retrouve par l'identifiant externe, pas par l'adresse : le second
    // aller ne crée rien et ouvre la session du même compte.
    const again = await startFlow();
    const second = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(again.state)}`,
      { cookie: again.cookie },
    );
    assert.equal(second.status, 302, logSink.value);
    assert.equal(countUsers(databasePath), 1, "une identité connue ne crée pas de second compte");

    // L'adresse du fournisseur peut changer : c'est l'identifiant qui fait foi.
    google.calls.profile = { ...google.calls.profile, email: "camille.martin@example.test" };
    const moved = await startFlow();
    await request(`${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(moved.state)}`, {
      cookie: moved.cookie,
    });
    const relocated = readUser(databasePath, "camille@example.test");
    assert.equal(relocated.email, "camille@example.test", "l'adresse du compte ne suit pas celle de Google");
    assert.equal(countUsers(databasePath), 1);
  } finally {
    await harness.stop();
  }
});

test("connexion Google : le state protège le callback et ne se rejoue pas", async () => {
  const harness = await bootOauth();
  const { databasePath, logSink } = harness;

  try {
    // ── Un state absent ──────────────────────────────────────────────────────
    // Le navigateur ne renvoie jamais là : c'est un callback forgé, par exemple par
    // une page tierce qui tente de connecter sa propre session.
    const forged = await request(`${REDIRECT_URI_PATH}?code=code-valide&state=state-fabrique`);
    assert.equal(forged.status, 302, logSink.value);
    assert.equal(forged.headers.get("location"), "/?oauth=state_invalide");
    assert.equal(countUsers(databasePath), 0, "aucun compte ne doit être créé");

    // ── Un state différent ───────────────────────────────────────────────────
    const flow = await startFlow();
    const mismatched = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=autre-state`,
      { cookie: flow.cookie },
    );
    assert.equal(mismatched.headers.get("location"), "/?oauth=state_invalide");
    assert.equal(countUsers(databasePath), 0);

    // ── Le code du fournisseur ne vaut rien sans le state ────────────────────
    const forgedCode = await request(`${REDIRECT_URI_PATH}?code=code-injecte&state=state-fabrique`, {
      cookie: flow.cookie,
    });
    assert.equal(forgedCode.headers.get("location"), "/?oauth=state_invalide");
    assert.equal(harness.google.calls.tokenRequest, null, "le code ne doit même pas être échangé");

    // ── Un aller comme un autre ──────────────────────────────────────────────
    const wrongCookie = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: flow.cookie.replace(/qrood_oauth_state=[^;]*/, "qrood_oauth_state=autre") },
    );
    assert.equal(wrongCookie.headers.get("location"), "/?oauth=state_invalide");
    assert.equal(countUsers(databasePath), 0);

    // ── Le même aller, deux fois ─────────────────────────────────────────────
    const once = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: flow.cookie },
    );
    assert.equal(once.status, 302, logSink.value);
    assert.ok(sessionCookie(once), "le premier retour doit ouvrir la session");

    // Le cookie d'état est effacé par la réponse : le navigateur n'a plus rien à
    // renvoyer, donc le même couple rejoué ne mène nulle part. La preuve est tenue
    // par le navigateur, pas par le serveur — un `state` n'est pas un jeton à usage
    // unique, c'est un secret partagé avec la seule machine qui a ouvert le flux.
    const replayed = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: sessionCookie(once) },
    );
    assert.equal(replayed.headers.get("location"), "/?oauth=state_invalide");
    assert.equal(sessionCookie(replayed), "", "aucune seconde session ne doit être ouverte");
    assert.equal(countUsers(databasePath), 1);

    // ── Un refus de Google, un code, et rien d'autre ─────────────────────────
    const abandoned = await startFlow();
    const refused = await request(
      `${REDIRECT_URI_PATH}?error=access_denied&state=${encodeURIComponent(abandoned.state)}`,
      { cookie: abandoned.cookie },
    );
    assert.equal(refused.headers.get("location"), "/?oauth=refus");
    assert.equal(sessionCookie(refused), "");

    const withoutCode = await startFlow();
    const missing = await request(
      `${REDIRECT_URI_PATH}?state=${encodeURIComponent(withoutCode.state)}`,
      { cookie: withoutCode.cookie },
    );
    assert.equal(missing.headers.get("location"), "/?oauth=code_manquant");
    assert.equal(sessionCookie(missing), "");
  } finally {
    await harness.stop();
  }
});

test("connexion Google : une identité non prouvée ne crée aucun compte", async () => {
  const harness = await bootOauth({ profile: { email_verified: false } });
  const { databasePath, logSink } = harness;

  try {
    // ── Une adresse que Google ne dit pas vérifiée ───────────────────────────
    const unverified = await startFlow();
    const refused = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(unverified.state)}`,
      { cookie: unverified.cookie },
    );
    assert.equal(refused.headers.get("location"), "/?oauth=identite_refusee", logSink.value);
    assert.equal(countUsers(databasePath), 0);
    assert.equal(sessionCookie(refused), "");

    // ── Une adresse absente ou mal formée ────────────────────────────────────
    for (const profile of [{ email: undefined }, { email: "pas-une-adresse" }, { sub: "" }]) {
      harness.google.calls.profile = { ...harness.google.calls.profile, ...profile };
      const flow = await startFlow();
      const response = await request(
        `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
        { cookie: flow.cookie },
      );
      assert.equal(response.headers.get("location"), "/?oauth=identite_refusee", JSON.stringify(profile));
      assert.equal(countUsers(databasePath), 0, JSON.stringify(profile));
    }

    // ── Un fournisseur qui répond mal ────────────────────────────────────────
    harness.google.calls.tokenStatus = 400;
    const broken = await startFlow();
    const exchange = await request(
      `${REDIRECT_URI_PATH}?code=code-expire&state=${encodeURIComponent(broken.state)}`,
      { cookie: broken.cookie },
    );
    assert.equal(exchange.headers.get("location"), "/?oauth=fournisseur_indisponible");
    assert.equal(countUsers(databasePath), 0);

    // Le secret du fournisseur ne doit pas fuiter dans le journal de démarrage, que
    // l'échec vienne du corps renvoyé ou de la pile.
    assert.doesNotMatch(logSink.value, new RegExp(CLIENT_SECRET));
    assert.doesNotMatch(logSink.value, /jeton-de-test/);
  } finally {
    await harness.stop();
  }
});

test("connexion Google : un compte existant n'est jamais repris ni lié", async () => {
  const harness = await bootOauth();
  const { databasePath, logSink } = harness;

  try {
    // Un compte local existe déjà pour cette adresse, avec un mot de passe que seul
    // son titulaire connaît. Lui rendre la session sur la seule foi d'une adresse
    // commune reviendrait à céder le compte à quiconque possède un compte Google.
    const registered = await request("/api/auth/register", {
      method: "POST",
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { displayName: "Camille Martin", email: "camille@example.test", password: PASSWORD },
    });
    assert.equal(registered.status, 201, logSink.value);

    const flow = await startFlow();
    const refused = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: flow.cookie },
    );
    assert.equal(refused.headers.get("location"), "/?oauth=email_deja_utilise", logSink.value);
    assert.equal(sessionCookie(refused), "");

    // Le compte est intact : ni converti, ni lié, ni mot de passe remplacé.
    const user = readUser(databasePath, "camille@example.test");
    assert.equal(user.auth_provider, "local");
    assert.equal(user.provider_id, null);
    assert.ok(user.password_hash, "le mot de passe existant doit rester en place");

    // ── Un mot de passe ne se déduit jamais d'un compte sans mot de passe ─────
    const passwordless = harness.google.calls.profile;
    harness.google.calls.profile = { ...passwordless, email: "nouveau@example.test" };
    const created = await startFlow();
    await request(`${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(created.state)}`, {
      cookie: created.cookie,
    });
    assert.ok(readUser(databasePath, "nouveau@example.test"));

    // Un compte créé par Google n'a pas de mot de passe : la connexion par mot de
    // passe répond comme pour une adresse inconnue, sans révéler que le compte existe.
    const wrongPassword = await request("/api/auth/login", {
      method: "POST",
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { email: "nouveau@example.test", password: PASSWORD },
    });
    assert.equal(wrongPassword.status, 401, logSink.value);
    assert.equal(await errorCode(wrongPassword), "invalid_credentials");

    const noPassword = await request("/api/auth/login", {
      method: "POST",
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { email: "nouveau@example.test", password: "" },
    });
    assert.equal(noPassword.status, 400);
  } finally {
    await harness.stop();
  }
});

test("connexion Google : la destination de retour reste sur le site", async () => {
  const harness = await bootOauth();
  const { logSink } = harness;

  try {
    // ── Un chemin du site est accepté tel quel ───────────────────────────────
    const kept = await startFlow(`?next=${encodeURIComponent("/compte")}`);
    const keptReturn = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(kept.state)}`,
      { cookie: kept.cookie },
    );
    assert.equal(keptReturn.status, 302, logSink.value);
    assert.equal(keptReturn.headers.get("location"), "/compte");

    // ── Tout ce qui sort du site est ramené à la racine ──────────────────────
    const attempts = [
      "https://exemple.test/pirate",
      "//exemple.test/pirate",
      "/\\exemple.test/pirate",
      "javascript:alert(1)",
      "compte",
      "",
    ];
    for (const next of attempts) {
      const flow = await startFlow(`?next=${encodeURIComponent(next)}`);
      const response = await request(
        `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
        { cookie: flow.cookie },
      );
      const location = response.headers.get("location");
      assert.equal(location, "/", `next=${next} doit revenir à la racine`);
      // Le `Location` est relatif : il ne peut pas désigner un autre site, quelle que
      // soit la façon dont le navigateur le résout.
      assert.ok(location.startsWith("/") && !location.startsWith("//"), location);
    }

    // ── La même garantie sur l'échec ─────────────────────────────────────────
    const hostile = await startFlow(`?next=${encodeURIComponent("https://exemple.test/pirate")}`);
    const failure = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=state-fabrique`,
      { cookie: hostile.cookie },
    );
    assert.equal(failure.headers.get("location"), "/?oauth=state_invalide");
  } finally {
    await harness.stop();
  }
});

test("connexion Google : sans identifiants, la route n'existe pas", async () => {
  const harness = await bootOauth({ configured: false });
  const { databasePath, logSink } = harness;

  try {
    const start = await request("/api/auth/google/start", {
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
    });
    assert.equal(start.status, 404, logSink.value);
    assert.equal(await errorCode(start), "oauth_unavailable");
    assert.equal(start.headers.get("location"), null, "aucune redirection vers un fournisseur");

    const callback = await request(`${REDIRECT_URI_PATH}?code=code-valide&state=state`);
    assert.equal(callback.status, 404);
    assert.equal(await errorCode(callback), "oauth_unavailable");
    assert.equal(countUsers(databasePath), 0);

// L'interface n'a rien à afficher : elle ne demande pas un bouton pour un
    // fournisseur qui n'existe pas.
    const me = await (await request("/api/auth/me")).json();
    assert.equal(me.googleEnabled, false);

    // Délier, en revanche, ne demande rien au fournisseur. Le garder fermé derrière la
    // même configuration piégerait un lien qui subsiste après la disparition des
    // identifiants : impossible à retirer, donc un compte verrouillé sur un compte
    // qu'on ne peut plus rejoindre.
    const account = await registerLocal("camille@example.test");
    const unlink = await accountAction("/api/account/google/unlink", account, { currentPassword: PASSWORD });
    assert.equal(unlink.status, 409, logSink.value);
    assert.equal(await errorCode(unlink), "google_not_linked");
    assert.ok(readUser(databasePath, "camille@example.test"), "le compte reste joignable");
  } finally {
    await harness.stop();
  }
});

test("la migration du schéma accepte une base d'avant la connexion Google", async () => {
  PORT = await getFreePort();
  ORIGIN = `http://localhost:${PORT}`;
  const directory = mkdtempSync(path.join(os.tmpdir(), "qrood-oauth-test-"));
  const databasePath = path.join(directory, "test.sqlite");
  const logSink = { value: "" };

  // La base est écrite avant le tout premier démarrage : c'est la seule façon que la
  // migration vois l'ancien schéma, `password_hash` en `NOT NULL` et sans aucune
  // colonne de fournisseur.
  const legacy = new DatabaseSync(databasePath);
  legacy.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      display_name TEXT NOT NULL,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL
    ) STRICT;
  `);
  legacy.prepare(`
    INSERT INTO users (display_name, email, password_hash, created_at)
    VALUES ('Camille Martin', 'avant@example.test', 'scrypt$16384$8$1$sel$empreinte', ?)
  `).run(Date.now());
  legacy.close();

  let server = await startServer(buildChildEnvironment({ QROOD_DB_PATH: databasePath }), logSink);
  try {
    assert.doesNotMatch(logSink.value, /SQL logic error|already exists/i, logSink.value);

    // ── Le compte antérieur est intact ───────────────────────────────────────
    const kept = readUser(databasePath, "avant@example.test");
    assert.equal(kept.display_name, "Camille Martin");
    assert.equal(kept.password_hash, "scrypt$16384$8$1$sel$empreinte");
    assert.equal(kept.auth_provider, "local", "un compte d'avant reste local");
    assert.equal(kept.provider_id, null);

    // ── `password_hash` n'est plus obligatoire ───────────────────────────────
    const database = new DatabaseSync(databasePath);
    try {
      database.exec("PRAGMA foreign_keys = ON;");
      const declared = database.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").get().sql;
      assert.doesNotMatch(declared, /password_hash TEXT NOT NULL/, "la contrainte doit être levée");

      database.prepare(`
        INSERT INTO users (display_name, email, password_hash, created_at, email_verified_at, auth_provider, provider_id)
        VALUES (?, ?, ?, ?, ?, 'google', ?)
      `).run("Sans mot de passe", "google@example.test", null, Date.now(), Date.now(), "sub-x");
      const created = database.prepare("SELECT password_hash FROM users WHERE email = ?").get("google@example.test");
      assert.equal(created.password_hash, null, "un compte sans mot de passe doit pouvoir être écrit");

      // Les sept tables qui référencent `users` doivent l'avoir retrouvé : c'est le
      // risque propre à une table recréée, pas à une simple colonne ajoutée.
      assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), [], "les références doivent rester valides");
      const indexes = database
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'users'")
        .all()
        .map((row) => row.name);
      assert.ok(indexes.includes("idx_users_provider_identity"), "l'index de fournisseur doit être reposé");
      assert.ok(indexes.includes("idx_users_pending_email"), "l'index d'adresse en attente doit être reposé");
    } finally {
      database.close();
    }

    // ── Le serveur fonctionne toujours ───────────────────────────────────────
    const registered = await request("/api/auth/register", {
      method: "POST",
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { displayName: "Nouvelle", email: "nouvelle@example.test", password: PASSWORD },
    });
    assert.equal(registered.status, 201, logSink.value);
    const session = sessionCookie(registered);
    const me = await request("/api/auth/me", { cookie: session });
    assert.equal(me.status, 200, logSink.value);
    assert.equal((await me.json()).user.email, "nouvelle@example.test");

    // ── La migration ne se rejoue pas ────────────────────────────────────────
    await stopServer(server);
    server = await startServer(buildChildEnvironment({ QROOD_DB_PATH: databasePath }), logSink);
    assert.doesNotMatch(logSink.value, /SQL logic error|already exists/i, logSink.value);
    // Les trois comptes : celui d'avant, celui écrit sans mot de passe, celui inscrit
    // par l'API.
    assert.equal(countUsers(databasePath), 3);
  } finally {
    await stopServer(server);
    rmSync(directory, { recursive: true, force: true });
  }
});
test("compte : une identité Google se relie sans remplacer le mot de passe", async () => {
  const harness = await bootOauth({ profile: { sub: "sub-linked", email: "google-camille@example.test" } });
  const { databasePath, logSink } = harness;

  try {
    const account = await registerLocal("camille@example.test");
    assert.equal(account.response.status, 201, logSink.value);
    assert.equal(account.me.hasPassword, true);
    assert.equal(account.me.googleLinked, false);
    assert.equal(account.me.googleEnabled, true);

// ── Le mot de passe d'abord ───────────────────────────────────────────────
    const withoutToken = await startAccountFlow("/api/account/google/link", { session: account.session }, {
      currentPassword: PASSWORD,
    });
    assert.equal(withoutToken.response.status, 403);
    assert.equal(await errorCode(withoutToken.response), "invalid_csrf_token");

    const withoutPassword = await startAccountFlow("/api/account/google/link", account, {});
    assert.equal(withoutPassword.response.status, 400);
    assert.equal(await errorCode(withoutPassword.response), "current_password_required");

    const wrongPassword = await startAccountFlow("/api/account/google/link", account, {
      currentPassword: "MotDePasseFaux789",
    });
    assert.equal(wrongPassword.response.status, 403);
    assert.equal(await errorCode(wrongPassword.response), "invalid_current_password");
    assert.equal(readUser(databasePath, "camille@example.test").auth_provider, "local", "rien ne doit avoir été lié");

    // ── L'aller-retour ────────────────────────────────────────────────────────
    const flow = await startAccountFlow("/api/account/google/link", account, { currentPassword: PASSWORD });
    assert.equal(flow.response.status, 200, logSink.value);
    assert.equal(flow.url.origin, harness.google.origin);
    assert.ok(flow.state && flow.state.length >= 32);

    const returnCookie = flow.response.headers.getSetCookie().find((entry) => entry.startsWith("qrood_oauth_next="));
    assert.ok(returnCookie);
    assert.match(returnCookie, /HttpOnly/);
    // La destination d'une liaison n'est pas négociable : elle revient à la page du
    // compte, quoi que la requête demande.
    const destination = Buffer.from(returnCookie.split("=", 2)[1].split(";")[0], "base64url").toString("utf8");
    assert.equal(destination, "/compte");

    const callback = await finishAccountFlow(flow);
    assert.equal(callback.status, 302, logSink.value);
    assert.equal(callback.headers.get("location"), "/compte?oauth=liaison_reussie");
    assert.equal(sessionCookie(callback), "", "une liaison ne change pas de session");

    // ── Le compte ─────────────────────────────────────────────────────────────
    const user = readUser(databasePath, "camille@example.test");
    assert.equal(user.auth_provider, "google");
    assert.equal(user.provider_id, "sub-linked");
    assert.ok(user.password_hash, "le mot de passe doit rester en place");
    assert.equal(
      readUser(databasePath, "google-camille@example.test"),
      undefined,
      "l'adresse de Google n'entre pas dans le compte",
    );

    const me = await (await request("/api/auth/me", { cookie: account.session })).json();
    assert.equal(me.googleLinked, true);
    assert.equal(me.hasPassword, true);

    // ── La connexion Google ouvre ce compte, et lui seul ───────────────────────
    const login = await startFlow();
    const opened = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(login.state)}`,
      { cookie: login.cookie },
    );
    assert.equal(opened.status, 302, logSink.value);
    const openedMe = await (await request("/api/auth/me", { cookie: sessionCookie(opened) })).json();
    assert.equal(openedMe.user.email, "camille@example.test", "c'est le compte relié qui s'ouvre");
    assert.equal(countUsers(databasePath), 1);

    // ── Relier deux fois ──────────────────────────────────────────────────────
    const again = await startAccountFlow("/api/account/google/link", account, { currentPassword: PASSWORD });
    assert.equal(again.response.status, 409);
    assert.equal(await errorCode(again.response), "google_already_linked");
  } finally {
    await harness.stop();
  }
});

test("compte : une liaison ne s'achève ni sans session ni sur une autre session", async () => {
  const harness = await bootOauth({ profile: { sub: "sub-partage", email: "google-camille@example.test" } });
  const { databasePath, logSink } = harness;

  try {
    const camille = await registerLocal("camille@example.test");
    const malik = await registerLocal("malik@example.test");

    const flow = await startAccountFlow("/api/account/google/link", camille, { currentPassword: PASSWORD });
    assert.equal(flow.response.status, 200, logSink.value);

    // ── La session a disparu entre l'aller et le retour ───────────────────────
    const anonymous = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: flow.flowCookie },
    );
    assert.equal(anonymous.status, 302);
    assert.equal(anonymous.headers.get("location"), "/compte?oauth=session_expiree");
    assert.equal(sessionCookie(anonymous), "", "aucune session ne doit être ouverte");

    // ── Une autre session, après la fermeture de la première ──────────────────
    const logout = await request("/api/auth/logout", {
      method: "POST",
      cookie: camille.session,
      csrf: camille.csrf,
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
    });
    assert.equal(logout.status, 200, logSink.value);

    const mixed = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: `${malik.session}; ${flow.flowCookie}` },
    );
    assert.equal(mixed.status, 302);
    assert.equal(mixed.headers.get("location"), "/compte?oauth=session_expiree");
    assert.equal(sessionCookie(mixed), "", "la session de Malik ne doit pas être réémise");

    // ── Rien n'a été lié, ni d'un côté ni de l'autre ───────────────────────────
    assert.equal(readUser(databasePath, "camille@example.test").auth_provider, "local");
    assert.equal(readUser(databasePath, "malik@example.test").auth_provider, "local");
    assert.equal(countUsers(databasePath), 2);
  } finally {
    await harness.stop();
  }
});

test("compte : la double authentification prime sur la liaison et la connexion Google", async () => {
  const harness = await bootOauth({ profile: { sub: "sub-2fa-a", email: "camille@example.test" } });
  const { databasePath, logSink } = harness;

  try {
    // ── Protégé avant d'avoir lié ─────────────────────────────────────────────
    const account = await registerLocal("camille@example.test");
    const enrolled = await enrollTwoFactor(account);
    assert.equal(enrolled.setup.status, 200, logSink.value);
    assert.equal(enrolled.confirmed.status, 200, logSink.value);

const link = await startAccountFlow("/api/account/google/link", account, { currentPassword: PASSWORD });
    assert.equal(link.response.status, 409);
    assert.equal(await errorCode(link.response), "two_factor_conflict");

    // Rien à prouver par Google tant que rien n'y est relié : la demande est refusée
    // avant même qu'on parle de la double authentification.
    const reauth = await startAccountFlow("/api/account/google/reauth", account, {});
    assert.equal(reauth.response.status, 409);
    assert.equal(await errorCode(reauth.response), "google_not_linked");

    // ── Lié avant d'être protégé : c'est l'ordre réel d'un utilisateur ─────────
    const second = await registerLocal("malik@example.test");
    swapProfile(harness, { sub: "sub-2fa-b", email: "google-malik@example.test" });

    const flow = await startAccountFlow("/api/account/google/link", second, { currentPassword: PASSWORD });
    assert.equal(flow.response.status, 200, logSink.value);
    assert.equal(
      (await finishAccountFlow(flow)).headers.get("location"),
      "/compte?oauth=liaison_reussie",
      logSink.value,
    );
    assert.equal(readUser(databasePath, "malik@example.test").auth_provider, "google");

const protectedAccount = await enrollTwoFactor(second);
    assert.equal(protectedAccount.confirmed.status, 200, logSink.value);

    // Une fois relié et protégé, plus aucun aller-retour par Google : le second facteur
    // est la preuve, et Google ne peut pas s'y substituer.
    const protectedReauth = await startAccountFlow("/api/account/google/reauth", second, {});
    assert.equal(protectedReauth.response.status, 409);
    assert.equal(await errorCode(protectedReauth.response), "two_factor_conflict");

    const login = await startFlow();
    const refused = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(login.state)}`,
      { cookie: login.cookie },
    );
    assert.equal(refused.status, 302);
    assert.equal(refused.headers.get("location"), "/?oauth=deux_facteurs");
    assert.equal(sessionCookie(refused), "", "le second facteur ne se contourne pas par Google");

    // ── Le mot de passe et le code suffisent toujours ─────────────────────────
    const loginWithPassword = await request("/api/auth/login", {
      method: "POST",
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { email: "malik@example.test", password: PASSWORD, twoFactorCode: totpCodeFor(protectedAccount.secret) },
    });
    assert.equal(loginWithPassword.status, 200, logSink.value);
    assert.ok(sessionCookie(loginWithPassword));
  } finally {
    await harness.stop();
  }
});

test("compte : sans mot de passe, une identité Google ne vaut preuve que le temps de la fenêtre", async () => {
  const harness = await bootOauth({ profile: { sub: "sub-google", email: "camille@example.test" } });
  const { databasePath, logSink } = harness;

  try {
    const login = await startFlow();
    const callback = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(login.state)}`,
      { cookie: login.cookie },
    );
    const session = sessionCookie(callback);
const me = await (await request("/api/auth/me", { cookie: session })).json();
    assert.equal(me.hasPassword, false);
    assert.equal(me.googleLinked, true);

    // Le retour du fournisseur vient de prouver le compte : la session est fraîche
    // d'emblée, sans quoi le compte créé par Google ne pourrait rien faire de plus.
    assert.ok(
      readFreshness(databasePath, "camille@example.test") > Date.now(),
      "une session ouverte par Google doit être fraîche",
      logSink.value,
    );

    const sendChange = async (body) =>
      request("/api/account/email", {
        method: "POST",
        cookie: session,
        csrf: me.csrfToken,
        headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
        body,
      });

// ── Délier n'a pas de mot de passe à demander ─────────────────────────────
    // La session est encore fraîche, et c'est bien le dernier accès qui est en jeu :
    // sans mot de passe, il n'y aurait plus rien pour rouvrir le compte.
    const unlink = await accountAction("/api/account/google/unlink", { session, csrf: me.csrfToken }, {});
    assert.equal(unlink.status, 409);
    assert.equal(await errorCode(unlink), "password_required_to_unlink");

    // ── La fenêtre se referme ─────────────────────────────────────────────────
    expireFreshness(databasePath);
    const stale = await sendChange({ email: "nouvelle@example.test" });
    assert.equal(stale.status, 403);
    assert.equal(await errorCode(stale), "reauth_required");

    const staleDelete = await request("/api/account/delete", {
      method: "POST",
      cookie: session,
      csrf: me.csrfToken,
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { confirmation: "SUPPRIMER" },
    });
    assert.equal(staleDelete.status, 403);
    assert.equal(await errorCode(staleDelete), "reauth_required");
    assert.ok(readUser(databasePath, "camille@example.test"), "le compte existe toujours");

    // ── La ré-authentification ne vaut que pour cette identité ─────────────────
    const wrongIdentity = await startAccountFlow("/api/account/google/reauth", { session, csrf: me.csrfToken }, {});
    assert.equal(wrongIdentity.response.status, 200, logSink.value);
    swapProfile(harness, { sub: "sub-autre", email: "autre@example.test" });
    const mismatch = await finishAccountFlow(wrongIdentity);
    assert.equal(mismatch.headers.get("location"), "/compte?oauth=autre_identite");
    assert.equal(readFreshness(databasePath, "camille@example.test"), 0, "aucune preuve n'est accordée");

    // ── La bonne identité ─────────────────────────────────────────────────────
    swapProfile(harness, { sub: "sub-google", email: "camille@example.test" });
    const proof = await startAccountFlow("/api/account/google/reauth", { session, csrf: me.csrfToken }, {});
    assert.equal(proof.response.status, 200, logSink.value);
    assert.equal(proof.url.origin, harness.google.origin);
    const refreshed = await finishAccountFlow(proof);
    assert.equal(refreshed.status, 302, logSink.value);
    assert.equal(refreshed.headers.get("location"), "/compte?oauth=reauth_reussie");
    assert.ok(readFreshness(databasePath, "camille@example.test") > Date.now(), "la fenêtre doit rouvrir");

    const changed = await sendChange({ email: "nouvelle@example.test" });
    assert.ok(changed.status >= 200 && changed.status < 300, `statut inattendu : ${changed.status}\n${logSink.value}`);

    // ── Définir un mot de passe referme la voie sans mot de passe ─────────────
    const setPassword = await request("/api/account/password", {
      method: "POST",
      cookie: session,
      csrf: me.csrfToken,
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { newPassword: "NouveauMotDePasse789" },
    });
    assert.ok(setPassword.status >= 200 && setPassword.status < 300, `${setPassword.status}\n${logSink.value}`);

    const withPassword = await (await request("/api/auth/me", { cookie: session })).json();
    assert.equal(withPassword.hasPassword, true);

    expireFreshness(databasePath);
    const withoutPassword = await sendChange({ email: "encore@example.test" });
    assert.equal(withoutPassword.status, 400);
    assert.equal(
      await errorCode(withoutPassword),
      "current_password_required",
      "une fois un mot de passe défini, la preuve Google ne le remplace plus",
    );

    const withPasswordBody = await sendChange({
      email: "encore@example.test",
      currentPassword: "NouveauMotDePasse789",
    });
    assert.ok(withPasswordBody.status >= 200 && withPasswordBody.status < 300, logSink.value);
  } finally {
    await harness.stop();
  }
});

test("compte : délier Google laisse le mot de passe en place et libère l'identité", async () => {
  const harness = await bootOauth({ profile: { sub: "sub-unlink", email: "google-camille@example.test" } });
  const { databasePath, logSink } = harness;

  try {
    const account = await registerLocal("camille@example.test");

// ── Rien à délier ─────────────────────────────────────────────────────────
    const nothing = await accountAction("/api/account/google/unlink", account, { currentPassword: PASSWORD });
    assert.equal(nothing.status, 409);
    assert.equal(await errorCode(nothing), "google_not_linked");

    const link = await startAccountFlow("/api/account/google/link", account, { currentPassword: PASSWORD });
    assert.equal(link.response.status, 200, logSink.value);
    assert.equal((await finishAccountFlow(link)).headers.get("location"), "/compte?oauth=liaison_reussie");

    // ── Le mot de passe d'abord ───────────────────────────────────────────────
    const withoutToken = await accountAction("/api/account/google/unlink", { session: account.session }, {
      currentPassword: PASSWORD,
    });
    assert.equal(withoutToken.status, 403);
    assert.equal(await errorCode(withoutToken), "invalid_csrf_token");

    const withoutPassword = await accountAction("/api/account/google/unlink", account, {});
    assert.equal(withoutPassword.status, 400);
    assert.equal(await errorCode(withoutPassword), "current_password_required");

    const unlinked = await accountAction("/api/account/google/unlink", account, { currentPassword: PASSWORD });
    assert.equal(unlinked.status, 200, logSink.value);

    const user = readUser(databasePath, "camille@example.test");
    assert.equal(user.auth_provider, "local");
    assert.equal(user.provider_id, null);
    assert.ok(user.password_hash, "le mot de passe reste");

    const me = await (await request("/api/auth/me", { cookie: account.session })).json();
    assert.equal(me.googleLinked, false);
    assert.equal(me.hasPassword, true);

    // ── Le mot de passe ouvre toujours le compte ──────────────────────────────
    const login = await request("/api/auth/login", {
      method: "POST",
      headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      body: { email: "camille@example.test", password: PASSWORD },
    });
    assert.equal(login.status, 200, logSink.value);
    assert.ok(sessionCookie(login));

    // ── L'identité libérée ne reprend pas l'ancien compte ─────────────────────
    // Elle appartient à Google, pas à ce compte : la prochaine connexion crée le sien
    // propre plutôt que de rouvrir un compte dont il ne connaît rien. La page du compte
    // doit le dire avant de laisser partir l'utilisateur.
    const flow = await startFlow();
    const opened = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(flow.state)}`,
      { cookie: flow.cookie },
    );
    assert.equal(opened.status, 302, logSink.value);
    assert.equal(opened.headers.get("location"), "/", logSink.value);
    const openedMe = await (await request("/api/auth/me", { cookie: sessionCookie(opened) })).json();
assert.equal(openedMe.user.email, "google-camille@example.test");
    assert.equal(openedMe.hasPassword, false);
    assert.equal(countUsers(databasePath), 2);
  } finally {
    await harness.stop();
  }
});

test("compte : un cookie d'état forgé ne lie aucune identité à un compte", async () => {
  const harness = await bootOauth({ profile: { sub: "sub-attaquant", email: "attaquant@example.test" } });
  const { databasePath, logSink } = harness;

  try {
    const victim = await registerLocal("victime@example.test");

    // L'attaque : un tiers qui peut poser un cookie à ce nom — un hôte frère du même
    // domaine, un trajet non chiffré, une fuite d'en-tête — écrit lui-même le compte et
    // la session visés, puis fait aboutir le retour du fournisseur avec sa propre
    // identité Google. Sans signature, le serveur lirait ces deux nombres comme
    // venant de la session légitime, et l'identité de l'attaquant deviendrait celle de
    // la victime, définitivement.
    const state = "etat-fabrique-par-un-tiers-0000000000";
    const victimUserId = readUser(databasePath, "victime@example.test").id;
    const victimSessionId = readLatestSessionId(databasePath, victimUserId);
    assert.ok(victimSessionId, "la session de la victime doit exister");

    const forged = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(state)}`,
      {
        cookie: [
          victim.session,
          `qrood_oauth_state=${state}.link.${victimUserId}.${victimSessionId}.signature-inventee`,
        ].join("; "),
      },
    );
    assert.equal(forged.status, 302, logSink.value);
    // La destination ne vient que du cookie de retour, absent ici : un cookie d'état
    // illisible ne peut pas rediriger nulle part en particulier.
    assert.equal(forged.headers.get("location"), "/?oauth=state_invalide");
    assert.equal(harness.google.calls.tokenRequest, null, "le code ne doit même pas être échangé");

    // Le lien est la seule chose que l'attaque cherche à obtenir.
    const user = readUser(databasePath, "victime@example.test");
    assert.equal(user.provider_id, null, "aucune identité ne doit être reliée");
    assert.equal(user.auth_provider, "local");
    const me = await (await request("/api/auth/me", { cookie: victim.session })).json();
    assert.equal(me.googleLinked, false);
    assert.equal(me.googleEnabled, true, "le fournisseur, lui, fonctionne toujours");
    assert.equal(countUsers(databasePath), 1, "aucun compte ne doit être créé");

// ── Réécrire l'intention n'aide pas non plus ──────────────────────────────
    // Le cookie est pris tel quel, signature comprise : changer `link` en `reauth` ne
    // produit pas un cookie plus faible, il le rend illisible, donc sans intention.
    // Ici le cookie de retour, lui, est intact : le retour retombe sur la page du
    // compte, et c'est bien la seule chose qui décide de la destination. Rien n'est
    // lié, et surtout aucune preuve n'est accordée.
    const intent = await startAccountFlow("/api/account/google/link", victim, { currentPassword: PASSWORD });
    assert.equal(intent.response.status, 200, logSink.value);
    const rewritten = intent.flowCookie.replace(".link.", ".reauth.");
    const retagged = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(intent.state)}`,
      { cookie: `${victim.session}; ${rewritten}` },
    );
    assert.equal(retagged.headers.get("location"), "/compte?oauth=state_invalide", logSink.value);
    assert.equal(readUser(databasePath, "victime@example.test").provider_id, null);
    assert.equal(countUsers(databasePath), 1);
  } finally {
    await harness.stop();
  }
});

test("compte : sans mot de passe, la double authentification refuse de s'activer", async () => {
  const harness = await bootOauth({ profile: { sub: "sub-google", email: "camille@example.test" } });
  const { databasePath, logSink } = harness;

  try {
    const login = await startFlow();
    const callback = await request(
      `${REDIRECT_URI_PATH}?code=code-valide&state=${encodeURIComponent(login.state)}`,
      { cookie: login.cookie },
    );
    const session = sessionCookie(callback);
    const me = await (await request("/api/auth/me", { cookie: session })).json();
    assert.equal(me.hasPassword, false);

    const account = { session, csrf: me.csrfToken };

    // ── L'activation est refusée ──────────────────────────────────────────────
    // Google est l'unique porte de ce compte, et la double authentification la ferme
    // partout : la connexion Google, la liaison, la ré-authentification et la
    // déliaison. L'activer ici laisserait un compte que rien ne peut rouvrir, sinon
    // par un e-mail de réinitialisation — pour un compte qui n'a jamais eu de mot de
    // passe. Une session fraîche ne change rien à cela.
    const setup = await accountAction("/api/auth/2fa/setup", account, {});
    assert.equal(setup.status, 409, logSink.value);
    assert.equal(await errorCode(setup), "password_required_before_two_factor");

    const status = await (await request("/api/auth/2fa", { cookie: session })).json();
    assert.equal(status.enrolled, false, "aucun code ne doit avoir été émis");
    assert.equal(status.setupPending, false);

    // ── Délier reste hors de portée, et le dit avant tout detour ──────────────
    // La fenêtre de preuve est close : sans mot de passe, aucun aller par Google ne
    // servirait de toute façon. Le refus doit donc nommer le mot de passe, et non
    // renvoyer vers une preuve impossible à fournir.
    expireFreshness(databasePath);
    const unlink = await accountAction("/api/account/google/unlink", account, {});
    assert.equal(unlink.status, 409, logSink.value);
    assert.equal(await errorCode(unlink), "password_required_to_unlink");
    assert.ok(readUser(databasePath, "camille@example.test"), "le compte existe toujours");

    // ── Un mot de passe, et l'activation redevient possible ───────────────────
    // Il faut d'abord le prouver par Google : c'est le seul facteur que ce compte
    // possède encore, et la fenêtre refermée ne vaut plus rien.
    const proof = await startAccountFlow("/api/account/google/reauth", account, {});
    assert.equal(proof.response.status, 200, logSink.value);
    assert.equal((await finishAccountFlow(proof)).headers.get("location"), "/compte?oauth=reauth_reussie");

    const setPassword = await accountAction("/api/account/password", account, {
      newPassword: "NouveauMotDePasse789",
    });
    assert.ok(setPassword.status >= 200 && setPassword.status < 300, `${setPassword.status}\n${logSink.value}`);

    const allowed = await accountAction("/api/auth/2fa/setup", account, {
      currentPassword: "NouveauMotDePasse789",
    });
    assert.equal(allowed.status, 200, logSink.value);
    const pending = await allowed.json();
    assert.ok(pending.secret && pending.uri, "un secret doit être proposé");
  } finally {
    await harness.stop();
  }
});
