import assert from "node:assert/strict";
import { spawn } from "node:child_process";
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
    // page ne le forge pas, `Lax` seul mode qui accompagne le retour de Google.
    const stateCookie = flow.response.headers.getSetCookie()
      .find((entry) => entry.startsWith("qrood_oauth_state="));
    assert.ok(stateCookie, "le cookie d'état doit être posé");
    assert.match(stateCookie, /HttpOnly/);
    assert.match(stateCookie, /SameSite=Lax/);
    assert.match(stateCookie, /Path=\/api\/auth\/google/);
    assert.equal(stateCookie.split("=", 2)[1].split(";")[0], flow.state);

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