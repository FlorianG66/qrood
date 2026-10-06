// Vérification en navigateur : boutons d'accueil, section du compte, messages
// d'échec et retour sur la bonne page — Chrome headless piloté par CDP, avec un
// faux fournisseur local qui répond comme Google et Microsoft.
//
//   npm run check:browser
//
// Chrome se cherche dans les emplacements usuels, ou prend `QROOD_CHROME`. Les
// trois ports sont surchargeables (`QROOD_CHECK_APP_PORT`, `QROOD_CHECK_IDP_PORT`,
// `QROOD_CHECK_CDP_PORT`) si l'un d'eux est pris sur la machine.
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const APP_PORT = Number(process.env.QROOD_CHECK_APP_PORT || 39501);
const IDP_PORT = Number(process.env.QROOD_CHECK_IDP_PORT || 39502);
const CDP_PORT = Number(process.env.QROOD_CHECK_CDP_PORT || 9444);
const ORIGIN = `http://127.0.0.1:${APP_PORT}`;
const IDP = `http://127.0.0.1:${IDP_PORT}`;
const PASSWORD = "MotDePasseDeBrowser9!";
const LOCAL_EMAIL = "camille.browser@example.test";

// Le chemin de Chrome est le seul besoin matériel du script. L'ordre compte : le
// chemin Windows explicite d'abord, puis les noms résolus par le PATH (Linux).
const CHROME_CANDIDATES = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "google-chrome",
  "chromium",
  "chrome",
];

const PROFILES = {
  browser_google: {
    sub: "sub-browser-google",
    email: "browser.google@example.test",
    email_verified: true,
    name: "Camille Google",
  },
  browser_microsoft: {
    sub: "sub-browser-microsoft",
    email: "camille.browser@entreprise.test",
    name: "Camille Microsoft",
  },
};

const results = [];
function check(label, condition, detail = "") {
  results.push({ ok: Boolean(condition), label, detail });
  console.log(`${condition ? "ok  " : "FAIL"} ${label}${detail ? ` — ${detail}` : ""}`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ── Faux fournisseur : /authorize redirige tout de suite, /token et /userinfo
// répondent selon le `client_id` reçu. ─────────────────────────────────────────
function startIdp() {
  const byClientId = { browser_google: "browser_google", browser_microsoft: "browser_microsoft" };
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, IDP);
    if (url.pathname === "/authorize") {
      const provider = byClientId[url.searchParams.get("client_id")];
      const target = new URL(url.searchParams.get("redirect_uri"));
      if (!provider) {
        response.writeHead(400).end("client_id inconnu");
        return;
      }
      target.searchParams.set("code", `code-${provider}`);
      target.searchParams.set("state", url.searchParams.get("state"));
      response.writeHead(302, { Location: target.href }).end();
      return;
    }
    if (url.pathname === "/token") {
      let body = "";
      request.on("data", (chunk) => { body += chunk; });
      request.on("end", () => {
        const params = new URLSearchParams(body);
        const provider = (params.get("code") || "").replace(/^code-/, "");
        if (!PROFILES[provider]) {
          response.writeHead(400, { "Content-Type": "application/json" }).end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        response.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ access_token: `at-${provider}`, token_type: "Bearer" }));
      });
      return;
    }
    if (url.pathname === "/userinfo") {
      const provider = (request.headers.authorization || "").replace(/^Bearer /, "").replace(/^at-/, "");
      const profile = PROFILES[provider];
      if (!profile) {
        response.writeHead(401).end();
        return;
      }
      response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(profile));
      return;
    }
    response.writeHead(404).end();
  });
  return new Promise((resolve) => server.listen(IDP_PORT, "127.0.0.1", () => resolve(server)));
}

function childEnvironment() {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.startsWith("QROOD_") || key.startsWith("GOOGLE_") || key.startsWith("MICROSOFT_")) delete environment[key];
  }
  return Object.assign(environment, {
    QROOD_PORT: String(APP_PORT),
    QROOD_HOST: "127.0.0.1",
    QROOD_PUBLIC_ORIGIN: ORIGIN,
    QROOD_IDLE_TIMEOUT_MINUTES: "5",
    NODE_ENV: "test",
    GOOGLE_CLIENT_ID: "browser_google",
    GOOGLE_CLIENT_SECRET: "secret-browser-google",
    QROOD_GOOGLE_AUTH_URL: `${IDP}/authorize`,
    QROOD_GOOGLE_TOKEN_URL: `${IDP}/token`,
    QROOD_GOOGLE_USERINFO_URL: `${IDP}/userinfo`,
    MICROSOFT_CLIENT_ID: "browser_microsoft",
    MICROSOFT_CLIENT_SECRET: "secret-browser-microsoft",
    QROOD_MICROSOFT_AUTH_URL: `${IDP}/authorize`,
    QROOD_MICROSOFT_TOKEN_URL: `${IDP}/token`,
    QROOD_MICROSOFT_USERINFO_URL: `${IDP}/userinfo`,
  });
}

async function startApp(workDir) {
  const databasePath = path.join(workDir, "browser.sqlite");
  const log = { value: "" };
  const child = spawn(process.execPath, [path.join(ROOT, "server.mjs")], {
    cwd: ROOT,
    env: Object.assign(childEnvironment(), { QROOD_DB_PATH: databasePath }),
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => { log.value += chunk; });
  child.stderr.on("data", (chunk) => { log.value += chunk; });
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Le serveur s'est arrêté : ${log.value}`);
    try {
      const response = await fetch(`${ORIGIN}/api/health`);
      if (response.ok) return { child, log, databasePath };
    } catch {
      // Socket pas encore prêt.
    }
    await sleep(50);
  }
  throw new Error(`Démarrage du serveur dépassé : ${log.value}`);
}

// ── Client CDP minimal : WebSocket global de Node, cibles et évaluations. ─────
class Cdp {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.sessionId = null;
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.id && this.pending.has(message.id)) {
        const { resolve, reject } = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) reject(new Error(message.error.message));
        else resolve(message.result);
      }
    });
  }

  static connect(url) {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      socket.addEventListener("open", () => resolve(new Cdp(socket)), { once: true });
      socket.addEventListener("error", () => reject(new Error("WebSocket CDP inaccessible")), { once: true });
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (this.sessionId) message.sessionId = this.sessionId;
    this.socket.send(JSON.stringify(message));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
}

// Un candidat absent du PATH échoue de façon asynchrone : on passe au suivant
// plutôt que de faire échouer le contrôle entier sur un chemin deviné.
function trySpawn(command, args, options) {
  return new Promise((resolve) => {
    const child = spawn(command, args, options);
    child.once("error", (error) => resolve({ child: null, error }));
    child.once("spawn", () => resolve({ child, error: null }));
  });
}

async function startChrome(profileDir) {
  const candidates = process.env.QROOD_CHROME ? [process.env.QROOD_CHROME] : CHROME_CANDIDATES;
  const chromeArguments = [
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
    `--remote-debugging-port=${CDP_PORT}`,
    `--user-data-dir=${profileDir}`,
    "about:blank",
  ];
  for (const candidate of candidates) {
    const { child } = await trySpawn(candidate, chromeArguments, { stdio: ["ignore", "ignore", "pipe"] });
    if (!child) continue;
    const errorLog = { value: "" };
    child.stderr.on("data", (chunk) => { errorLog.value += chunk; });
    const opened = await waitForCdp(child);
    if (opened) return { child, ...opened };
    if (child.exitCode !== null) continue;
    // Le binaire est bien celui-là, mais il n'ouvre pas le port : inutile d'essayer
    // un autre chemin, le message porte sa propre trace.
    throw new Error(`Chrome n'a pas ouvert le port CDP : ${errorLog.value.slice(-800)}`);
  }
  throw new Error(
    `Chrome introuvable parmi : ${candidates.join(", ")}. Installez-le ou définissez QROOD_CHROME avec son chemin complet.`,
  );
}

async function waitForCdp(child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) return null;
    try {
      const response = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
      if (response.ok) {
        const info = await response.json();
        return { version: info.Browser, endpoint: info.webSocketDebuggerUrl };
      }
    } catch {
      // Pas encore en écoute.
    }
    await sleep(100);
  }
  return null;
}

async function openPage(endpoint) {
  const cdp = await Cdp.connect(endpoint);
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  cdp.sessionId = sessionId;
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  return cdp;
}

async function evaluate(cdp, expression) {
  const { result, exceptionDetails } = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (exceptionDetails) throw new Error(`Évaluation refusée : ${exceptionDetails.text} — ${expression}`);
  return result.value;
}

async function waitFor(cdp, expression, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try {
      last = await evaluate(cdp, expression);
      if (last) return last;
    } catch {
      // La page change de document pendant une navigation : on retente.
    }
    await sleep(120);
  }
  throw new Error(`Délai dépassé en attendant : ${expression} (dernière valeur : ${JSON.stringify(last)})`);
}

async function goto(cdp, url) {
  const { errorText } = await cdp.send("Page.navigate", { url });
  if (errorText) throw new Error(`Navigation refusée (${url}) : ${errorText}`);
  await waitFor(cdp, "document.readyState === 'complete'");
}

async function screenshot(cdp, file) {
  const { data } = await cdp.send("Page.captureScreenshot", { format: "png" });
  writeFileSync(file, Buffer.from(data, "base64"));
  return file;
}

// ── Scénario ──────────────────────────────────────────────────────────────────
async function run(cdp, shotsDir) {
  // 1. Un retour d'échec nomme le fournisseur, ouvre la fenêtre de connexion et
  //    nettoie l'adresse pour qu'un rechargement ne répète pas l'annonce.
  await goto(cdp, `${ORIGIN}/?oauth=state_invalide&oauth_provider=microsoft`);
  await waitFor(cdp, "document.querySelector('#authModal') && !document.querySelector('#authModal').hidden");
  const failureText = await evaluate(cdp, "document.body.innerText");
  check("retour d'échec : message au nom du fournisseur", failureText.includes("Connexion Microsoft expirée. Recommencez depuis cette page."), failureText.split("\n").find((line) => line.includes("Connexion")) || "");
  check("retour d'échec : adresse nettoyée", await evaluate(cdp, "location.search") === "", await evaluate(cdp, "location.pathname + location.search"));

  // 2. Les deux boutons sont annoncés par le serveur, jamais écrits dans le HTML.
  await goto(cdp, `${ORIGIN}/`);
  await waitFor(cdp, "document.querySelectorAll('#providerAuth a').length === 2");
  const links = await evaluate(cdp, `[...document.querySelectorAll('#providerAuth a')].map((a) => ({ text: a.textContent, href: a.getAttribute('href'), hidden: a.closest('#providerAuth').hidden }))`);
  check("accueil : les deux boutons sont visibles", links.every((link) => link.hidden === false), JSON.stringify(links.map((l) => l.text)));
  check("accueil : « Continuer avec Google »", links[0]?.text === "Continuer avec Google", links[0]?.text);
  check("accueil : « Continuer avec Microsoft »", links[1]?.text === "Continuer avec Microsoft", links[1]?.text);
  check("accueil : bonnes adresses de départ", links[0]?.href === "/api/auth/google/start" && links[1]?.href === "/api/auth/microsoft/start", `${links[0]?.href} ${links[1]?.href}`);

  // 3. Un compte local, pour ouvrir la section du compte.
  const registration = await evaluate(cdp, `(async () => {
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ displayName: 'Camille', email: ${JSON.stringify(LOCAL_EMAIL)}, password: ${JSON.stringify(PASSWORD)} }),
    });
    return response.status;
  })()`);
  check("inscription locale acceptée", registration === 201, `status ${registration}`);

  // 4. La section du compte : carte visible, aucun lien, formulaire de liaison.
  await goto(cdp, `${ORIGIN}/compte`);
  await waitFor(cdp, "document.querySelector('#providerCard') && !document.querySelector('#providerCard').hidden && document.querySelector('#providerCard h2')");
  const cardText = await evaluate(cdp, "document.querySelector('#providerCard').innerText");
  check("compte : carte fournisseur visible", cardText.includes("Connexion par un compte tiers"));
  check("compte : aucun lien pour l'instant", cardText.includes("Aucune identité reliée"), cardText.split("\n").find((line) => line.includes("identité")));
  const linkForm = await evaluate(cdp, `(() => {
    const form = document.querySelector('form[data-provider="google"][data-provider-action="link"]');
    if (!form) return null;
    return { button: form.querySelector('button').textContent, field: form.querySelector('input[name="currentPassword"]').type };
  })()`);
  check("compte : formulaire de liaison Google", linkForm?.button === "Relier mon compte Google" && linkForm?.field === "password", JSON.stringify(linkForm));

  // 5. La liaison, aller-retour complet depuis la page du compte.
  await evaluate(cdp, `(() => {
    const form = document.querySelector('form[data-provider="google"][data-provider-action="link"]');
    form.querySelector('input[name="currentPassword"]').value = ${JSON.stringify(PASSWORD)};
    form.requestSubmit();
    return true;
  })()`);
  await waitFor(cdp, "location.pathname === '/compte' && location.search === ''");
  await waitFor(cdp, "document.querySelector('#providerCard').innerText.includes('Identité Google reliée')");
  const linkedText = await evaluate(cdp, "document.querySelector('#providerCard').innerText");
  check("compte : retour de liaison sur la page du compte", linkedText.includes("Identité Google reliée : ton compte s'ouvre avec Google"), linkedText.split("\n").find((line) => line.includes("Google")));
  const toast = await evaluate(cdp, "document.body.innerText");
  check("compte : confirmation affichée", toast.includes("Identité Google reliée à ton compte."));
  check("compte : adresse restée sur /compte", (await evaluate(cdp, "location.pathname + location.search")) === "/compte");
  const unlinkForm = await evaluate(cdp, `(() => {
    const form = document.querySelector('form[data-provider="google"][data-provider-action="unlink"]');
    return form ? form.querySelector('button').textContent : null;
  })()`);
  check("compte : déliaison proposée ensuite", unlinkForm === "Délier mon compte Google", unlinkForm);

  // 6. Connexion complète depuis l'accueil, chez l'autre fournisseur : la session
  //    change de compte et le compte se retrouve.
  await goto(cdp, `${ORIGIN}/`);
  await waitFor(cdp, "document.querySelector('[data-oauth-start=\"microsoft\"]')");
  await evaluate(cdp, "document.querySelector('[data-oauth-start=\"microsoft\"]').click()");
  await waitFor(cdp, "location.pathname === '/' && location.search === ''");
  const session = await evaluate(cdp, `(async () => {
    const me = await (await fetch('/api/auth/me')).json();
    return { email: me.user && me.user.email, linked: me.linkedProvider, providers: me.providers.map((p) => p.id).join(','), verified: me.user && me.user.emailVerified };
  })()`);
  check("connexion Microsoft : session ouverte", session.email === PROFILES.browser_microsoft.email, JSON.stringify(session));
  check("connexion Microsoft : identité reliée", session.linked === "microsoft", session.linked);
  check("connexion Microsoft : adresse non certifiée", session.verified === false, String(session.verified));
  check("accueil : les deux boutons restent annoncés", session.providers === "google,microsoft", session.providers);

  await goto(cdp, `${ORIGIN}/compte`);
  await waitFor(cdp, "document.querySelector('#providerCard').innerText.includes('Identité Microsoft reliée')");
  const microsoftCard = await evaluate(cdp, "document.querySelector('#providerCard').innerText");
  check("compte : état Microsoft affiché", microsoftCard.includes("Identité Microsoft reliée"), microsoftCard.split("\n").find((line) => line.includes("Microsoft")));
  const proofButton = await evaluate(cdp, `(() => {
    const button = document.querySelector('button[data-provider-action="reauth"]');
    return button ? button.textContent : null;
  })()`);
  check("compte : preuve proposée sans mot de passe", proofButton === "Prouver mon identité avec Microsoft", proofButton);
  const passwordGroups = await evaluate(cdp, `['emailPasswordGroup', 'oldPasswordGroup', 'deletePasswordGroup']
    .map((id) => ({ id, hidden: document.getElementById(id).hidden }))`);
  check("compte : champs de mot de passe masqués sans mot de passe", passwordGroups.every((group) => group.hidden === true), JSON.stringify(passwordGroups));
  const secondLink = await evaluate(cdp, `(() => {
    const form = document.querySelector('form[data-provider][data-provider-action="link"]');
    return form ? form.innerText : null;
  })()`);
  check("compte : pas de seconde liaison proposée", secondLink === null, String(secondLink));
  return screenshot(cdp, path.join(shotsDir, "compte-microsoft.png"));
}

const workDir = mkdtempSync(path.join(tmpdir(), "qrood-browser-"));
const profileDir = path.join(workDir, "chrome-profile");
mkdirSync(profileDir, { recursive: true });
const shotsDir = path.join(workDir, "shots");
mkdirSync(shotsDir, { recursive: true });

let idp;
let app;
let chrome;
try {
  idp = await startIdp();
  app = await startApp(workDir);
  chrome = await startChrome(profileDir);
  console.log(`Chrome : ${chrome.version}`);
  const cdp = await openPage(chrome.endpoint);
  const shot = await run(cdp, shotsDir);
  console.log(`Capture : ${shot}`);
  cdp.socket.close();
} finally {
  chrome?.child.kill();
  if (app?.child && app.child.exitCode === null) app.child.kill();
  idp?.close();
}

const failed = results.filter((result) => !result.ok);
console.log(`\n${results.length - failed.length}/${results.length} vérifications réussies`);
if (failed.length) {
  for (const failure of failed) console.log(`  FAIL ${failure.label}`);
  process.exitCode = 1;
}
