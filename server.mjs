import http from "node:http";
import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { mkdirSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  buildCheckoutParams as buildStripeCheckoutParams,
  computeGraceUntil,
  normalizeStripeStatus,
  readPeriodEnd,
  redactSecrets,
} from "./billing-rules.mjs";
import {
  buildEmailChangeMessage,
  buildResetMessage,
  buildVerificationMessage,
  createApiTransport,
  createOutboxTransport,
  isValidMailAddress,
  validateMailConfiguration,
} from "./mailer.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const scrypt = promisify(scryptCallback);
const PORT = readInteger("QROOD_PORT", 3000, 1, 65535);
const HOST = process.env.QROOD_HOST || "127.0.0.1";
const PUBLIC_ORIGIN = normalizePublicOrigin(process.env.QROOD_PUBLIC_ORIGIN || `http://localhost:${PORT}`);
const IDLE_TIMEOUT_MS = process.env.QROOD_IDLE_TIMEOUT_MS
  ? readInteger("QROOD_IDLE_TIMEOUT_MS", 1_800_000, 0, 86_400_000)
  : readInteger("QROOD_IDLE_TIMEOUT_MINUTES", 30, 0, 1440) * 60_000;
const SESSION_TTL_MS = readInteger("QROOD_SESSION_TTL_HOURS", 168, 1, 720) * 60 * 60 * 1_000;
const DB_PATH = process.env.QROOD_DB_PATH || path.join(ROOT, "data", "qrood.sqlite");
const TRUST_PROXY = process.env.QROOD_TRUST_PROXY === "true";
const SECURE_COOKIES = process.env.QROOD_SECURE_COOKIES
  ? process.env.QROOD_SECURE_COOKIES === "true"
  : PUBLIC_ORIGIN.startsWith("https://");
const ALLOW_PRIVATE_DESTINATIONS = process.env.QROOD_ALLOW_PRIVATE_DESTINATIONS === "true";
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const MAX_JSON_BYTES = 64 * 1024;
const MAX_QR_JSON_BYTES = 384 * 1024;
const MAX_LOGO_LENGTH = 220_000;
const MAX_STYLE_MARGIN = 8;
const DEFAULT_STYLE_MARGIN = 4;
const MIN_LOGO_SIZE_PCT = 18;
const MAX_LOGO_SIZE_PCT = 30;
const DEFAULT_LOGO_SIZE_PCT = 22;
const STYLE_MODULE_SHAPES = new Set(["square", "rounded", "dot"]);
const STYLE_EYE_SHAPES = new Set(["square", "rounded", "leaf"]);
const LOGO_PATTERN = /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
const MAX_NAME_LENGTH = 80;
const MAX_DESTINATION_LENGTH = 2_048;
const TOKEN_PATTERN = /[A-Za-z0-9_-]{16}/;
const PUBLIC_ID_PATTERN = /^[1-9][0-9]{0,14}$/;
// Deux compteurs par offre : le nombre de QR codes stockés et le nombre de QR
// codes actifs en simultané. `null` signifie « illimité ».
const PLAN_CATALOG = {
  decouverte: {
    key: "decouverte",
    label: "Découverte",
    maxQrcodes: 5,
    maxActive: 1,
    statsDays: 30,
    customization: "base",
    support: null,
  },
  pro: {
    key: "pro",
    label: "Pro",
    maxQrcodes: 25,
    maxActive: null,
    statsDays: 365,
    customization: "avancee",
    support: "standard",
  },
  ultra: {
    key: "ultra",
    label: "Ultra",
    maxQrcodes: null,
    maxActive: null,
    statsDays: 730,
    customization: "complete",
    support: "prioritaire",
  },
};
const DEFAULT_PLAN = "decouverte";
// Seules Pro et Ultra sont facturables. Découverte est gratuite, donc elle n'a
// pas de Price Stripe : le webhook refuse alors de lui attribuer un accès payant.
const BILLABLE_PLANS = ["pro", "ultra"];
const STRIPE_PRICE_ENV = {
  pro: "STRIPE_PRICE_PRO",
  ultra: "STRIPE_PRICE_ULTRA",
};
const STRIPE_SECRET_KEY = readStripeEnv("STRIPE_SECRET_KEY");
const STRIPE_WEBHOOK_SECRET = readStripeEnv("STRIPE_WEBHOOK_SECRET");
const STRIPE_PRICES = Object.fromEntries(
  BILLABLE_PLANS.map((plan) => [plan, readStripeEnv(STRIPE_PRICE_ENV[plan])])
);
const STRIPE_PRICE_BY_ID = new Map(
  Object.entries(STRIPE_PRICES).filter(([, priceId]) => priceId).map(([plan, priceId]) => [priceId, plan])
);
// Sans clé secrète, aucun appel réseau n'est possible : la billetterie reste
// inerte et le serveur démarre normalement, ce qui garde les tests et la
// développement local hors ligne fonctionnels.
const BILLING_ENABLED = Boolean(STRIPE_SECRET_KEY);
const BILLING_CONFIGURED = BILLING_ENABLED && BILLABLE_PLANS.some((plan) => STRIPE_PRICES[plan]);
const BILLING_WEBHOOKS_ENABLED = BILLING_ENABLED && Boolean(STRIPE_WEBHOOK_SECRET);
const STRIPE_API_VERSION = "2025-10-29.clover";
let stripeClient = null;
// Palier de personnalisation par offre, avec l'offre minimale exigée : le refus
// doit nommer le palier à atteindre plutôt qu'un « 402 » nu.
const STYLE_ENTITLEMENTS = {
  base: {
    requiredLabel: "Découverte",
    moduleShapes: ["square"],
    eyeShapes: ["square"],
    gradient: false,
    logo: false,
  },
  avancee: {
    requiredLabel: "Pro",
    moduleShapes: ["square", "rounded"],
    eyeShapes: ["square", "rounded"],
    gradient: true,
    logo: false,
  },
  complete: {
    requiredLabel: "Ultra",
    moduleShapes: [...STYLE_MODULE_SHAPES],
    eyeShapes: [...STYLE_EYE_SHAPES],
    gradient: true,
    logo: true,
  },
};
const MAX_SCAN_EVENTS_PER_QR = 100_000;
const MAX_REFERRER_HOSTS_PER_QRCODE = 100;
const OTHER_REFERRER = "(autre)";
const MAX_SCAN_RETENTION_DAYS = 365;
const SCAN_DEDUPE_WINDOW_MS = 5 * 60 * 1_000;
const MAX_SESSIONS_PER_USER = 10;
const MAX_RATE_BUCKETS = 10_000;

// Adresses e-mail : deux usages distincts, deux jetons distincts, une seule
// table. La confirmation prouve que la boîte existe, la réinitialisation prouve
// qu'on la contrôle : les deux liens sont donc consommés séparément, pour que
// voler un lien de réinitialisation ne valide pas une adresse par surprise.
const VERIFICATION_PURPOSE = "email_verification";
const RESET_PURPOSE = "password_reset";
// Le changement d'adresse a son propre but : son lien ne vaut ni confirmation
// ni réinitialisation. Il ne s'applique qu'à l'adresse en attente, donc le
// voler ne donne accès à rien, mais le séparer évite qu'un lien de
// réinitialisation interprete une adresse jamais prouvée comme confirmée.
const EMAIL_CHANGE_PURPOSE = "email_change";
const VERIFICATION_TOKEN_TTL_MS = readInteger("QROOD_VERIFICATION_TOKEN_HOURS", 24, 1, 168) * 60 * 60 * 1_000;
const RESET_TOKEN_TTL_MS = readInteger("QROOD_RESET_TOKEN_MINUTES", 60, 5, 1_440) * 60 * 1_000;
const EMAIL_CHANGE_TOKEN_TTL_MS = readInteger("QROOD_EMAIL_CHANGE_TOKEN_MINUTES", 60, 5, 1_440) * 60 * 1_000;
// Plancher entre deux envois pour une même adresse et un même but : il
// dépend de l'heure du dernier envoi, donc il survit au redémarrage.
const MAIL_RESEND_DELAY_MS = readInteger("QROOD_MAIL_RESEND_DELAY_SECONDS", 60, 0, 3_600) * 1_000;
const MAIL_TRANSPORT = (readStripeEnv("MAIL_TRANSPORT") || "outbox").toLowerCase();
const MAIL_FROM = readStripeEnv("MAIL_FROM") || "no-reply@qrood.example";
const MAIL_OUTBOX_DIRECTORY = process.env.QROOD_MAIL_OUTBOX_DIR
  || path.join(DB_PATH === ":memory:" ? path.join(ROOT, "data") : path.dirname(DB_PATH), "outbox");
const MAIL_API_URL = readStripeEnv("MAIL_API_URL");
const MAIL_API_KEY = readStripeEnv("MAIL_API_KEY");

if (IS_PRODUCTION && !PUBLIC_ORIGIN.startsWith("https://")) {
  throw new Error("QROOD_PUBLIC_ORIGIN doit utiliser HTTPS en production.");
}
if (IS_PRODUCTION && PUBLIC_ORIGIN.startsWith("https://") && !SECURE_COOKIES) {
  throw new Error("QROOD_SECURE_COOKIES doit être activé en production.");
}

// La vérification d'adresse et la réinitialisation de mot de passe passent par
// un envoi d'e-mail : sans transport configuré, un utilisateur ne peut ni
// confirmer son compte ni récupérer son accès. En production c'est un refus de
// démarrer, pas une dégradation silencieuse.
const mailConfigurationError = validateMailConfiguration({
  transport: MAIL_TRANSPORT,
  apiUrl: MAIL_API_URL,
  apiKey: MAIL_API_KEY,
  production: IS_PRODUCTION,
});
if (mailConfigurationError) throw new Error(mailConfigurationError);

if (MAIL_TRANSPORT === "api" && !isValidMailAddress(MAIL_FROM)) {
  throw new Error("QROOD_MAIL_FROM doit être une adresse e-mail valide, sans nom d'affichage.");
}

const mailer = MAIL_TRANSPORT === "api"
  ? createApiTransport({ url: MAIL_API_URL, apiKey: MAIL_API_KEY, from: MAIL_FROM, fetch })
  : createOutboxTransport({ directory: MAIL_OUTBOX_DIRECTORY, writeFile, mkdir: mkdirSync });

if (DB_PATH !== ":memory:") {
  mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

const db = new DatabaseSync(DB_PATH);
const SCHEMA_VERSION = 4;
// La version est lue avant toute écriture : c'est elle qui distingue une base
// existante d'une base neuve, et donc une migration d'un simple rattrapage.
const previousSchemaVersion = Number(db.prepare("PRAGMA user_version").get()?.user_version || 0);
db.exec("PRAGMA foreign_keys = ON;");
db.exec("PRAGMA busy_timeout = 5000;");
if (DB_PATH !== ":memory:") db.exec("PRAGMA journal_mode = WAL;");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    pending_email TEXT
  ) STRICT;

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    user_agent TEXT NOT NULL
  ) STRICT;

  CREATE TABLE IF NOT EXISTS qrcodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_token TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('link', 'contact')),
    destination TEXT,
    contact_data TEXT,
    vcard TEXT,
    foreground TEXT NOT NULL,
    background TEXT NOT NULL,
    legacy_key TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    qrcode_id INTEGER NOT NULL REFERENCES qrcodes(id) ON DELETE CASCADE,
    scanned_at INTEGER NOT NULL,
    device_type TEXT NOT NULL,
    referrer_host TEXT
  ) STRICT;

  CREATE TABLE IF NOT EXISTS scan_rollups (
    qrcode_id INTEGER NOT NULL REFERENCES qrcodes(id) ON DELETE CASCADE,
    day TEXT NOT NULL,
    device_type TEXT NOT NULL,
    referrer_host TEXT NOT NULL,
    scan_count INTEGER NOT NULL,
    last_scan_at INTEGER NOT NULL,
    PRIMARY KEY (qrcode_id, day, device_type, referrer_host)
  ) STRICT;

  CREATE INDEX IF NOT EXISTS idx_scan_rollups_qrcode_day
    ON scan_rollups(qrcode_id, day);

  CREATE INDEX IF NOT EXISTS idx_scan_rollups_qrcode_referrer
    ON scan_rollups(qrcode_id, referrer_host);

  CREATE TRIGGER IF NOT EXISTS scan_events_rollup_insert
  AFTER INSERT ON scan_events
  BEGIN
    INSERT INTO scan_rollups (
      qrcode_id, day, device_type, referrer_host, scan_count, last_scan_at
    )
    VALUES (
      NEW.qrcode_id,
      date(NEW.scanned_at / 1000, 'unixepoch'),
      NEW.device_type,
      COALESCE(NEW.referrer_host, ''),
      1,
      NEW.scanned_at
    )
    ON CONFLICT(qrcode_id, day, device_type, referrer_host)
    DO UPDATE SET
      scan_count = scan_count + 1,
      last_scan_at = MAX(last_scan_at, excluded.last_scan_at);
  END;

  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
  CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS idx_qrcodes_user ON qrcodes(user_id, updated_at DESC);
  CREATE INDEX IF NOT EXISTS idx_scans_qrcode_time ON scan_events(qrcode_id, scanned_at DESC);

  CREATE TABLE IF NOT EXISTS billing_customers (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan TEXT NOT NULL CHECK(plan IN ('decouverte','pro','ultra')),
    status TEXT NOT NULL CHECK(status IN ('active','trialing','past_due','canceled',
                  'unpaid','paused','incomplete','incomplete_expired')),
    stripe_customer_id TEXT NOT NULL,
    stripe_subscription_id TEXT UNIQUE,
    stripe_price_id TEXT NOT NULL,
    current_period_end INTEGER,
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0 CHECK(cancel_at_period_end IN (0,1)),
    grace_until INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT;

  -- Une seule subscription non terminale par compte : c'est la garantie
  -- structurelle contre le double facturage.
  CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_live_user
    ON subscriptions(user_id)
    WHERE status NOT IN ('canceled','incomplete_expired');

  CREATE TABLE IF NOT EXISTS stripe_events (
    event_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    received_at INTEGER NOT NULL
  ) STRICT;

  -- Jeton à usage unique, jamais stocké en clair : seul son SHA-256 est
  -- conservé, comme pour les sessions. La colonne used_at rend la
  -- consommation vérifiable en base, et non seulement dans le code appelant.
  CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK(purpose IN ('email_verification','password_reset','email_change')),
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
  ) STRICT;

  CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id, purpose);
  CREATE INDEX IF NOT EXISTS idx_auth_tokens_expiry ON auth_tokens(expires_at);

  PRAGMA user_version = ${SCHEMA_VERSION};
`);

function ensureQrcodeLegacyKey() {
  const columns = db.prepare("PRAGMA table_info(qrcodes)").all();
  if (!columns.some((column) => column.name === "legacy_key")) {
    db.exec("ALTER TABLE qrcodes ADD COLUMN legacy_key TEXT");
  }
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_qrcodes_user_legacy_key ON qrcodes(user_id, legacy_key)");
}

function ensureQrcodeStyleColumns() {
  const columns = db.prepare("PRAGMA table_info(qrcodes)").all();
  const names = new Set(columns.map((column) => column.name));
  if (!names.has("style")) {
    db.exec("ALTER TABLE qrcodes ADD COLUMN style TEXT");
  }
  if (!names.has("logo")) {
    db.exec("ALTER TABLE qrcodes ADD COLUMN logo TEXT");
  }
}

function ensureQrcodeActivityColumns() {
  const names = new Set(db.prepare("PRAGMA table_info(qrcodes)").all().map((column) => column.name));
  // `is_active` vaut 1 par défaut : les QR codes déjà enregistrés sont actifs,
  // parce qu'ils sont potentiellement imprimés chez des tiers.
  if (!names.has("is_active")) {
    db.exec("ALTER TABLE qrcodes ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1))");
  }
  if (!names.has("inactive_scans")) {
    db.exec("ALTER TABLE qrcodes ADD COLUMN inactive_scans INTEGER NOT NULL DEFAULT 0");
  }
  db.exec("CREATE INDEX IF NOT EXISTS idx_qrcodes_user_active ON qrcodes(user_id, is_active)");
}

function ensureEmailVerificationColumns() {
  const names = new Set(db.prepare("PRAGMA table_info(users)").all().map((column) => column.name));
  if (!names.has("email_verified_at")) {
    db.exec("ALTER TABLE users ADD COLUMN email_verified_at INTEGER");
  }
  // Les comptes créés avant l'exigence de confirmation sont considérés comme
  // vérifiés : leur adresse a servi à tout ce qu'ils ont publié, et les
  // bloquer retroactivement leur retirerait un accès déjà acquis. Le remplissage
  // est lié à la version de schéma, donc il ne rejoue pas sur les comptes
  // inscrits depuis, qui doivent au contraire passer par l'e-mail.
  if (previousSchemaVersion < 2) {
    db.exec("UPDATE users SET email_verified_at = created_at WHERE email_verified_at IS NULL");
  }
}

// L'offre Entreprise, qui se négociait par devis, est retirée du catalogue. La
// table de ses demandes n'a plus de raison d'exister, et la contrainte CHECK des
// abonnements est reprise sans elle. SQLite ne sait pas modifier un CHECK : la
// table est donc recréée à l'identique, lignes conservées, puis l'index d'unicité
// qui interdit le double abonnement est réposé. Rien d'autre n'` + "`" + `est
// modifié, et ` + "`" + `foreign_keys` + "`" + ` n'a pas à être désactivé car aucune table ne référence subscriptions.
function migrateEntreprisePlanRemoval() {
  db.exec("DROP TABLE IF EXISTS enterprise_leads");
  const table = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'subscriptions'").get();
  if (!table?.sql || !table.sql.includes("'entreprise'")) return;
  db.exec(`
    BEGIN;
    CREATE TABLE subscriptions_retablies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL CHECK(plan IN ('decouverte','pro','ultra')),
      status TEXT NOT NULL CHECK(status IN ('active','trialing','past_due','canceled',
                    'unpaid','paused','incomplete','incomplete_expired')),
      stripe_customer_id TEXT NOT NULL,
      stripe_subscription_id TEXT UNIQUE,
      stripe_price_id TEXT NOT NULL,
      current_period_end INTEGER,
      cancel_at_period_end INTEGER NOT NULL DEFAULT 0 CHECK(cancel_at_period_end IN (0,1)),
      grace_until INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;
    INSERT INTO subscriptions_retablies SELECT * FROM subscriptions;
    DROP TABLE subscriptions;
    ALTER TABLE subscriptions_retablies RENAME TO subscriptions;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_live_user
      ON subscriptions(user_id)
      WHERE status NOT IN ('canceled','incomplete_expired');
    COMMIT;
  `);
}

function ensurePendingEmailColumn() {
  const names = new Set(db.prepare("PRAGMA table_info(users)").all().map((column) => column.name));
  if (!names.has("pending_email")) {
    db.exec("ALTER TABLE users ADD COLUMN pending_email TEXT");
  }
  // L'unicité est aussi vérifiée à chaque demande : l'index est la garantie
  // matérielle en cas de deux requêtes simultanées, là où le SELECT voit le même état.
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_pending_email
      ON users(pending_email)
      WHERE pending_email IS NOT NULL
  `);
}

// Le but « email_change » rejoint la liste des causes autorisées pour auth_tokens.
// SQLite ne sait pas modifier un CHECK : comme pour les abonnements, la table est
// recréée à l'identique, jetons conservés, puis les deux index reposés. Un jeton
// de changement d'adresse en cours au moment du déploiement reste donc valable.
function migrateAuthTokenPurposes() {
  const table = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'auth_tokens'").get();
  if (!table?.sql || table.sql.includes("'email_change'")) return;
  db.exec(`
    BEGIN;
    CREATE TABLE auth_tokens_retablies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK(purpose IN ('email_verification','password_reset','email_change')),
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used_at INTEGER
    ) STRICT;
    INSERT INTO auth_tokens_retablies SELECT * FROM auth_tokens;
    DROP TABLE auth_tokens;
    ALTER TABLE auth_tokens_retablies RENAME TO auth_tokens;
    CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id, purpose);
    CREATE INDEX IF NOT EXISTS idx_auth_tokens_expiry ON auth_tokens(expires_at);
    COMMIT;
  `);
}

ensureQrcodeLegacyKey();
ensureQrcodeStyleColumns();
ensureQrcodeActivityColumns();
ensureEmailVerificationColumns();
ensurePendingEmailColumn();
migrateEntreprisePlanRemoval();
migrateAuthTokenPurposes();

function backfillScanRollups() {
  // Réconciliation plutôt qu’un test « table vide » : le calcul est rejoué à
  // chaque démarrage mais n’ajoute que les écarts manquants, donc un agrégat
  // existant n’est jamais compté deux fois.
  db.exec(`
    INSERT INTO scan_rollups (
      qrcode_id, day, device_type, referrer_host, scan_count, last_scan_at
    )
    SELECT grouped.qrcode_id,
           grouped.day,
           grouped.device_type,
           grouped.referrer_host,
           grouped.event_count - COALESCE(existing.scan_count, 0) AS missing_count,
           grouped.last_scan_at
    FROM (
      SELECT qrcode_id,
             date(scanned_at / 1000, 'unixepoch') AS day,
             device_type,
             COALESCE(referrer_host, '') AS referrer_host,
             COUNT(*) AS event_count,
             MAX(scanned_at) AS last_scan_at
      FROM scan_events
      GROUP BY qrcode_id,
               date(scanned_at / 1000, 'unixepoch'),
               device_type,
               COALESCE(referrer_host, '')
    ) AS grouped
    LEFT JOIN scan_rollups AS existing
      ON existing.qrcode_id = grouped.qrcode_id
     AND existing.day = grouped.day
     AND existing.device_type = grouped.device_type
     AND existing.referrer_host = grouped.referrer_host
    WHERE grouped.event_count > COALESCE(existing.scan_count, 0)
    ON CONFLICT(qrcode_id, day, device_type, referrer_host)
    DO UPDATE SET
      scan_count = scan_count + excluded.scan_count,
      last_scan_at = MAX(last_scan_at, excluded.last_scan_at);
  `);
  db.prepare("DELETE FROM scan_events WHERE scanned_at < ?").run(
    now() - MAX_SCAN_RETENTION_DAYS * 24 * 60 * 60 * 1_000,
  );
}

backfillScanRollups();

const staticFiles = new Map([
  ["/", "index.html"],
  ["/index.html", "index.html"],
  ["/compte", "compte.html"],
  ["/compte.html", "compte.html"],
  ["/styles.css", "styles.css"],
  ["/app.js", "app.js"],
  ["/compte.js", "compte.js"],
  ["/qrcode-generator.js", "qrcode-generator.js"],
]);

const mimeTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "application/javascript; charset=utf-8"],
]);

const rateBuckets = new Map();
const recentScanBuckets = new Map();
const DUMMY_PASSWORD_HASH = await hashPassword(randomBytes(32).toString("hex"));
let idleTimer = null;
let shuttingDown = false;

class HttpError extends Error {
  constructor(status, message, code = "request_error") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function normalizePublicOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("QROOD_PUBLIC_ORIGIN doit être une origine HTTP ou HTTPS valide.");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("QROOD_PUBLIC_ORIGIN doit contenir uniquement le schéma, l’hôte et le port.");
  }
  return parsed.origin;
}

function readInteger(name, fallback, minimum, maximum) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} doit être un entier entre ${minimum} et ${maximum}.`);
  }
  return value;
}

// Les variables d'outillage suivent la convention `QROOD_` du projet, mais la
// convention de leur outil est aussi acceptée : `STRIPE_…` pour Stripe,
// `MAIL_…` pour l'envoi d'e-mails. Les deux lisent la même variable.
function readStripeEnv(name) {
  return cleanText(process.env[`QROOD_${name}`] || process.env[name] || "", 255);
}

// Aucune trace d'une clé ne doit atteindre le journal, même enveloppée dans une
// erreur de SDK. Le masquage est fait par `redactSecrets` (billing-rules.mjs),
// testable isolément.
function isStripeSdkError(error) {
  return typeof error?.type === "string" && error.type.startsWith("Stripe");
}

function now() {
  return Date.now();
}

function isoDate(timestamp) {
  return timestamp ? new Date(timestamp).toISOString() : null;
}

function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

function safeTokenEquals(expected, received) {
  if (typeof received !== "string") return false;
  const expectedBuffer = Buffer.from(expected);
  const receivedBuffer = Buffer.from(received);
  return expectedBuffer.length === receivedBuffer.length && timingSafeEqual(expectedBuffer, receivedBuffer);
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const options = { N: 16_384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
  const derived = await scrypt(password, salt, 64, options);
  return `scrypt$16384$8$1$${salt.toString("base64url")}$${Buffer.from(derived).toString("base64url")}`;
}

async function verifyPassword(password, storedHash) {
  try {
    const [algorithm, n, r, p, saltText, hashText] = String(storedHash).split("$");
    if (algorithm !== "scrypt" || n !== "16384" || r !== "8" || p !== "1") return false;
    const salt = Buffer.from(saltText, "base64url");
    const expected = Buffer.from(hashText, "base64url");
    const derived = Buffer.from(await scrypt(password, salt, expected.length, {
      N: 16_384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    }));
    return expected.length === derived.length && timingSafeEqual(expected, derived);
  } catch {
    return false;
  }
}

function parseCookies(header = "") {
  const cookies = new Map();
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

function sessionCookie(token) {
  const attributes = [
    `qrood_session=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (SECURE_COOKIES) attributes.push("Secure");
  return attributes.join("; ");
}

function clearSessionCookie() {
  const attributes = ["qrood_session=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (SECURE_COOKIES) attributes.push("Secure");
  return attributes.join("; ");
}

function getSession(request) {
  const token = parseCookies(request.headers.cookie).get("qrood_session");
  if (!token || !/^[A-Za-z0-9_-]{32,128}$/.test(token)) return null;
  const session = db.prepare(`
    SELECT s.id, s.user_id, s.csrf_token, s.last_seen_at, s.expires_at,
           u.id AS user_id_value, u.display_name, u.email, u.email_verified_at, u.pending_email
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(hashToken(token), now());

  if (!session) return null;
  if (now() - session.last_seen_at > 15 * 60 * 1_000) {
    db.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").run(now(), session.id);
  }
  return {
    id: session.id,
    userId: session.user_id_value,
    csrfToken: session.csrf_token,
    displayName: session.display_name,
    email: session.email,
    emailVerifiedAt: session.email_verified_at,
    pendingEmail: session.pending_email,
  };
}

function requireSession(request) {
  const session = getSession(request);
  if (!session) throw new HttpError(401, "Authentification requise.", "authentication_required");
  return session;
}

function verifyBrowserOrigin(request) {
  const origin = request.headers.origin;
  if (origin) {
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw new HttpError(403, "Origine de requête invalide.", "invalid_origin");
    }
    if (parsed.origin !== new URL(PUBLIC_ORIGIN).origin) {
      throw new HttpError(403, "Origine de requête refusée.", "invalid_origin");
    }
  }
  const fetchSite = request.headers["sec-fetch-site"];
  if (fetchSite && !["same-origin", "none"].includes(fetchSite)) {
    throw new HttpError(403, "Requête intersite refusée.", "cross_site_request");
  }
}

function verifyCsrf(request, session) {
  verifyBrowserOrigin(request);
  const received = request.headers["x-csrf-token"];
  if (!safeTokenEquals(session.csrfToken, received)) {
    throw new HttpError(403, "Jeton de sécurité invalide ou expiré.", "invalid_csrf_token");
  }
}

function getClientIp(request) {
  const peerAddress = String(request.socket.remoteAddress || "unknown").slice(0, 64);
  if (!TRUST_PROXY) return peerAddress;

  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded !== "string" || forwarded.length > 256) return peerAddress;
  const candidate = forwarded.split(",", 1)[0].trim().replace(/^\[|\]$/g, "");
  return isIP(candidate) ? candidate : peerAddress;
}

function checkRateLimit(key, limit, windowMs) {
  const timestamp = now();
  const existing = rateBuckets.get(key);
  if (!existing || existing.resetAt <= timestamp) {
    if (rateBuckets.size >= MAX_RATE_BUCKETS) {
      pruneRateBuckets();
      if (rateBuckets.size >= MAX_RATE_BUCKETS) {
        const oldestKey = rateBuckets.keys().next().value;
        if (oldestKey !== undefined) rateBuckets.delete(oldestKey);
      }
    }
    rateBuckets.set(key, { count: 1, resetAt: timestamp + windowMs });
    return;
  }
  existing.count += 1;
  if (existing.count > limit) {
    const error = new HttpError(429, "Trop de tentatives. Réessayez plus tard.", "rate_limited");
    error.retryAfter = Math.max(1, Math.ceil((existing.resetAt - timestamp) / 1000));
    throw error;
  }
}

function checkPublicRouteLimits(request, token, kind, countScan = false) {
  const ip = getClientIp(request);
  checkRateLimit(`public:${ip}`, 600, 60 * 1_000);
  checkRateLimit(`public:${kind}:${token}`, 240, 60 * 1_000);
  if (countScan) checkRateLimit(`scan:${ip}`, 240, 60 * 1_000);
}

function pruneRateBuckets() {
  const timestamp = now();
  for (const [key, bucket] of rateBuckets) {
    if (bucket.resetAt <= timestamp) rateBuckets.delete(key);
  }
}

// -- Adresses e-mail -------------------------------------------------------
// Les jetons vivent dans la base et ne sont jamais journalisés : le journal
// receives des faits (« envoi effectué »), jamais le lien qui autorise l'action.

function lastAuthToken(userId, purpose) {
  return db.prepare(`
    SELECT created_at FROM auth_tokens
    WHERE user_id = ? AND purpose = ?
    ORDER BY id DESC LIMIT 1
  `).get(userId, purpose);
}

function issueAuthToken(userId, purpose, ttlMs) {
  const timestamp = now();
  // Un seul jeton vivant par but : un nouveau lien annule le précédent, sinon
  // un e-mail de réinitialisation resterait valable après une demande plus
  // récente, et les deux liens seraient acceptés.
  db.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND purpose = ? AND used_at IS NULL").run(
    userId,
    purpose,
  );
  const token = randomToken(32);
  db.prepare(`
    INSERT INTO auth_tokens (user_id, purpose, token_hash, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, purpose, hashToken(token), timestamp, timestamp + ttlMs);
  return { token, expiresAt: timestamp + ttlMs };
}

/**
 * Consomme un jeton, une seule fois.
 *
 * La consommation est un `UPDATE` conditionnel : deux requêtes simultanées
 * avec le même jeton ne peuvent pas toutes deux voir `changes === 1`. C'est la
 * condition `expires_at > now` qui décide, pas l'heure de création du jeton.
 */
function consumeAuthToken(token, purpose) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{32,128}$/.test(token)) return null;
  const result = db.prepare(`
    UPDATE auth_tokens SET used_at = ?
    WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
  `).run(now(), hashToken(token), purpose, now());
  if (result.changes !== 1) return null;
  return db.prepare("SELECT user_id FROM auth_tokens WHERE token_hash = ?").get(hashToken(token));
}

function authTokenState(token, purpose) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{32,128}$/.test(token)) return null;
  return db.prepare(`
    SELECT user_id, used_at, expires_at FROM auth_tokens WHERE token_hash = ? AND purpose = ?
  `).get(hashToken(token), purpose);
}

function purgeAuthTokens() {
  // Un jeton inutilisé disparaît à son expiration ; un jeton consommé est gardé
  // un jour, pour que recharger la page après un clic reste une réussite et non
  // une erreur. Ces deux lignes ne contiennent que des condensats : le délai
  // d'effacement n'est pas une donnée sensible.
  db.prepare(`
    DELETE FROM auth_tokens
    WHERE (used_at IS NULL AND expires_at <= ?) OR (used_at IS NOT NULL AND used_at <= ?)
  `).run(now(), now() - 24 * 60 * 60 * 1_000);
}

/**
 * Envoie un message sans jamais faire échouer la demande qui l'a déclenché.
 *
 * Un e-mail non parti ne doit pas annuler une inscription ni une
 * réinitialisation déjà validées en base : l'utilisateur peut en demander un
 * nouveau. L'échec est journalisé sans le lien, qui est une autorisation.
 */
async function sendMail(message) {
  // Un destinataire invalide ne part jamais : une adresse pourrie dans la base
  // ne doit pas se transformer en tentative d'envoi.
  if (!isValidMailAddress(message.to)) {
    console.error(`e-mail ${message.purpose} non envoyé : destinataire invalide.`);
    return false;
  }
  try {
    await mailer.send(message);
    console.log(`e-mail ${message.purpose} envoyé (transport : ${mailer.mode}).`);
    return true;
  } catch (error) {
    console.error(redactSecrets(`e-mail ${message.purpose} non envoyé : ${error?.message || error}`));
    return false;
  }
}

async function sendVerificationEmail(user, token) {
  const url = `${PUBLIC_ORIGIN}/?verifie=${encodeURIComponent(token)}`;
  return sendMail(buildVerificationMessage({
    to: user.email,
    name: user.display_name,
    url,
    validHours: Math.round(VERIFICATION_TOKEN_TTL_MS / 3_600_000),
  }));
}

async function sendPasswordResetEmail(user, token) {
  const url = `${PUBLIC_ORIGIN}/?reinitialisation=${encodeURIComponent(token)}`;
  return sendMail(buildResetMessage({
    to: user.email,
    name: user.display_name,
    url,
    validMinutes: Math.round(RESET_TOKEN_TTL_MS / 60_000),
  }));
}

async function sendEmailChangeEmail(user, token) {
  const url = `${PUBLIC_ORIGIN}/compte?confirmation-email=${encodeURIComponent(token)}`;
  return sendMail(buildEmailChangeMessage({
    to: user.pending_email,
    name: user.display_name,
    url,
    validMinutes: Math.round(EMAIL_CHANGE_TOKEN_TTL_MS / 60_000),
  }));
}

/**
 * Refuse une opération qui publie ou consomme un droit tant que l'adresse n'est
 * pas confirmée. La désactivation et la suppression en sont exemptes : ce sont
 * des actes de retrait, et les bloquer obligerait un compte mal vérifié à
 * laisser en ligne ce qu'il voudrait retirer.
 */
function requireVerifiedEmail(session) {
  if (session.emailVerifiedAt) return;
  throw new HttpError(
    403,
    "Confirmez votre adresse e-mail pour enregistrer et publier vos QR codes.",
    "email_verification_required",
  );
}

function validateDisplayName(value) {
  const displayName = cleanText(value, 80);
  if (displayName.length < 2) throw new HttpError(400, "Le nom doit contenir entre 2 et 80 caractères.", "invalid_name");
  return displayName;
}

function validateEmail(value) {
  const email = cleanText(value, 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/u.test(email)) {
    throw new HttpError(400, "L’adresse e-mail est invalide.", "invalid_email");
  }
  return email;
}

function validatePassword(value) {
  if (typeof value !== "string" || value.length < 12 || value.length > 128) {
    throw new HttpError(400, "Le mot de passe doit contenir entre 12 et 128 caractères.", "invalid_password");
  }
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) {
    throw new HttpError(400, "Le mot de passe doit contenir une minuscule, une majuscule et un chiffre.", "weak_password");
  }
  return value;
}

function cleanText(value, maximum) {
  return String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, maximum);
}

function requireObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "Le corps de la requête doit être un objet JSON.", "invalid_body");
  }
  return value;
}

function isPrivateIpv4(first, second, third, fourth) {
  return first === 0 || first === 10 || first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && (second === 0 || second === 168)) ||
    (first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100))) ||
    (first === 203 && second === 0 && third === 113) ||
    first >= 224;
}

function parseIpv6(value) {
  let input = String(value || "").toLowerCase();
  if (!input || input.includes("%")) return null;

  if (input.includes(".")) {
    const separator = input.lastIndexOf(":");
    if (separator < 0) return null;
    const octets = input.slice(separator + 1).split(".").map(Number);
    if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    input = `${input.slice(0, separator + 1)}${high}:${low}`;
  }

  const halves = input.split("::");
  if (halves.length > 2) return null;
  const parseHalf = (half) => half ? half.split(":") : [];
  const left = parseHalf(halves[0]);
  const right = halves.length === 2 ? parseHalf(halves[1]) : [];
  const words = [...left, ...right];
  if (words.some((word) => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
  const numericWords = words.map((word) => Number.parseInt(word, 16));
  if (halves.length === 1) return numericWords.length === 8 ? numericWords : null;
  const missing = 8 - numericWords.length;
  if (missing < 1) return null;
  return [...numericWords.slice(0, left.length), ...Array(missing).fill(0), ...numericWords.slice(left.length)];
}

function isPrivateIpv6(words) {
  const first = words[0];
  const isZeroPrefix = words.slice(0, 5).every((word) => word === 0);
  if (words.every((word) => word === 0)) return true;
  if (isZeroPrefix && words[5] === 0xffff) {
    return isPrivateIpv4(words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff);
  }
  if (words.slice(0, 6).every((word) => word === 0)) {
    return isPrivateIpv4(words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff);
  }
  return (first & 0xfe00) === 0xfc00 ||
    (first & 0xffc0) === 0xfe80 ||
    (first & 0xffc0) === 0xfec0 ||
    (first & 0xff00) === 0xff00;
}

function isPrivateHostname(rawHostname) {
  const hostname = String(rawHostname || "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || hostname.endsWith(".home.arpa")) return true;
  if (isIP(hostname) === 4) {
    const [first, second, third, fourth] = hostname.split(".").map(Number);
    return isPrivateIpv4(first, second, third, fourth);
  }
  if (isIP(hostname) === 6) {
    const words = parseIpv6(hostname);
    return words ? isPrivateIpv6(words) : true;
  }
  return false;
}

function normalizeHttpUrl(rawValue) {
  const raw = String(rawValue ?? "").trim();
  if (raw.length > MAX_DESTINATION_LENGTH) {
    throw new HttpError(400, "Le lien est trop long.", "invalid_destination");
  }
  let value = cleanText(raw, MAX_DESTINATION_LENGTH);
  if (!value) throw new HttpError(400, "Le lien est obligatoire.", "invalid_destination");
  if (!/^[a-z][a-z\d+.-]*:/i.test(value) && /^[\w.-]+\.[a-z]{2,}(?:\/.*)?$/i.test(value)) {
    value = `https://${value}`;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new HttpError(400, "Le lien est invalide.", "invalid_destination");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new HttpError(400, "Seuls les liens HTTP et HTTPS sont autorisés.", "invalid_destination");
  }
  if (parsed.username || parsed.password) {
    throw new HttpError(400, "Les liens contenant des identifiants sont refusés.", "invalid_destination");
  }
  if (!ALLOW_PRIVATE_DESTINATIONS && isPrivateHostname(parsed.hostname)) {
    throw new HttpError(400, "Les destinations réseau privées ou locales sont refusées.", "private_destination");
  }
  if (parsed.origin === new URL(PUBLIC_ORIGIN).origin) {
    throw new HttpError(400, "La destination ne peut pas pointer vers QROOD.", "self_destination");
  }
  if (parsed.href.length > MAX_DESTINATION_LENGTH) {
    throw new HttpError(400, "Le lien est trop long.", "invalid_destination");
  }
  return parsed.href;
}

function validateContactData(rawContact) {
  const contact = rawContact && typeof rawContact === "object" ? rawContact : {};
  const normalized = {
    firstName: cleanText(contact.firstName, 80),
    lastName: cleanText(contact.lastName, 80),
    company: cleanText(contact.company, 120),
    phone: cleanText(contact.phone, 40),
    email: "",
    website: "",
    address: cleanText(contact.address, 300),
  };

  if (contact.email) normalized.email = validateEmail(contact.email);
  if (contact.website) normalized.website = normalizeHttpUrl(contact.website);
  if (!Object.values(normalized).some(Boolean)) {
    throw new HttpError(400, "Ajoutez au moins une coordonnée de contact.", "empty_contact");
  }
  return normalized;
}

function escapeVCard(value) {
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/\r?\n/g, "\\n")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,");
}

function foldVCardLine(line) {
  const bytes = Buffer.from(String(line || ""), "utf8");
  const chunks = [];
  let start = 0;
  let first = true;
  while (start < bytes.length) {
    const limit = first ? 75 : 74;
    let end = Math.min(start + limit, bytes.length);
    while (end > start && end < bytes.length && (bytes[end] & 0xc0) === 0x80) end -= 1;
    chunks.push(bytes.subarray(start, end).toString("utf8"));
    start = end;
    first = false;
  }
  return chunks.join("\r\n ");
}

function buildVCard(contact) {
  const fullName = [contact.firstName, contact.lastName].filter(Boolean).join(" ");
  const lines = ["BEGIN:VCARD", "VERSION:3.0"];
  if (contact.firstName || contact.lastName) {
    lines.push(`N:${escapeVCard(contact.lastName)};${escapeVCard(contact.firstName)};;;`);
  }
  lines.push(`FN:${escapeVCard(fullName || contact.company || contact.email || "Contact")}`);
  if (contact.company) lines.push(`ORG:${escapeVCard(contact.company)}`);
  if (contact.phone) lines.push(`TEL;TYPE=CELL:${escapeVCard(contact.phone)}`);
  if (contact.email) lines.push(`EMAIL;TYPE=INTERNET:${escapeVCard(contact.email)}`);
  if (contact.website) lines.push(`URL:${escapeVCard(contact.website)}`);
  if (contact.address) {
    const parts = contact.address.split(",").map((part) => part.trim()).filter(Boolean);
    const [street = "", city = "", region = "", postalCode = "", ...countryParts] = parts;
    lines.push(`ADR;TYPE=WORK:;;${escapeVCard(street)};${escapeVCard(city)};${escapeVCard(region)};${escapeVCard(postalCode)};${escapeVCard(countryParts.join(", "))}`);
  }
  lines.push("END:VCARD");
  return `${lines.map(foldVCardLine).join("\r\n")}\r\n`;
}

function relativeLuminance(hexColor) {
  const channels = hexColor.match(/[0-9a-f]{2}/gi).map((channel) => Number.parseInt(channel, 16) / 255);
  const linear = channels.map((channel) => channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function colorContrast(foreground, background) {
  const first = relativeLuminance(foreground);
  const second = relativeLuminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

function coerceStyle(rawStyle) {
  const source = rawStyle && typeof rawStyle === "object" ? rawStyle : {};
  const gradientSource = source.gradient && typeof source.gradient === "object" ? source.gradient : null;
  const angle = Number(gradientSource && gradientSource.angle);
  return {
    moduleShape: STYLE_MODULE_SHAPES.has(source.moduleShape) ? source.moduleShape : "square",
    eyeShape: STYLE_EYE_SHAPES.has(source.eyeShape) ? source.eyeShape : "square",
    margin: Number.isInteger(source.margin)
      ? Math.min(Math.max(source.margin, 0), MAX_STYLE_MARGIN)
      : DEFAULT_STYLE_MARGIN,
    logoSizePct: Number.isFinite(Number(source.logoSizePct))
      ? Math.min(Math.max(Math.round(Number(source.logoSizePct)), MIN_LOGO_SIZE_PCT), MAX_LOGO_SIZE_PCT)
      : DEFAULT_LOGO_SIZE_PCT,
    gradient: gradientSource ? {
      from: String(gradientSource.from || "").toLowerCase(),
      to: String(gradientSource.to || "").toLowerCase(),
      angle: Number.isFinite(angle) ? ((Math.round(angle) % 360) + 360) % 360 : 135,
    } : null,
  };
}

function validateStyle(rawStyle, background, features, currentStyle = null) {
  const style = coerceStyle(rawStyle);
  // Non-régression : une personnalisation déjà enregistrée reste modifiable après
  // un retour sur une offre inférieure. On ne refuse donc que ce qui change
  // réellement, jamais ce qui était déjà en base. C'est ce qui permet de
  // promettre « tout continue de fonctionner » dans la bannière de régression.
  const unchanged = currentStyle !== null
    && currentStyle.moduleShape === style.moduleShape
    && currentStyle.eyeShape === style.eyeShape
    && JSON.stringify(currentStyle.gradient) === JSON.stringify(style.gradient);
  if (!unchanged) {
    if (!features.moduleShapes.includes(style.moduleShape)) {
      throw new HttpError(
        402,
        `La forme « ${style.moduleShape} » est réservée à l’offre ${features.requiredLabel}.`,
        "plan_upgrade_required",
      );
    }
    if (!features.eyeShapes.includes(style.eyeShape)) {
      throw new HttpError(
        402,
        `La forme d’œil « ${style.eyeShape} » est réservée à l’offre ${features.requiredLabel}.`,
        "plan_upgrade_required",
      );
    }
    if (style.gradient && !features.gradient) {
      throw new HttpError(
        402,
        `Le dégradé est réservé à l’offre ${features.requiredLabel}.`,
        "plan_upgrade_required",
      );
    }
  }
  if (style.gradient) {
    if (!/^#[0-9a-f]{6}$/.test(style.gradient.from) || !/^#[0-9a-f]{6}$/.test(style.gradient.to)) {
      throw new HttpError(400, "Les couleurs du dégradé sont invalides.", "invalid_color");
    }
    if (colorContrast(style.gradient.from, background) < 3 || colorContrast(style.gradient.to, background) < 3) {
      throw new HttpError(
        400,
        "Le dégradé doit rester suffisamment contrasté avec le fond pour rester scannable.",
        "low_contrast",
      );
    }
  }
  return style;
}

function validateLogo(rawLogo, features, currentLogo = null) {
  if (rawLogo === undefined || rawLogo === null || rawLogo === "") return null;
  const logo = String(rawLogo);
  if (logo.length > MAX_LOGO_LENGTH) {
    throw new HttpError(413, "Le logo est trop volumineux. Utilisez une image plus légère.", "logo_too_large");
  }
  if (!LOGO_PATTERN.test(logo)) {
    throw new HttpError(400, "Le logo doit être une image PNG, JPEG ou WEBP.", "invalid_logo");
  }
  if (!features.logo && logo !== currentLogo) {
    throw new HttpError(
      402,
      `Le logo au centre du QR code est réservé à l’offre ${features.requiredLabel}.`,
      "plan_upgrade_required",
    );
  }
  return logo;
}

function validateQrPayload(body, entitlement, current = null) {
  const features = entitlement.features;
  const mode = body.mode === "contact" ? "contact" : body.mode === "link" ? "link" : null;
  if (!mode) throw new HttpError(400, "Le type de QR code est invalide.", "invalid_mode");
  const legacyKey = body.legacyKey === undefined || body.legacyKey === null || body.legacyKey === ""
    ? null
    : String(body.legacyKey);
  if (legacyKey !== null && !/^[A-Za-z0-9_-]{16,128}$/.test(legacyKey)) {
    throw new HttpError(400, "La clé de migration est invalide.", "invalid_legacy_key");
  }
  const foreground = String(body.foreground || "#101b33").toLowerCase();
  const background = String(body.background || "#ffffff").toLowerCase();
  if (!/^#[0-9a-f]{6}$/.test(foreground) || !/^#[0-9a-f]{6}$/.test(background)) {
    throw new HttpError(400, "Les couleurs sont invalides.", "invalid_color");
  }
  if (relativeLuminance(foreground) >= relativeLuminance(background) || colorContrast(foreground, background) < 3) {
    throw new HttpError(400, "Choisissez des couleurs suffisamment contrastées pour le QR code.", "low_contrast");
  }
  const currentStyle = current ? coerceStyle(parseStoredJson(current.style)) : null;
  const style = validateStyle(body.style, background, features, currentStyle);
  const logo = validateLogo(body.logo, features, current ? current.logo : null);

  if (mode === "link") {
    const destination = normalizeHttpUrl(body.destination);
    const name = cleanText(body.name, MAX_NAME_LENGTH) || displayNameForLink(destination);
    return { mode, name, destination, contactData: null, vcard: null, foreground, background, style, logo, legacyKey };
  }

  const contactData = validateContactData(body.contactData);
  const name = cleanText(body.name, MAX_NAME_LENGTH) || displayNameForContact(contactData);
  return {
    mode,
    name,
    destination: null,
    contactData,
    vcard: buildVCard(contactData),
    foreground,
    background,
    style,
    logo,
    legacyKey,
  };
}

function displayNameForLink(destination) {
  try {
    return cleanText(new URL(destination).hostname.replace(/^www\./, ""), MAX_NAME_LENGTH);
  } catch {
    return "QR code lien";
  }
}

function displayNameForContact(contact) {
  const name = [contact.firstName, contact.lastName].filter(Boolean).join(" ");
  return cleanText(name || contact.company || contact.email || "Carte de visite", MAX_NAME_LENGTH);
}

function parseStoredJson(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(String(raw));
  } catch {
    return null;
  }
}

function mapQrcode(row, entitlement = null) {
  if (!row) return null;
  const route = row.mode === "link" ? "r" : "c";
  return {
    id: row.id,
    name: row.name,
    mode: row.mode,
    destination: row.destination,
    contactData: row.contact_data ? JSON.parse(row.contact_data) : null,
    foreground: row.foreground,
    background: row.background,
    style: coerceStyle(parseStoredJson(row.style)),
    logo: row.logo || null,
    trackingUrl: `${PUBLIC_ORIGIN}/${route}/${row.public_token}`,
    createdAt: isoDate(row.created_at),
    updatedAt: isoDate(row.updated_at),
    isActive: row.is_active === 1,
    inactiveScans: row.inactive_scans ?? 0,
    statsDays: entitlement ? entitlement.statsDays : PLAN_CATALOG[DEFAULT_PLAN].statsDays,
    scanCount: row.scan_count ?? 0,
    scansWeek: row.scans_week ?? 0,
    lastScanAt: isoDate(row.last_scan_at),
  };
}

function listQrcodes(userId, limit = 100, offset = 0, entitlement = null) {
  return db.prepare(`
    SELECT q.*,
           COALESCE((SELECT SUM(r.scan_count) FROM scan_rollups r WHERE r.qrcode_id = q.id), 0) AS scan_count,
           (SELECT MAX(r.last_scan_at) FROM scan_rollups r WHERE r.qrcode_id = q.id) AS last_scan_at,
           COALESCE((SELECT SUM(r.scan_count) FROM scan_rollups r
             WHERE r.qrcode_id = q.id AND r.day >= date('now', '-7 days')), 0) AS scans_week
    FROM qrcodes q
    WHERE q.user_id = ?
    ORDER BY q.updated_at DESC
    LIMIT ? OFFSET ?
  `).all(userId, limit, offset).map((row) => mapQrcode(row, entitlement));
}

function getQrcodeStatsRow(id) {
  return db.prepare(`
    SELECT q.*,
           COALESCE((SELECT SUM(r.scan_count) FROM scan_rollups r WHERE r.qrcode_id = q.id), 0) AS scan_count,
           (SELECT MAX(r.last_scan_at) FROM scan_rollups r WHERE r.qrcode_id = q.id) AS last_scan_at,
           COALESCE((SELECT SUM(r.scan_count) FROM scan_rollups r
             WHERE r.qrcode_id = q.id AND r.day >= date('now', '-7 days')), 0) AS scans_week
    FROM qrcodes q
    WHERE q.id = ?
  `).get(id);
}

function countQrcodes(userId) {
  return db.prepare("SELECT COUNT(*) AS count FROM qrcodes WHERE user_id = ?").get(userId).count;
}

function countActiveQrcodes(userId) {
  return db.prepare("SELECT COUNT(*) AS count FROM qrcodes WHERE user_id = ? AND is_active = 1").get(userId).count;
}

// Volontairement sans cache : la résolution coûte trois requêtes indexées sur un
// fichier SQLite local, soit moins d'une milliseconde, alors qu'un cache
// rendrait l'offre affichée fausse pendant plusieurs secondes après un paiement
// ou une désinscription — le moment exact où l'utilisateur regarde.
function resolvePlanKey(userId) {
  const row = db.prepare("SELECT plan, status, grace_until FROM subscriptions WHERE user_id = ?").get(userId);
  if (!row || !PLAN_CATALOG[row.plan] || !isEntitled(row, now())) return DEFAULT_PLAN;
  return row.plan;
}

// `grace_until` porte la grâce de 48 h décidée en cas de perte d'accès : elle se
// décompte depuis `current_period_end`, donc le décompte affiché et l'expiration
// enregistrée ne peuvent pas diverger.
function isEntitled(row, timestamp) {
  if (!row) return false;
  if (row.status === "active" || row.status === "trialing") return true;
  // `past_due` et `unpaid` restent couverts : les relances de Stripe sont en cours
  // et l'utilisateur n'a rien fait de mal.
  if (row.status === "past_due" || row.status === "unpaid") return true;
  // `canceled` et `paused` basculent sur Découverte à l'expiration de la grâce.
  if (row.status === "canceled" || row.status === "paused") {
    return row.grace_until !== null && row.grace_until > timestamp;
  }
  // `incomplete` (Checkout abandonné) et `incomplete_expired` n'accordent rien.
  return false;
}

function resolveEntitlement(userId) {
  const planKey = resolvePlanKey(userId);
  const plan = PLAN_CATALOG[planKey];
  const used = countQrcodes(userId);
  const usedActive = countActiveQrcodes(userId);
  return {
    plan: planKey,
    label: plan.label,
    maxQrcodes: plan.maxQrcodes,
    maxActive: plan.maxActive,
    statsDays: plan.statsDays,
    customization: plan.customization,
    support: plan.support,
    features: STYLE_ENTITLEMENTS[plan.customization],
    used,
    usedActive,
    // `null` = illimité, donc jamais bloquant.
    canCreate: plan.maxQrcodes === null || used < plan.maxQrcodes,
    canActivate: plan.maxActive === null || usedActive < plan.maxActive,
    overQuota: (plan.maxQrcodes !== null && used > plan.maxQrcodes)
      || (plan.maxActive !== null && usedActive > plan.maxActive),
  };
}

// ── Facturation Stripe ──────────────────────────────────────────────────────
// Import différé : le serveur doit démarrer sans `node_modules` (installation
// oubliée, environnement de test) et se contenter de refuser la facturation.
async function getStripe() {
  if (!BILLING_ENABLED) {
    throw new HttpError(
      503,
      "La facturation n’est pas configurée sur ce serveur.",
      "billing_not_configured"
    );
  }
  if (!stripeClient) {
    const { default: Stripe } = await import("stripe");
    stripeClient = new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: STRIPE_API_VERSION,
      // Sans plafond, une API Stripe lente immobilise la requête HTTP derrière.
      timeout: 10_000,
      maxNetworkRetries: 1,
    });
  }
  return stripeClient;
}

function requireBillingConfigured() {
  if (!BILLING_CONFIGURED) {
    throw new HttpError(
      503,
      "La facturation n’est pas configurée sur ce serveur.",
      "billing_not_configured"
    );
  }
}

function readSubscriptionPriceId(subscription) {
  const price = subscription.items?.data?.[0]?.price;
  return typeof price === "string" ? price : (price?.id || null);
}

function resolvePlanForSubscription(subscription, existingPlan) {
  // `metadata.plan` est écrit à la création du Checkout et prime : un dashboard
  // Stripe remappé à la main ne doit pas pouvoir changer l'offre servie.
  const declared = cleanText(subscription.metadata?.plan, 32);
  if (PLAN_CATALOG[declared] && BILLABLE_PLANS.includes(declared)) return declared;
  const byPrice = STRIPE_PRICE_BY_ID.get(readSubscriptionPriceId(subscription));
  if (byPrice) return byPrice;
  if (existingPlan && PLAN_CATALOG[existingPlan]) return existingPlan;
  return null;
}

function findUserIdByStripeCustomer(customerId) {
  if (!customerId) return null;
  const row = db.prepare("SELECT user_id FROM billing_customers WHERE stripe_customer_id = ?").get(customerId);
  return row ? row.user_id : null;
}

function findUserIdFromMetadata(value) {
  const userId = Number(cleanText(value, 24));
  if (!Number.isInteger(userId) || userId < 1) return null;
  return db.prepare("SELECT id FROM users WHERE id = ?").get(userId)?.id ?? null;
}

function linkStripeCustomer(userId, customerId) {
  if (!userId || !customerId) return;
  db.prepare(`
    INSERT INTO billing_customers (user_id, stripe_customer_id, created_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET stripe_customer_id = excluded.stripe_customer_id
  `).run(userId, customerId, now());
  // Le même client Stripe ne peut pas être rattaché à deux comptes QROOD.
  db.prepare("UPDATE billing_customers SET user_id = ? WHERE stripe_customer_id = ? AND user_id <> ?")
    .run(userId, customerId, userId);
}

async function getOrCreateStripeCustomer(userId) {
  const existing = db.prepare("SELECT stripe_customer_id FROM billing_customers WHERE user_id = ?").get(userId);
  if (existing) return existing.stripe_customer_id;
  const user = db.prepare("SELECT display_name, email FROM users WHERE id = ?").get(userId);
  if (!user) throw new HttpError(404, "Compte introuvable.", "user_not_found");
  const stripe = await getStripe();
  const customer = await stripe.customers.create({
    email: user.email,
    name: user.display_name,
    metadata: { qrood_user_id: String(userId) },
  });
  linkStripeCustomer(userId, customer.id);
  const stored = db.prepare("SELECT stripe_customer_id FROM billing_customers WHERE user_id = ?").get(userId);
  return stored ? stored.stripe_customer_id : customer.id;
}

// Un seul abonnement vivant par compte est garanti par
// `idx_subscriptions_live_user`. Les lignes `incomplete` et `incomplete_expired`
// ne sont jamais insérées, sinon un Checkout abandonné figerait le compte.
function syncSubscriptionFromStripe(subscription) {
  const stripeSubscriptionId = cleanText(subscription?.id, 64);
  if (!stripeSubscriptionId) return null;
  const customerId = typeof subscription.customer === "string" ? subscription.customer : subscription.customer?.id;
  const existing = db.prepare("SELECT * FROM subscriptions WHERE stripe_subscription_id = ?").get(stripeSubscriptionId);
  const status = normalizeStripeStatus(subscription.status);
  const plan = resolvePlanForSubscription(subscription, existing?.plan);
  const timestamp = now();
  const periodEnd = readPeriodEnd(subscription);

  if (!existing) {
    if (status === "incomplete" || status === "incomplete_expired") return null;
    if (!plan) {
      console.error(
        `qrood billing: abonnement Stripe ${stripeSubscriptionId} sur un Price inconnu, accès laissé sur Découverte.`
      );
      return null;
    }
    const userId =
      findUserIdByStripeCustomer(customerId)
      || findUserIdFromMetadata(subscription.metadata?.qrood_user_id);
    if (!userId) {
      console.error(`qrood billing: abonnement Stripe ${stripeSubscriptionId} sans compte QROOD associé, ignoré.`);
      return null;
    }
    if (customerId) linkStripeCustomer(userId, customerId);
    db.prepare(`
      INSERT INTO subscriptions (
        user_id, plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id,
        current_period_end, cancel_at_period_end, grace_until, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      userId,
      plan,
      status,
      customerId || "",
      stripeSubscriptionId,
      readSubscriptionPriceId(subscription) || STRIPE_PRICES[plan] || "",
      periodEnd,
      subscription.cancel_at_period_end ? 1 : 0,
      computeGraceUntil(status, periodEnd, timestamp),
      timestamp,
      timestamp
    );
    return db.prepare("SELECT * FROM subscriptions WHERE stripe_subscription_id = ?").get(stripeSubscriptionId);
  }

  if (!plan) {
    console.error(
      `qrood billing: abonnement Stripe ${stripeSubscriptionId} sur un Price inconnu, offre ${existing.plan} conservée.`
    );
    return existing;
  }
  db.prepare(`
    UPDATE subscriptions
    SET plan = ?, status = ?, stripe_customer_id = ?, stripe_price_id = ?, current_period_end = ?,
        cancel_at_period_end = ?, grace_until = ?, updated_at = ?
    WHERE id = ?
  `).run(
    plan,
    status,
    customerId || existing.stripe_customer_id,
    readSubscriptionPriceId(subscription) || existing.stripe_price_id,
    periodEnd,
    subscription.cancel_at_period_end ? 1 : 0,
    computeGraceUntil(status, periodEnd, timestamp),
    timestamp,
    existing.id
  );
  return db.prepare("SELECT * FROM subscriptions WHERE stripe_subscription_id = ?").get(stripeSubscriptionId);
}

// Résumé destiné au client : aucun identifiant Stripe n'est exposé.
function getSubscriptionSummary(userId) {
  const row = db.prepare(`
    SELECT plan, status, current_period_end, cancel_at_period_end, grace_until
    FROM subscriptions
    WHERE user_id = ?
    ORDER BY updated_at DESC
    LIMIT 1
  `).get(userId);
  const customer = db.prepare("SELECT 1 AS ok FROM billing_customers WHERE user_id = ?").get(userId);
  if (!row) {
    return {
      hasBillingAccount: Boolean(customer),
      plan: DEFAULT_PLAN,
      status: null,
      cancelAtPeriodEnd: false,
      currentPeriodEnd: null,
      graceUntil: null,
    };
  }
  return {
    hasBillingAccount: Boolean(customer),
    plan: row.plan,
    status: row.status,
    cancelAtPeriodEnd: Boolean(row.cancel_at_period_end),
    currentPeriodEnd: row.current_period_end,
    graceUntil: row.grace_until,
  };
}

const priceCache = { value: null, expiresAt: 0 };
// Un Price illisible ne doit pas bloquer la page des offres plus de quelques
// secondes : au-delà, l'offre est simplement donnée comme indisponible.
const PRICE_LOOKUP_TIMEOUT_MS = 5_000;

function withTimeout(promise, milliseconds) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`délai dépassé après ${milliseconds} ms`)), milliseconds);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); }
    );
  });
}

async function readStripePrices() {
  if (!BILLING_CONFIGURED) return {};
  if (priceCache.value && priceCache.expiresAt > now()) return priceCache.value;
  const stripe = await getStripe();
  const offers = {};
  for (const plan of BILLABLE_PLANS) {
    const priceId = STRIPE_PRICES[plan];
    if (!priceId) continue;
    try {
      const price = await withTimeout(stripe.prices.retrieve(priceId), PRICE_LOOKUP_TIMEOUT_MS);
      if (price.active === false) {
        throw new Error(`le Price ${priceId} de l'offre ${plan} est désactivé`);
      }
      if (price.currency !== "eur") {
        throw new Error(`le Price ${priceId} de l'offre ${plan} n'est pas en euros`);
      }
      if (price.recurring?.interval !== "month" || price.recurring?.interval_count !== 1) {
        throw new Error(`le Price ${priceId} de l'offre ${plan} n'est pas un abonnement mensuel`);
      }
      offers[plan] = {
        amount: price.unit_amount,
        currency: price.currency.toUpperCase(),
        interval: "month",
        // Un Price `inclusive` porte déjà la TVA dans son montant : l'interface
        // doit alors l'annoncer en TTC. Sans ce champ, elle afficherait
        // « 12,00 € HT » pour un montant que le client paie bien à 12,00 €.
        taxInclusive: price.tax_behavior === "inclusive",
      };
    } catch (error) {
      console.error(`qrood billing: Price ${priceId} illisible (${redactSecrets(error.message)}).`);
      offers[plan] = null;
    }
  }
  priceCache.value = offers;
  priceCache.expiresAt = now() + 60 * 60 * 1_000;
  return offers;
}

function buildOffersPayload(prices) {
  const featuresFor = (plan) => {
    const catalog = PLAN_CATALOG[plan];
    const style = STYLE_ENTITLEMENTS[catalog.customization];
    const features = [
      `${catalog.maxQrcodes === null ? "QR codes illimités" : `${catalog.maxQrcodes} QR codes enregistrés`}`,
      `${catalog.maxActive === null ? "QR codes actifs illimités" : `${catalog.maxActive} QR code actif`}`,
      `Statistiques sur ${catalog.statsDays} jours`,
    ];
    if (style.gradient) features.push("Dégradés");
    if (style.moduleShapes.includes("rounded")) features.push("Modules arrondis");
    if (style.eyeShapes.includes("leaf")) features.push("Yeux en feuille");
    if (style.logo) features.push("Logo au centre");
    if (catalog.support) features.push(catalog.support === "prioritaire" ? "Support prioritaire" : "Support standard");
    return features;
  };
  return {
    decouverte: {
      key: "decouverte",
      label: PLAN_CATALOG.decouverte.label,
      price: null,
      features: featuresFor("decouverte"),
    },
    pro: {
      key: "pro",
      label: PLAN_CATALOG.pro.label,
      price: prices.pro || null,
      features: featuresFor("pro"),
    },
    ultra: {
      key: "ultra",
      label: PLAN_CATALOG.ultra.label,
      price: prices.ultra || null,
      features: featuresFor("ultra"),
    },
  };
}

function findLiveStripeSubscription(userId) {
  return db.prepare(`
    SELECT stripe_subscription_id FROM subscriptions
    WHERE user_id = ? AND status NOT IN ('canceled','incomplete_expired')
    LIMIT 1
  `).get(userId) || null;
}

// Paramètres de la session Checkout, isolés de l'appel réseau pour être
// vérifiables : c'est ici que sont décidés la fiscalité, la collecte de la
// carte et la résiliation.
function buildCheckoutParams(userId, plan, customerId, priceId) {
  return buildStripeCheckoutParams({ userId, plan, customerId, priceId, publicOrigin: PUBLIC_ORIGIN });
}

async function createCheckoutSession(userId, plan) {
  if (!BILLABLE_PLANS.includes(plan) || !PLAN_CATALOG[plan]) {
    throw new HttpError(400, "Cette offre ne peut pas être achetée en ligne.", "plan_not_purchasable");
  }
  requireBillingConfigured();
  const priceId = STRIPE_PRICES[plan];
  if (!priceId) {
    throw new HttpError(
      503,
      "Cette offre n’est pas encore disponible à la vente.",
      "plan_not_purchasable"
    );
  }
  const live = findLiveStripeSubscription(userId);
  if (live) {
    // Changer d'offre passe par le portail : c'est le seul chemin qui évite de
    // laisser cohabiter deux abonnements vivants sur un même compte.
    throw new HttpError(
      409,
      "Vous avez déjà un abonnement actif. Gérez-le depuis votre espace de facturation.",
      "subscription_already_active"
    );
  }
  const stripe = await getStripe();
  const customerId = await getOrCreateStripeCustomer(userId);
  const session = await stripe.checkout.sessions.create(
    buildCheckoutParams(userId, plan, customerId, priceId)
  );
  if (!session?.url) {
    throw new HttpError(502, "Stripe n’a pas renvoyé d’adresse de paiement.", "checkout_failed");
  }
  return session.url;
}

async function createPortalSession(userId) {
  requireBillingConfigured();
  const customer = db.prepare("SELECT stripe_customer_id FROM billing_customers WHERE user_id = ?").get(userId);
  if (!customer) {
    throw new HttpError(
      404,
      "Aucun abonnement à gérer. Choisissez d’abord une offre payante.",
      "no_billing_account"
    );
  }
  const stripe = await getStripe();
  const session = await stripe.billingPortal.sessions.create({
    customer: customer.stripe_customer_id,
    return_url: `${PUBLIC_ORIGIN}/`,
  });
  if (!session?.url) {
    throw new HttpError(502, "Stripe n’a pas renvoyé d’adresse de facturation.", "portal_failed");
  }
  return session.url;
}

async function processStripeEvent(event) {
  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data?.object;
      if (session?.mode !== "subscription") return;
      if (session.customer) {
        const userId =
          findUserIdByStripeCustomer(typeof session.customer === "string" ? session.customer : session.customer.id)
          || findUserIdFromMetadata(session.client_reference_id)
          || findUserIdFromMetadata(session.metadata?.qrood_user_id);
        if (userId) linkStripeCustomer(userId, typeof session.customer === "string" ? session.customer : session.customer.id);
      }
      const subscriptionId = typeof session.subscription === "string" ? session.subscription : session.subscription?.id;
      if (!subscriptionId) return;
      const stripe = await getStripe();
      syncSubscriptionFromStripe(await stripe.subscriptions.retrieve(subscriptionId));
      return;
    }
    case "customer.subscription.created":
    case "customer.subscription.updated":
    case "customer.subscription.deleted":
      syncSubscriptionFromStripe(event.data?.object);
      return;
    default:
      return;
  }
}

function parsePagination(url) {
  const rawLimit = url.searchParams.get("limit");
  const rawOffset = url.searchParams.get("offset");
  const limit = rawLimit === null ? 100 : Number(rawLimit);
  const offset = rawOffset === null ? 0 : Number(rawOffset);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new HttpError(400, "La taille de page est invalide.", "invalid_pagination");
  }
  if (!Number.isInteger(offset) || offset < 0 || offset > 10_000) {
    throw new HttpError(400, "Le décalage de pagination est invalide.", "invalid_pagination");
  }
  return { limit, offset };
}

function getOwnedQrcode(userId, id) {
  return db.prepare("SELECT * FROM qrcodes WHERE id = ? AND user_id = ?").get(id, userId);
}

function createSession(userId, request) {
  const token = randomToken(32);
  const csrfToken = randomToken(24);
  const timestamp = now();
  db.prepare(`
    INSERT INTO sessions (user_id, token_hash, csrf_token, created_at, last_seen_at, expires_at, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    userId,
    hashToken(token),
    csrfToken,
    timestamp,
    timestamp,
    timestamp + SESSION_TTL_MS,
    cleanText(request.headers["user-agent"], 300),
  );
  db.prepare(`
    DELETE FROM sessions
    WHERE user_id = ? AND id NOT IN (
      SELECT id FROM sessions
      WHERE user_id = ?
      ORDER BY last_seen_at DESC, id DESC
      LIMIT ?
    )
  `).run(userId, userId, MAX_SESSIONS_PER_USER);
  return { token, csrfToken };
}

function deviceType(userAgent) {
  const value = String(userAgent || "").toLowerCase();
  if (/bot|crawler|spider|headless|slurp|facebookexternalhit|whatsapp/.test(value)) return "bot";
  if (/ipad|tablet|playbook|silk/.test(value)) return "tablette";
  if (/mobi|iphone|android|phone/.test(value)) return "mobile";
  return "ordinateur";
}

function isLikelyBot(userAgent) {
  return deviceType(userAgent) === "bot";
}

function normalizeReferrerHost(rawReferrer) {
  if (typeof rawReferrer !== "string" || rawReferrer.length > 2_048) return "";
  try {
    const hostname = new URL(rawReferrer).hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    // Une adresse IP ne doit jamais être conservée dans les statistiques.
    if (!hostname || isIP(hostname)) return "";
    return hostname.slice(0, 190);
  } catch {
    return "";
  }
}

function boundedReferrerHost(qrcodeId, hostname) {
  if (!hostname) return "";
  const existing = db.prepare(`
    SELECT 1 FROM scan_rollups
    WHERE qrcode_id = ? AND referrer_host = ?
    LIMIT 1
  `).get(qrcodeId, hostname);
  if (existing) return hostname;

  const distinctHosts = db.prepare(`
    SELECT COUNT(DISTINCT referrer_host) AS count
    FROM scan_rollups
    WHERE qrcode_id = ? AND referrer_host NOT IN ('', ?)
  `).get(qrcodeId, OTHER_REFERRER).count;
  return distinctHosts >= MAX_REFERRER_HOSTS_PER_QRCODE ? OTHER_REFERRER : hostname;
}

// Une seule fenêtre de déduplication par appareil et par QR code, partagée entre
// les scans mesurés et les scans perdus sur un QR code inactif.
function claimScanSlot(clientKey, timestamp) {
  for (const [key, expiresAt] of recentScanBuckets) {
    if (expiresAt <= timestamp) recentScanBuckets.delete(key);
  }
  if (recentScanBuckets.size >= MAX_RATE_BUCKETS) {
    const oldestKey = recentScanBuckets.keys().next().value;
    if (oldestKey !== undefined) recentScanBuckets.delete(oldestKey);
  }
  if (recentScanBuckets.has(clientKey)) return false;
  recentScanBuckets.set(clientKey, timestamp + SCAN_DEDUPE_WINDOW_MS);
  return true;
}

function recordScan(qrcodeId, request) {
  if (isLikelyBot(request.headers["user-agent"])) return false;
  const timestamp = now();
  const count = db.prepare(`
    SELECT COALESCE(SUM(scan_count), 0) AS count
    FROM scan_rollups WHERE qrcode_id = ?
  `).get(qrcodeId).count;
  if (count >= MAX_SCAN_EVENTS_PER_QR) return false;

  const clientKey = createHash("sha256")
    .update(`${qrcodeId}:${getClientIp(request)}`)
    .digest("hex");
  if (!claimScanSlot(clientKey, timestamp)) return false;

  const referrerHost = boundedReferrerHost(qrcodeId, normalizeReferrerHost(request.headers.referer));
  db.prepare(`
    INSERT INTO scan_events (qrcode_id, scanned_at, device_type, referrer_host)
    VALUES (?, ?, ?, ?)
  `).run(qrcodeId, timestamp, deviceType(request.headers["user-agent"]), referrerHost || null);
  return true;
}

// Un scan sur un QR code inactif est un scan perdu : c'est la preuve chiffrée de
// ce que coûte l'offre gratuite, donc le meilleur argument de vente dont on
// dispose. Un simple entier suffit — ni événement brut, ni référent, ni adresse IP,
// donc aucune contradiction avec la politique de confidentialité.
function countInactiveScan(qrcodeId, request) {
  if (isLikelyBot(request.headers["user-agent"])) return false;
  const timestamp = now();
  const clientKey = createHash("sha256")
    .update(`inactive:${qrcodeId}:${getClientIp(request)}`)
    .digest("hex");
  if (!claimScanSlot(clientKey, timestamp)) return false;
  db.prepare("UPDATE qrcodes SET inactive_scans = inactive_scans + 1 WHERE id = ?").run(qrcodeId);
  return true;
}

function scanStats(qrcodeId, days) {
  const timestamp = now();
  const since = timestamp - days * 24 * 60 * 60 * 1_000;
  const sinceDay = new Date(since).toISOString().slice(0, 10);
  const today = new Date(timestamp).toISOString().slice(0, 10);
  const totals = db.prepare(`
    SELECT COALESCE(SUM(scan_count), 0) AS total, MAX(last_scan_at) AS last_scan_at
    FROM scan_rollups WHERE qrcode_id = ?
  `).get(qrcodeId);
  const dailyRows = db.prepare(`
    SELECT day, SUM(scan_count) AS count
    FROM scan_rollups
    WHERE qrcode_id = ? AND day >= ?
    GROUP BY day
    ORDER BY day ASC
  `).all(qrcodeId, sinceDay);
  const deviceRows = db.prepare(`
    SELECT device_type, SUM(scan_count) AS count
    FROM scan_rollups WHERE qrcode_id = ?
    GROUP BY device_type ORDER BY count DESC
  `).all(qrcodeId);
  const referrerRows = db.prepare(`
    SELECT referrer_host, SUM(scan_count) AS count
    FROM scan_rollups
    WHERE qrcode_id = ? AND referrer_host != ''
    GROUP BY referrer_host ORDER BY count DESC LIMIT 6
  `).all(qrcodeId);

  const counts = new Map(dailyRows.map((row) => [row.day, row.count]));
  const daily = [];
  const todayUtc = Date.parse(`${today}T00:00:00Z`);
  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const date = new Date(todayUtc - offset * 24 * 60 * 60 * 1_000).toISOString().slice(0, 10);
    daily.push({ date, count: counts.get(date) || 0 });
  }
  return {
    total: totals.total,
    lastScanAt: isoDate(totals.last_scan_at),
    periodDays: days,
    daily,
    devices: deviceRows.map((row) => ({ type: row.device_type, count: row.count })),
    referrers: referrerRows.map((row) => ({ host: row.referrer_host, count: row.count })),
  };
}

async function readJson(request, maxBytes = MAX_JSON_BYTES) {
  const contentType = String(request.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpError(415, "Le contenu de la requête doit être au format JSON.", "unsupported_media_type");
  }
  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const chunks = [];
    request.on("data", (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBytes) {
        settled = true;
        request.removeAllListeners("data");
        request.resume();
        reject(new HttpError(413, "La requête est trop volumineuse.", "payload_too_large"));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (settled) return;
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve(text ? JSON.parse(text) : {});
      } catch {
        reject(new HttpError(400, "Le JSON envoyé est invalide.", "invalid_json"));
      }
    });
    request.on("error", () => {
      if (!settled) reject(new HttpError(400, "La requête n’a pas pu être lue.", "invalid_request"));
    });
  });
}

function readRawBody(request, maxBytes = MAX_JSON_BYTES) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const chunks = [];
    request.on("data", (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBytes) {
        settled = true;
        request.removeAllListeners("data");
        request.resume();
        reject(new HttpError(413, "La requête est trop volumineuse.", "payload_too_large"));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (settled) return;
      resolve(Buffer.concat(chunks));
    });
    request.on("error", () => {
      if (!settled) reject(new HttpError(400, "La requête n’a pas pu être lue.", "invalid_request"));
    });
  });
}

function securityHeaders(response, options = {}) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", options.noReferrer ? "no-referrer" : "strict-origin-when-cross-origin");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader(
    "Content-Security-Policy",
    options.contentSecurityPolicy || "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
  );
  if (PUBLIC_ORIGIN.startsWith("https://")) {
    response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}

function sendJson(response, status, payload, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(payload));
  securityHeaders(response);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  response.end(body);
}

function sendHtml(response, status, html, extraHeaders = {}, securityOptions = {}) {
  const body = Buffer.from(html);
  securityHeaders(response, securityOptions);
  response.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  response.end(body);
}

function sendError(response, error) {
  const isStripe = isStripeSdkError(error);
  const status = isStripe ? 502 : (error instanceof HttpError ? error.status : 500);
  let message = error instanceof HttpError ? error.message : "Une erreur interne est survenue.";
  let code = error instanceof HttpError ? error.code : "internal_error";
  if (isStripe) {
    // Le détail utile est pour l'exploitant, pas pour le client : il reste dans
    // le journal, filtré, et la réponse se limite à un message actionnable.
    message = "Le service de paiement est momentanément indisponible. Réessayez dans un instant.";
    code = "billing_unavailable";
  }
  if (status >= 500) {
    // La pile est conservée pour le diagnostic, mais jamais l'objet brut : il
    // peut contenir la requête envoyée, donc l'authentification.
    console.error(redactSecrets(error?.stack || error?.message || String(error)));
  }
  const headers = error.retryAfter ? { "Retry-After": String(error.retryAfter) } : {};
  if (response.headersSent) {
    response.destroy();
    return;
  }
  sendJson(response, status, { error: { code, message } }, headers);
}

function publicUser(row) {
  return {
    id: row.userId ?? row.id,
    displayName: row.displayName ?? row.display_name,
    email: row.email,
    emailVerified: Boolean(row.emailVerifiedAt ?? row.email_verified_at),
    // L'adresse en attente est exposée pour que l'interface puisse rappeler qu'un
    // changement est en cours : sans cela, il disparaîtrait à chaque rechargement
    // alors que le changement, lui, attend toujours son lien.
    pendingEmail: row.pendingEmail ?? row.pending_email ?? null,
  };
}

async function handleAuthApi(request, response, url) {
  if (request.method === "GET" && url.pathname === "/api/auth/me") {
    const session = getSession(request);
    if (!session) {
      sendJson(response, 200, { user: null, csrfToken: null });
      return;
    }
    sendJson(response, 200, {
      user: publicUser(session),
      csrfToken: session.csrfToken,
      entitlement: resolveEntitlement(session.userId),
      subscription: getSubscriptionSummary(session.userId),
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/register") {
    const ip = getClientIp(request);
    checkRateLimit(`register:${ip}`, 5, 60 * 60 * 1_000);
    verifyBrowserOrigin(request);
    const body = requireObject(await readJson(request));
    const displayName = validateDisplayName(body.displayName);
    const email = validateEmail(body.email);
    const password = validatePassword(body.password);
    const passwordHash = await hashPassword(password);
    const timestamp = now();
    let result;
    try {
      result = db.prepare(`
        INSERT INTO users (display_name, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
      `).run(displayName, email, passwordHash, timestamp);
    } catch (error) {
      if (String(error.message).includes("UNIQUE")) {
        throw new HttpError(409, "Un compte utilise déjà cette adresse e-mail.", "email_already_used");
      }
      throw error;
    }
    const userId = Number(result.lastInsertRowid);
    const createdSession = createSession(userId, request);
    // Le compte existe immédiatement : l'utilisateur est connecté, mais il ne
    // peut rien publier tant que l'adresse n'est pas confirmée.
    const verification = issueAuthToken(userId, VERIFICATION_PURPOSE, VERIFICATION_TOKEN_TTL_MS);
    await sendVerificationEmail({ email, display_name: displayName }, verification.token);
    sendJson(response, 201, {
      user: { id: userId, displayName, email, emailVerified: false },
      csrfToken: createdSession.csrfToken,
      verification: { required: true, resendDelaySeconds: Math.round(MAIL_RESEND_DELAY_MS / 1_000) },
    }, { "Set-Cookie": sessionCookie(createdSession.token) });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/login") {
    const ip = getClientIp(request);
    checkRateLimit(`login:${ip}`, 8, 15 * 60 * 1_000);
    verifyBrowserOrigin(request);
    const body = requireObject(await readJson(request));
    const email = validateEmail(body.email);
    if (typeof body.password !== "string" || body.password.length > 128 || body.password.length < 1) {
      throw new HttpError(400, "Mot de passe invalide.", "invalid_password");
    }
    const user = db.prepare(`
      SELECT id, display_name, email, password_hash, email_verified_at
      FROM users WHERE email = ?
    `).get(email);
    const valid = await verifyPassword(body.password, user?.password_hash || DUMMY_PASSWORD_HASH);
    if (!user || !valid) {
      throw new HttpError(401, "E-mail ou mot de passe incorrect.", "invalid_credentials");
    }
    db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now());
    const createdSession = createSession(user.id, request);
    sendJson(response, 200, {
      user: publicUser({
        id: user.id,
        display_name: user.display_name,
        email: user.email,
        email_verified_at: user.email_verified_at,
      }),
      csrfToken: createdSession.csrfToken,
    }, { "Set-Cookie": sessionCookie(createdSession.token) });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/logout") {
    verifyBrowserOrigin(request);
    const session = getSession(request);
    if (session) {
      verifyCsrf(request, session);
      db.prepare("DELETE FROM sessions WHERE id = ?").run(session.id);
    }
    sendJson(response, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
    return;
  }

  // Le lien de confirmation est la preuve : aucune session n'est requise, pour
  // que le clic fonctionne même après une expiration de session. En revanche
  // aucune session n'est créée non plus — un lien d'e-mail reste une
  // autorisation à usage unique, pas un billet de connexion.
  if (request.method === "POST" && url.pathname === "/api/auth/verify-email") {
    checkRateLimit(`verify:${getClientIp(request)}`, 20, 15 * 60 * 1_000);
    verifyBrowserOrigin(request);
    const body = requireObject(await readJson(request));
    const token = cleanText(body.token, 128);
    const consumed = consumeAuthToken(token, VERIFICATION_PURPOSE);
    if (consumed) {
      const timestamp = now();
      db.prepare(`
        UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?
      `).run(timestamp, consumed.user_id);
      // Le jeton consommé reste en base (purgeAuthTokens l'efface après 24 h) :
      // c'est lui qui permet à un second clic sur le même lien de renvoyer une
      // réussite au lieu d'une erreur.
      sendJson(response, 200, { verified: true });
      return;
    }
    // Un second clic sur le même lien ne doit pas enregistrer une erreur alors
    // que l'adresse est bien confirmée : c'est le cas le plus fréquent quand on
    // recharge la page. Le jeton reste la preuve, rien n'est divulgué de plus.
    const previous = authTokenState(token, VERIFICATION_PURPOSE);
    if (previous?.used_at) {
      const owner = db.prepare("SELECT email_verified_at FROM users WHERE id = ?").get(previous.user_id);
      if (owner?.email_verified_at) {
        sendJson(response, 200, { verified: true });
        return;
      }
    }
    throw new HttpError(400, "Ce lien de confirmation est invalide ou a expiré.", "invalid_token");
  }

  if (request.method === "POST" && url.pathname === "/api/auth/email/resend") {
    const ip = getClientIp(request);
    checkRateLimit(`resend:${ip}`, 20, 60 * 60 * 1_000);
    const session = requireSession(request);
    verifyCsrf(request, session);
    checkRateLimit(`resend:user:${session.userId}`, 10, 60 * 60 * 1_000);
    if (session.emailVerifiedAt) {
      sendJson(response, 200, { verified: true });
      return;
    }
    await issueAndSendVerification(session.userId);
    sendJson(response, 200, { sent: true, resendDelaySeconds: Math.round(MAIL_RESEND_DELAY_MS / 1_000) });
    return;
  }

  // Réponse volontairement identique que le compte existe ou non : cette
  // adresse ne doit pas pouvoir servir à découvrir qui a un compte QROOD.
  if (request.method === "POST" && url.pathname === "/api/auth/password/forgot") {
    const ip = getClientIp(request);
    checkRateLimit(`forgot:${ip}`, 5, 60 * 60 * 1_000);
    verifyBrowserOrigin(request);
    const body = requireObject(await readJson(request));
    const email = validateEmail(body.email);
    // La clé de compteur est un condensat de l'adresse : les seaux en mémoire
    // ne conservent donc aucune adresse en clair.
    checkRateLimit(`forgot:mail:${hashToken(email)}`, 3, 60 * 60 * 1_000);
    const user = db.prepare("SELECT id, display_name, email FROM users WHERE email = ?").get(email);
    if (user) {
      await issueAndSendReset(user);
    }
    sendJson(response, 200, { accepted: true });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/password/reset") {
    checkRateLimit(`reset:${getClientIp(request)}`, 10, 60 * 60 * 1_000);
    verifyBrowserOrigin(request);
    const body = requireObject(await readJson(request));
    const token = cleanText(body.token, 128);
    const password = validatePassword(body.password);
    const consumed = consumeAuthToken(token, RESET_PURPOSE);
    if (!consumed) {
      throw new HttpError(400, "Ce lien de réinitialisation est invalide ou a expiré.", "invalid_token");
    }
    const passwordHash = await hashPassword(password);
    const timestamp = now();
    db.prepare("UPDATE users SET password_hash = ?, email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?")
      .run(passwordHash, timestamp, consumed.user_id);
    // Un changement de mot de passe ferme les sessions ouvertes : la
    // réinitialisation sert justement à reprendre la main sur un compte dont
    // quelqu'un d'autre aurait obtenu l'accès.
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(consumed.user_id);
    db.prepare("DELETE FROM auth_tokens WHERE user_id = ?").run(consumed.user_id);
    sendJson(response, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
    return;
  }

  throw new HttpError(404, "Ressource introuvable.", "not_found");
}

// -- Gestion du compte ------------------------------------------------------
//
// Toute action qui change l'identité du compte — adresse, mot de passe,
// suppression — exige le mot de passe actuel, en plus du jeton de session. Un
// cookie volé sur un poste partagé donne l'accès à la bibliothèque, pas la
// propriété du compte : sans ce second facteur, un attaquant s'y installerait
// durablement en changeant l'adresse, ce qui coupe aussi la réinitialisation
// de mot de passe à la victime.

async function requireCurrentPassword(session, body) {
  if (typeof body.currentPassword !== "string" || body.currentPassword.length < 1 || body.currentPassword.length > 128) {
    throw new HttpError(400, "Saisis ton mot de passe actuel pour confirmer.", "current_password_required");
  }
  const row = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(session.userId);
  const valid = await verifyPassword(body.currentPassword, row?.password_hash || DUMMY_PASSWORD_HASH);
  if (!row || !valid) {
    throw new HttpError(403, "Mot de passe actuel incorrect.", "invalid_current_password");
  }
}

// Ferme les autres sessions sans toucher à celle qui vient d'agir : sans cela,
// changer son mot de passe depuis un poste déconnecterait l'écran en cours, et
// l'utilisateur pourrait croire s'être déconnecté lui-même.
function revokeOtherSessions(userId, keepSessionId) {
  db.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").run(userId, keepSessionId);
}

function hasLiveSubscription(userId) {
  const row = db.prepare(`
    SELECT 1 AS live FROM subscriptions
    WHERE user_id = ? AND status NOT IN ('canceled','incomplete_expired')
    LIMIT 1
  `).get(userId);
  return Boolean(row);
}

function buildAccountExport(userId) {
  const user = db.prepare(`
    SELECT display_name, email, email_verified_at, created_at, pending_email FROM users WHERE id = ?
  `).get(userId);
  const qrcodes = db.prepare(`
    SELECT q.id, q.public_token, q.name, q.mode, q.destination, q.contact_data, q.vcard,
           q.foreground, q.background, q.style, q.logo, q.is_active, q.created_at, q.updated_at,
           COALESCE((SELECT SUM(r.scan_count) FROM scan_rollups r WHERE r.qrcode_id = q.id), 0) AS scan_count,
           (SELECT MAX(r.last_scan_at) FROM scan_rollups r WHERE r.qrcode_id = q.id) AS last_scan_at
    FROM qrcodes q WHERE q.user_id = ? ORDER BY q.id
  `).all(userId);
  // Les statistiques sortent agrégées par jour, type d'appareil et domaine de
  // provenance : c'est déjà ce que l'interface affiche, et cela évite d'exporter
  // un journal de scans horodaté événement par événement.
  const rollups = db.prepare(`
    SELECT r.qrcode_id, r.day, r.device_type, r.referrer_host, r.scan_count, r.last_scan_at
    FROM scan_rollups r JOIN qrcodes q ON q.id = r.qrcode_id
    WHERE q.user_id = ?
    ORDER BY r.qrcode_id, r.day
  `).all(userId);
  return {
    exportedAt: new Date().toISOString(),
    account: {
      displayName: user?.display_name,
      email: user?.email,
      emailVerified: Boolean(user?.email_verified_at),
      createdAt: isoDate(user?.created_at),
      pendingEmail: user?.pending_email ?? null,
    },
    subscription: getSubscriptionSummary(userId),
    qrcodes: qrcodes.map((row) => ({
      id: row.id,
      publicToken: row.public_token,
      name: row.name,
      mode: row.mode,
      destination: row.destination,
      contactData: parseStoredJson(row.contact_data),
      vcard: row.vcard,
      appearance: { foreground: row.foreground, background: row.background, style: row.style, logo: row.logo },
      isActive: Boolean(row.is_active),
      createdAt: isoDate(row.created_at),
      updatedAt: isoDate(row.updated_at),
      scanCount: row.scan_count,
      lastScanAt: isoDate(row.last_scan_at),
    })),
    statistics: rollups.map((row) => ({
      qrcodeId: row.qrcode_id,
      day: row.day,
      deviceType: row.device_type,
      referrerHost: row.referrer_host,
      scanCount: row.scan_count,
      lastScanAt: isoDate(row.last_scan_at),
    })),
  };
}

async function handleAccountApi(request, response, url, session) {
  if (request.method === "PATCH" && url.pathname === "/api/account/profile") {
    verifyCsrf(request, session);
    checkRateLimit(`profile:${session.userId}`, 20, 60 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const displayName = validateDisplayName(body.displayName);
    db.prepare("UPDATE users SET display_name = ? WHERE id = ?").run(displayName, session.userId);
    sendJson(response, 200, { user: publicUser({ ...session, displayName }) });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/account/email") {
    verifyCsrf(request, session);
    checkRateLimit(`email-change:${session.userId}`, 5, 60 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    await requireCurrentPassword(session, body);
    const email = validateEmail(body.email);
    if (email === session.email) {
      throw new HttpError(400, "Cette adresse est déjà celle de ton compte.", "email_unchanged");
    }
    // L'adresse en attente est réservée le temps de la confirmation : sans cela,
    // deux comptes pourraient viser la même boîte, et le premier lien ouvert
    // adopterait une adresse que le second avait déjà demandée.
    const taken = db.prepare("SELECT 1 AS taken FROM users WHERE email = ? OR pending_email = ?")
      .get(email, email);
    if (taken) {
      throw new HttpError(409, "Cette adresse est déjà utilisée par un autre compte.", "email_taken");
    }
    db.prepare("UPDATE users SET pending_email = ? WHERE id = ?").run(email, session.userId);
    const issued = issueAuthToken(session.userId, EMAIL_CHANGE_PURPOSE, EMAIL_CHANGE_TOKEN_TTL_MS);
    const user = db.prepare("SELECT display_name, pending_email FROM users WHERE id = ?").get(session.userId);
    await sendEmailChangeEmail(user, issued.token);
    sendJson(response, 200, { pendingEmail: email });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/account/email/confirm") {
    verifyCsrf(request, session);
    checkRateLimit(`email-confirm:${session.userId}`, 10, 60 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const token = cleanText(body.token, 128);
    // Le propriétaire est contrôlé *avant* la consommation. Consommer d'abord
    // laisserait quiconque détient le lien — même sans la session du titulaire
    // — le brûler et interdire définitivement le changement à son destinataire :
    // un simple mot de passe.envoyé par erreur suffirait à tout bloquer.
    const state = authTokenState(token, EMAIL_CHANGE_PURPOSE);
    if (!state || state.user_id !== session.userId || state.used_at !== null || state.expires_at <= now()) {
      throw new HttpError(400, "Ce lien de confirmation est invalide ou a expiré.", "invalid_token");
    }
    // La consommation reste atomique : c'est elle, et non la lecture au-dessus,
    // qui garantit qu'un lien ne sert qu'une fois.
    if (!consumeAuthToken(token, EMAIL_CHANGE_PURPOSE)) {
      throw new HttpError(400, "Ce lien de confirmation est invalide ou a expiré.", "invalid_token");
    }
    const user = db.prepare("SELECT email, pending_email FROM users WHERE id = ?").get(session.userId);
    if (!user?.pending_email) {
      throw new HttpError(400, "Aucun changement d'adresse n'est en attente.", "no_pending_email");
    }
    // Le changement est refusé si l'adresse a été prise entre-temps. La session
    // est fermée pour toutes les autres : l'ancienne adresse ne reçoit plus rien
    // et l'ancienne session ne doit pas survivre au transfert de propriété.
    const taken = db.prepare("SELECT 1 AS taken FROM users WHERE email = ? AND id != ?")
      .get(user.pending_email, session.userId);
    if (taken) {
      db.prepare("UPDATE users SET pending_email = NULL WHERE id = ?").run(session.userId);
      throw new HttpError(409, "Cette adresse vient d'être utilisée par un autre compte.", "email_taken");
    }
    db.prepare("UPDATE users SET email = ?, pending_email = NULL, email_verified_at = ? WHERE id = ?")
      .run(user.pending_email, now(), session.userId);
    db.prepare("DELETE FROM auth_tokens WHERE user_id = ?").run(session.userId);
    revokeOtherSessions(session.userId, session.id);
    sendJson(response, 200, {
      // `pendingEmail` est forcé à null : la session en mémoire portait encore
      // l'attente, que la ligne vient de vider en base. Sans cette précision, la
      // page afficherait un changement en cours alors qu'il est accompli.
      user: publicUser({ ...session, email: user.pending_email, emailVerifiedAt: now(), pendingEmail: null }),
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/account/password") {
    verifyCsrf(request, session);
    checkRateLimit(`password-change:${session.userId}`, 5, 60 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    await requireCurrentPassword(session, body);
    const password = validatePassword(body.newPassword);
    if (await verifyPassword(password, db.prepare("SELECT password_hash FROM users WHERE id = ?").get(session.userId).password_hash)) {
      throw new HttpError(400, "Le nouveau mot de passe doit différer de l'ancien.", "password_unchanged");
    }
    const passwordHash = await hashPassword(password);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(passwordHash, session.userId);
    db.prepare("DELETE FROM auth_tokens WHERE user_id = ?").run(session.userId);
    revokeOtherSessions(session.userId, session.id);
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/account/export") {
    verifyCsrf(request, session);
    checkRateLimit(`export:${session.userId}`, 6, 60 * 60 * 1_000);
    // Un export passe par POST et non par GET : en GET, un simple lien — ou une
    // balise image sur un site tiers — suffirait à déclencher le téléchargement
    // du fichier chez quelqu'un d'autre que le titulaire.
    const stamp = new Date().toISOString().slice(0, 10);
    sendJson(response, 200, buildAccountExport(session.userId), {
      "Content-Disposition": `attachment; filename="qrood-donnees-${stamp}.json"`,
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/account/delete") {
    verifyCsrf(request, session);
    checkRateLimit(`delete:${session.userId}`, 5, 60 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    await requireCurrentPassword(session, body);
    if (cleanText(body.confirmation, 32) !== "SUPPRIMER") {
      throw new HttpError(400, "Confirme la suppression en écrivant SUPPRIMER.", "confirmation_required");
    }
    // Supprimer un compte souscripteur laisserait un abonnement se rebiller sans
    // personne pour le piloter : il faut passer par le portail d'abord.
    if (hasLiveSubscription(session.userId)) {
      throw new HttpError(
        409,
        "Résilie d'abord ton abonnement depuis le portail de facturation, puis reviens supprimer ton compte.",
        "subscription_active",
      );
    }
    // users porte les clés étrangères en cascade : QR codes, scans, sessions,
    // jetons et abonnements partent avec le compte, en une transaction.
    db.exec("BEGIN");
    try {
      db.prepare("DELETE FROM users WHERE id = ?").run(session.userId);
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
    sendJson(response, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
    return;
  }

  throw new HttpError(404, "Ressource introuvable.", "not_found");
}

// sur un compteur en mémoire : il tient après un redémarrage, et il empêche
// d'utiliser l'endpoint pour remplir la boîte d'un tiers.
async function issueAndSendVerification(userId) {
  const last = lastAuthToken(userId, VERIFICATION_PURPOSE);
  if (last && MAIL_RESEND_DELAY_MS > 0 && now() - last.created_at < MAIL_RESEND_DELAY_MS) {
    const error = new HttpError(
      429,
      "Un e-mail de confirmation vient d'être envoyé. Patientez quelques instants avant d'en demander un nouveau.",
      "resend_too_soon",
    );
    error.retryAfter = Math.max(1, Math.ceil((MAIL_RESEND_DELAY_MS - (now() - last.created_at)) / 1000));
    throw error;
  }
  const user = db.prepare("SELECT display_name, email FROM users WHERE id = ?").get(userId);
  if (!user) throw new HttpError(404, "Compte introuvable.", "not_found");
  const issued = issueAuthToken(userId, VERIFICATION_PURPOSE, VERIFICATION_TOKEN_TTL_MS);
  await sendVerificationEmail(user, issued.token);
}

async function issueAndSendReset(user) {
  const last = lastAuthToken(user.id, RESET_PURPOSE);
  if (last && MAIL_RESEND_DELAY_MS > 0 && now() - last.created_at < MAIL_RESEND_DELAY_MS) {
    // La réponse reste neutre : le demandeur n'a pas à savoir qu'un lien
    // circule déjà, ni être puni pour une cadence trop rapide.
    return;
  }
  const issued = issueAuthToken(user.id, RESET_PURPOSE, RESET_TOKEN_TTL_MS);
  await sendPasswordResetEmail(user, issued.token);
}

async function handleQrApi(request, response, url, session) {
  if (request.method === "GET" && url.pathname === "/api/qrcodes") {
    checkRateLimit(`library:${session.userId}`, 120, 60 * 1_000);
    const { limit, offset } = parsePagination(url);
    const entitlement = resolveEntitlement(session.userId);
    sendJson(response, 200, {
      qrcodes: listQrcodes(session.userId, limit, offset, entitlement),
      total: entitlement.used,
      entitlement,
      limit,
      offset,
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/qrcodes") {
    verifyCsrf(request, session);
    requireVerifiedEmail(session);
    checkRateLimit(`create:${session.userId}`, 120, 60 * 60 * 1_000);
    const body = requireObject(await readJson(request, MAX_QR_JSON_BYTES));
    const entitlement = resolveEntitlement(session.userId);
    const payload = validateQrPayload(body, entitlement);
    if (payload.legacyKey) {
      const existing = db.prepare("SELECT id FROM qrcodes WHERE user_id = ? AND legacy_key = ?").get(
        session.userId,
        payload.legacyKey,
      );
      if (existing) {
        sendJson(response, 200, { qrcode: mapQrcode(getQrcodeStatsRow(existing.id), entitlement) });
        return;
      }
    }
    // L'ordre compte : le quota de stockage d'abord (409), puis le quota d'actifs
    // (402), pour que le message désigne la contrainte réellement bloquante.
    if (entitlement.maxQrcodes !== null && entitlement.used >= entitlement.maxQrcodes) {
      throw new HttpError(
        409,
        `Votre compte compte ${entitlement.used} QR codes pour ${entitlement.maxQrcodes} places. Passez à une offre supérieure pour en créer davantage.`,
        "qrcode_limit_reached",
      );
    }
    if (entitlement.maxActive !== null && entitlement.usedActive >= entitlement.maxActive) {
      throw new HttpError(
        402,
        `L’offre ${entitlement.label} n’autorise qu’un seul QR code actif à la fois. Désactivez un QR code existant pour en activer un autre.`,
        "active_limit_reached",
      );
    }
    const publicToken = randomToken(12);
    const timestamp = now();
    const result = db.prepare(`
      INSERT INTO qrcodes (
        user_id, public_token, name, mode, destination, contact_data, vcard,
        foreground, background, style, logo, legacy_key, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      session.userId,
      publicToken,
      payload.name,
      payload.mode,
      payload.destination,
      payload.contactData ? JSON.stringify(payload.contactData) : null,
      payload.vcard,
      payload.foreground,
      payload.background,
      JSON.stringify(payload.style),
      payload.logo,
      payload.legacyKey,
      timestamp,
      timestamp,
    );
    const row = db.prepare(`
      SELECT q.*, 0 AS scan_count, 0 AS scans_week, NULL AS last_scan_at
      FROM qrcodes q WHERE q.id = ?
    `).get(Number(result.lastInsertRowid));
    sendJson(response, 201, { qrcode: mapQrcode(row, entitlement) });
    return;
  }

  const idMatch = url.pathname.match(/^\/api\/qrcodes\/(\d+)$/);
  if (idMatch) {
    const id = Number(idMatch[1]);
    if (!PUBLIC_ID_PATTERN.test(String(id))) throw new HttpError(404, "QR code introuvable.", "not_found");
    const existing = getOwnedQrcode(session.userId, id);
    if (!existing) throw new HttpError(404, "QR code introuvable.", "not_found");

    if (request.method === "PUT") {
      verifyCsrf(request, session);
      requireVerifiedEmail(session);
      const entitlement = resolveEntitlement(session.userId);
      const payload = validateQrPayload(
        requireObject(await readJson(request, MAX_QR_JSON_BYTES)),
        entitlement,
        existing,
      );
      db.prepare(`
        UPDATE qrcodes
        SET name = ?, mode = ?, destination = ?, contact_data = ?, vcard = ?,
            foreground = ?, background = ?, style = ?, logo = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
      `).run(
        payload.name,
        payload.mode,
        payload.destination,
        payload.contactData ? JSON.stringify(payload.contactData) : null,
        payload.vcard,
        payload.foreground,
        payload.background,
        JSON.stringify(payload.style),
        payload.logo,
        now(),
        id,
        session.userId,
      );
      const updated = getQrcodeStatsRow(id);
      sendJson(response, 200, { qrcode: mapQrcode(updated, entitlement) });
      return;
    }

    if (request.method === "DELETE") {
      verifyCsrf(request, session);
      db.prepare("DELETE FROM qrcodes WHERE id = ? AND user_id = ?").run(id, session.userId);
      sendJson(response, 200, { ok: true });
      return;
    }
  }

  const statusMatch = url.pathname.match(/^\/api\/qrcodes\/(\d+)\/status$/);
  if (request.method === "POST" && statusMatch) {
    if (!PUBLIC_ID_PATTERN.test(statusMatch[1])) {
      throw new HttpError(404, "QR code introuvable.", "not_found");
    }
    const id = Number(statusMatch[1]);
    const existing = getOwnedQrcode(session.userId, id);
    if (!existing) throw new HttpError(404, "QR code introuvable.", "not_found");
    verifyCsrf(request, session);
    checkRateLimit(`status:${session.userId}`, 300, 60 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    // Le booléen est exigé : sans cette garde, `{}` ou `{ active: 1 }`
    // désactiveraient un QR code par accident.
    if (typeof body.active !== "boolean") {
      throw new HttpError(400, "Le champ « active » doit être un booléen.", "invalid_body");
    }
    if (body.active && existing.is_active !== 1) {
      // Réactiver remet un lien en ligne : c'est une publication, donc elle
      // exige une adresse confirmée. Désactiver, ci-dessus, reste toujours
      // possible, y compris sans confirmation.
      requireVerifiedEmail(session);
      const entitlement = resolveEntitlement(session.userId);
      if (entitlement.maxActive !== null && entitlement.usedActive >= entitlement.maxActive) {
        throw new HttpError(
          402,
          `L’offre ${entitlement.label} n’autorise qu’un seul QR code actif à la fois. Désactivez un QR code existant pour activer celui-ci.`,
          "active_limit_reached",
        );
      }
    }
    if ((body.active ? 1 : 0) !== existing.is_active) {
      // Ni le jeton public ni la destination ne bougent : un QR code imprimé
      // reste réactivable à l'identique, ce qui rend la désactivation réversible.
      db.prepare("UPDATE qrcodes SET is_active = ?, updated_at = ? WHERE id = ? AND user_id = ?").run(
        body.active ? 1 : 0,
        now(),
        id,
        session.userId,
      );
    }
    const entitlement = resolveEntitlement(session.userId);
    sendJson(response, 200, { qrcode: mapQrcode(getQrcodeStatsRow(id), entitlement), entitlement });
    return;
  }

  const statsMatch = url.pathname.match(/^\/api\/qrcodes\/(\d+)\/stats$/);
  if (request.method === "GET" && statsMatch) {
    if (!PUBLIC_ID_PATTERN.test(statsMatch[1])) {
      throw new HttpError(404, "QR code introuvable.", "not_found");
    }
    const id = Number(statsMatch[1]);
    checkRateLimit(`stats:${session.userId}:${id}`, 120, 60 * 1_000);
    const existing = getOwnedQrcode(session.userId, id);
    if (!existing) throw new HttpError(404, "QR code introuvable.", "not_found");
    const entitlement = resolveEntitlement(session.userId);
    const defaultDays = Math.min(30, entitlement.statsDays);
    const requestedDays = Number(url.searchParams.get("days") || defaultDays);
    const days = Number.isInteger(requestedDays)
      ? Math.min(entitlement.statsDays, Math.max(7, requestedDays))
      : defaultDays;
    sendJson(response, 200, { stats: scanStats(id, days), maxStatsDays: entitlement.statsDays });
    return;
  }

  throw new HttpError(404, "Ressource introuvable.", "not_found");
}

async function handleApi(request, response, url) {
  if (url.pathname.startsWith("/api/auth/")) {
    await handleAuthApi(request, response, url);
    return;
  }
  if (url.pathname.startsWith("/api/qrcodes")) {
    const session = requireSession(request);
    await handleQrApi(request, response, url, session);
    return;
  }
  if (url.pathname.startsWith("/api/account/")) {
    const session = requireSession(request);
    await handleAccountApi(request, response, url, session);
    return;
  }
  if (url.pathname === "/api/billing/stripe/webhook") {
    // Avant toute session : Stripe n'a pas de cookie QROOD. La seule preuve
    // d'authenticité est la signature, vérifiée sur le corps brut.
    await handleStripeWebhook(request, response);
    return;
  }
  if (url.pathname.startsWith("/api/billing/")) {
    await handleBillingApi(request, response, url);
    return;
  }
  throw new HttpError(404, "Ressource introuvable.", "not_found");
}

async function handleBillingApi(request, response, url) {
  if (request.method === "GET" && url.pathname === "/api/billing/offers") {
    const prices = await readStripePrices();
    sendJson(response, 200, {
      // `false` = serveur sans facturation : l'interface doit le signaler
      // plutôt que d'afficher un prix fantôme.
      enabled: BILLING_ENABLED,
      configured: BILLING_CONFIGURED,
      webhooks: BILLING_WEBHOOKS_ENABLED,
      taxEnabled: true,
      offers: buildOffersPayload(prices),
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/billing/checkout") {
    const session = requireSession(request);
    verifyCsrf(request, session);
    // Avant la vérification de la configuration Stripe : un compte non
    // confirmé n'a pas à apprendre au passage que la facturation manque.
    requireVerifiedEmail(session);
    const body = requireObject(await readJson(request));
    const plan = cleanText(body.plan, 32);
    const url2 = await createCheckoutSession(session.userId, plan);
    sendJson(response, 200, { url: url2 });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/billing/portal") {
    const session = requireSession(request);
    verifyCsrf(request, session);
    const portalUrl = await createPortalSession(session.userId);
    sendJson(response, 200, { url: portalUrl });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/billing/confirm") {
    // Repli quand le webhook n'est pas encore arrivé : l'utilisateur vient de
    // payer et veut son offre immédiatement, pas après la prochaine livraison.
    const session = requireSession(request);
    verifyCsrf(request, session);
    // `/portal` reste ouvert : gérer un abonnement existant ne crée aucun
    // droit, alors que `confirm` en accorde un.
    requireVerifiedEmail(session);
    const body = requireObject(await readJson(request));
    const checkoutSessionId = cleanText(body.sessionId, 64);
    if (!/^cs_[A-Za-z0-9]{8,}$/.test(checkoutSessionId)) {
      throw new HttpError(400, "Référence de session de paiement invalide.", "invalid_session_id");
    }
    const synced = await confirmCheckoutSession(session.userId, checkoutSessionId);
    sendJson(response, 200, { synced, entitlement: resolveEntitlement(session.userId) });
    return;
  }

  throw new HttpError(404, "Ressource introuvable.", "not_found");
}

async function handleStripeWebhook(request, response) {
  if (!BILLING_WEBHOOKS_ENABLED) {
    throw new HttpError(
      503,
      "Les webhooks Stripe ne sont pas configurés sur ce serveur.",
      "webhooks_not_configured"
    );
  }
  const raw = await readRawBody(request, 512 * 1_024);
  const signature = request.headers["stripe-signature"];
  const stripe = await getStripe();
  let event;
  try {
    // La signature est vérifiée sur les octets bruts : toute re-sérialisation
    // du JSON invaliderait le HMAC.
    event = stripe.webhooks.constructEvent(raw, signature, STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    throw new HttpError(400, "Signature Stripe invalide.", "invalid_webhook_signature");
  }

  // `INSERT OR IGNORE` + `changes` : la livraison Stripe est « au moins une
  // fois », donc le même `event.id` doit être traité une seule fois.
  const inserted = db.prepare(`
    INSERT OR IGNORE INTO stripe_events (event_id, type, received_at) VALUES (?, ?, ?)
  `).run(event.id, event.type, now());
  if (inserted.changes === 0) {
    sendJson(response, 200, { received: true, duplicate: true });
    return;
  }
  try {
    await processStripeEvent(event);
  } catch (error) {
    // Le marqueur doit disparaître, sinon Stripe ne réessaiera jamais cet
    // événement et l'utilisateur resterait sans son offre.
    db.prepare("DELETE FROM stripe_events WHERE event_id = ?").run(event.id);
    console.error(`qrood billing: échec du traitement de ${event.type} (${redactSecrets(error.message)}).`);
    throw new HttpError(502, "Le paiement est enregistré mais l’offre n’a pas pu être appliquée.", "webhook_failed");
  }
  sendJson(response, 200, { received: true });
}

async function confirmCheckoutSession(userId, checkoutSessionId) {
  const stripe = await getStripe();
  const session = await stripe.checkout.sessions.retrieve(checkoutSessionId);
  const customerId = typeof session.customer === "string" ? session.customer : session.customer?.id;
  // Sans ce contrôle, un utilisateur qui devinerait un `session_id` pourrait
  // appliquer l'abonnement d'un autre compte au sien.
  const ownerId = findUserIdByStripeCustomer(customerId);
  if (ownerId !== userId) return false;
  const subscriptionId = typeof session.subscription === "string" ? session.subscription : session.subscription?.id;
  if (!subscriptionId) return false;
  syncSubscriptionFromStripe(await stripe.subscriptions.retrieve(subscriptionId));
  return true;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function contactPage(row) {
  const contact = JSON.parse(row.contact_data);
  const details = [
    contact.company,
    contact.phone,
    contact.email,
    contact.website,
    contact.address,
  ].filter(Boolean);
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>${escapeHtml(row.name)} — QROOD</title>
  <style>
    :root{color-scheme:light;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#101b33;background:#f5f6f9}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at top right,#ecebff,transparent 42%),#f5f6f9}
    main{width:min(100%,440px);padding:38px;border:1px solid #e2e6ed;border-radius:24px;background:#fff;box-shadow:0 20px 60px rgba(16,27,51,.12)}
    .mark{width:34px;height:34px;display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-bottom:30px}.mark i{border-radius:3px;background:#101b33}.mark i:nth-child(2),.mark i:nth-child(3){background:#bd3c34}
    .kicker{margin:0;color:#bd3c34;font-size:11px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}h1{margin:10px 0 12px;font-size:32px;line-height:1.1;letter-spacing:-.05em}p{margin:0;color:#5f6f86;line-height:1.6}
    .details{display:grid;gap:9px;margin:25px 0}.detail{padding:12px 14px;border-radius:10px;background:#f6f7f9;color:#35425a;font-size:14px;overflow-wrap:anywhere}
    a{display:flex;min-height:52px;align-items:center;justify-content:center;border-radius:12px;color:#fff;background:#bd3c34;text-decoration:none;font-weight:800}small{display:block;margin-top:18px;color:#5f6f86;text-align:center}
  </style>
</head>
<body><main>
  <div class="mark" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
  <p class="kicker">Contact partagé avec QROOD</p>
  <h1>${escapeHtml(row.name)}</h1>
  <p>Ajoutez cette carte de visite à vos contacts.</p>
  <div class="details">${details.map((detail) => `<div class="detail">${escapeHtml(detail)}</div>`).join("")}</div>
  <a href="/c/${encodeURIComponent(row.public_token)}/vcard">Ajouter aux contacts</a>
  <small>Ce lien de contact peut être ajouté à vos favoris.</small>
</main></body></html>`;
}

function inactivePage() {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>QR code inactif — QROOD</title>
  <style>
    :root{color-scheme:light;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#101b33;background:#f5f6f9}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at top right,#ecebff,transparent 42%),#f5f6f9}
    main{width:min(100%,440px);padding:38px;border:1px solid #e2e6ed;border-radius:24px;background:#fff;box-shadow:0 20px 60px rgba(16,27,51,.12)}
    .mark{width:34px;height:34px;display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-bottom:30px}.mark i{border-radius:3px;background:#101b33}.mark i:nth-child(2),.mark i:nth-child(3){background:#bd3c34}
    .kicker{margin:0;color:#bd3c34;font-size:11px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}h1{margin:10px 0 12px;font-size:32px;line-height:1.1;letter-spacing:-.05em}p{margin:0;color:#5f6f86;font-size:15px;line-height:1.6}
    small{display:block;margin-top:22px;color:#5f6f86;font-size:12px;line-height:1.5}
  </style>
</head>
<body><main>
  <div class="mark" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
  <p class="kicker">QROOD</p>
  <h1>Ce QR code est désactivé</h1>
  <p>Son propriétaire a suspendu la mesure des scans, donc ce lien n’est plus actif. Le QR code imprimé n’est pas responsable&nbsp;: c’est son propriétaire qui l’a désactivé.</p>
  <small>Si ce QR code figure sur un support que vous n’avez pas créé, signalez-le à son propriétaire.</small>
</main></body></html>`;
}

function sendInactive(response, request) {
  sendHtml(
    response,
    410,
    request.method === "HEAD" ? "" : inactivePage(),
    // `must-revalidate` est indispensable : un 410 mis en cache par le
    // navigateur ou un proxy mobile deviendrait un mur définitif, alors que la
    // réactivation du QR code doit être immédiate et complète.
    { "Cache-Control": "no-store, must-revalidate" },
    { noReferrer: true },
  );
}

function handlePublicRoute(request, response, url) {
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  const linkMatch = url.pathname.match(new RegExp(`^/r/(${TOKEN_PATTERN.source})$`));
  if (linkMatch) {
    const token = linkMatch[1];
    checkPublicRouteLimits(request, token, "link", request.method === "GET");
    const row = db.prepare("SELECT * FROM qrcodes WHERE public_token = ? AND mode = 'link'").get(token);
    if (!row) {
      sendHtml(response, 404, "<!doctype html><meta charset=\"utf-8\"><title>Introuvable</title><p>Ce QR code n’existe pas ou a été supprimé.</p>", {}, { noReferrer: true });
      return true;
    }
    if (!row.is_active) {
      if (request.method === "GET") countInactiveScan(row.id, request);
      sendInactive(response, request);
      return true;
    }
    const destination = normalizeHttpUrl(row.destination);
    if (request.method === "GET") recordScan(row.id, request);
    securityHeaders(response, { noReferrer: true });
    response.writeHead(302, { Location: destination, "Cache-Control": "no-store" });
    response.end();
    return true;
  }

  const vcardMatch = url.pathname.match(new RegExp(`^/c/(${TOKEN_PATTERN.source})/vcard$`));
  if (vcardMatch) {
    const token = vcardMatch[1];
    checkPublicRouteLimits(request, token, "vcard");
    const row = db.prepare("SELECT * FROM qrcodes WHERE public_token = ? AND mode = 'contact'").get(token);
    if (!row) {
      sendHtml(response, 404, "<!doctype html><meta charset=\"utf-8\"><title>Introuvable</title><p>Cette carte n’existe pas ou a été supprimée.</p>", {}, { noReferrer: true });
      return true;
    }
    if (!row.is_active) {
      if (request.method === "GET") countInactiveScan(row.id, request);
      sendInactive(response, request);
      return true;
    }
    const body = Buffer.from(row.vcard, "utf8");
    securityHeaders(response, { noReferrer: true });
    response.writeHead(200, {
      "Content-Type": "text/vcard; charset=utf-8",
      "Content-Length": body.length,
      "Content-Disposition": 'attachment; filename="qrood-contact.vcf"',
      "Cache-Control": "no-store",
    });
    response.end(request.method === "HEAD" ? undefined : body);
    return true;
  }

  const contactMatch = url.pathname.match(new RegExp(`^/c/(${TOKEN_PATTERN.source})$`));
  if (contactMatch) {
    const token = contactMatch[1];
    checkPublicRouteLimits(request, token, "contact", request.method === "GET");
    const row = db.prepare("SELECT * FROM qrcodes WHERE public_token = ? AND mode = 'contact'").get(token);
    if (!row) {
      sendHtml(response, 404, "<!doctype html><meta charset=\"utf-8\"><title>Introuvable</title><p>Cette carte n’existe pas ou a été supprimée.</p>", {}, { noReferrer: true });
      return true;
    }
    if (!row.is_active) {
      if (request.method === "GET") countInactiveScan(row.id, request);
      sendInactive(response, request);
      return true;
    }
    if (request.method === "GET") recordScan(row.id, request);
    const html = request.method === "HEAD" ? "" : contactPage(row);
    sendHtml(response, 200, html, {}, { noReferrer: true });
    return true;
  }
  return false;
}

async function serveStatic(request, response, url) {
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  const fileName = staticFiles.get(url.pathname);
  if (!fileName) return false;
  const body = await readFile(path.join(ROOT, fileName));
  securityHeaders(response);
  response.writeHead(200, {
    "Content-Type": mimeTypes.get(path.extname(fileName)) || "application/octet-stream",
    "Content-Length": body.length,
    "Cache-Control": "no-cache",
  });
  response.end(request.method === "HEAD" ? undefined : body);
  return true;
}

function scheduleIdleShutdown() {
  if (IDLE_TIMEOUT_MS <= 0) return;
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => shutdown("inactivity"), IDLE_TIMEOUT_MS);
}

async function handleApiDispatch(request, response, url) {
  if (request.method === "GET" && url.pathname === "/api/health") {
    sendJson(response, 200, { status: "ok" });
    return true;
  }
  if (url.pathname.startsWith("/api/")) {
    await handleApi(request, response, url);
    return true;
  }
  return false;
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", PUBLIC_ORIGIN);
    if (url.pathname !== "/api/health") scheduleIdleShutdown();
    if (await handleApiDispatch(request, response, url)) return;
    if (handlePublicRoute(request, response, url)) return;
    if (await serveStatic(request, response, url)) return;
    throw new HttpError(404, "Ressource introuvable.", "not_found");
  } catch (error) {
    sendError(response, error);
  }
});
server.requestTimeout = 30_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 100;

function shutdown(reason = "manual") {
  if (shuttingDown) return;
  shuttingDown = true;
  if (idleTimer) clearTimeout(idleTimer);
  console.log(`qrood server stopping (${reason}).`);
  const forceTimer = setTimeout(() => process.exit(1), 3_000);
  forceTimer.unref();
  server.close(() => {
    db.close();
    clearTimeout(forceTimer);
    process.exit(0);
  });
  server.closeIdleConnections?.();
}

setInterval(() => {
  const timestamp = now();
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(timestamp);
  db.prepare("DELETE FROM scan_events WHERE scanned_at < ?").run(
    timestamp - MAX_SCAN_RETENTION_DAYS * 24 * 60 * 60 * 1_000,
  );
  db.prepare("DELETE FROM stripe_events WHERE received_at < ?").run(timestamp - 7 * 24 * 60 * 60 * 1_000);
  purgeAuthTokens();
  pruneRateBuckets();
  for (const [key, expiresAt] of recentScanBuckets) {
    if (expiresAt <= timestamp) recentScanBuckets.delete(key);
  }
}, 15 * 60 * 1_000).unref();

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

server.listen(PORT, HOST, () => {
  scheduleIdleShutdown();
  const idleLabel = IDLE_TIMEOUT_MS <= 0
    ? "inactivité : arrêt désactivé"
    : `inactivité : arrêt après ${Math.round(IDLE_TIMEOUT_MS / 60_000)} min`;
  console.log(`qrood server listening on ${PUBLIC_ORIGIN}/ (${idleLabel})`);
});
