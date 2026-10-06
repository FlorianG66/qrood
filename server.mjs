import http from "node:http";
import { createHash, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
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
// Fenêtre pendant laquelle un aller-retour par le fournisseur d-identité vaut preuve
// d'identité, pour les actions qu'un mot de passe autorise. Volontairement courte :
// elle couvre la confirmation d'une action, pas une session de travail. Elle ne sert
// qu'aux comptes sans mot de passe — un compte qui en a un doit toujours le saisir.
const FRESH_WINDOW_MS = readInteger("QROOD_FRESH_WINDOW_MINUTES", 15, 1, 60) * 60 * 1_000;
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

// ── Fournisseurs d'identité ───────────────────────────────────────────────
//
// Chaque fournisseur est décrit une fois, ici : le préfixe d'environnement qui porte
// ses identifiants, ses points d'appel, ce qu'il demande, et — la seule différence qui
// compte vraiment — ce qu'il affirme de l'adresse. Google certifie qu'elle est vérifiée,
// et cette attestation est conservée comme preuve. Microsoft renvoie une adresse mais ne
// la certifie pas : le compte qu'elle ouvre naît donc sans adresse confirmée.
//
// Un fournisseur sans identifiants complets n'existe pas : ses routes répondent
// « introuvable » et l'interface n'affiche aucun bouton, plutôt que d'annoncer une
// connexion qui échouerait toujours. Le reste de la plateforme fonctionne normalement.
const OAUTH_PROVIDER_DEFINITIONS = [
  {
    id: "google",
    label: "Google",
    envPrefix: "GOOGLE",
    defaultAuthUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    defaultTokenUrl: "https://oauth2.googleapis.com/token",
    defaultUserinfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    // `select_account` évite qu'un compte déjà présent dans la session du fournisseur
    // s'impose à un utilisateur qui voulait en changer.
    authorization: { prompt: "select_account" },
    readIdentity(profile) {
      const email = normalizeEmail(profile?.email);
      if (!email || profile?.email_verified !== true) return null;
      return { email, verified: true };
    },
  },
  {
    id: "microsoft",
    label: "Microsoft",
    envPrefix: "MICROSOFT",
    // `common` accepte les comptes professionnels comme les comptes personnels. C'est
    // aussi ce qui rend `sub` inutilisable pour retrouver un compte sans l'index
    // unique : deux fournisseurs ne partageant jamais la même table, rien ne se croise.
    defaultAuthUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    defaultTokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    defaultUserinfoUrl: "https://graph.microsoft.com/oidc/userinfo",
    authorization: { prompt: "select_account" },
    // Microsoft expose une adresse pour un compte professionnel, mais sans jamais dire
    // que la personne en est propriétaire : c'est un attribut d'annuaire, pas une
    // preuve. Un compte personnel ne livre qu'un `preferred_username`, qui est un nom de
    // connexion et non une boîte. L'un et l'autre font un contact ; aucun n'est un
    // certificat. D'où `verified: false` — le compte sera créé sans confirmation et
    // devra confirmer son adresse par e-mail comme une inscription locale.
    readIdentity(profile) {
      const email = normalizeEmail(profile?.email) || normalizeEmail(profile?.preferred_username);
      if (!email) return null;
      return { email, verified: false };
    },
  },
];

const OAUTH_SCOPE = "openid email profile";
const OAUTH_HTTP_TIMEOUT_MS = 10_000;

function buildOAuthProvider(definition) {
  const clientId = readStripeEnv(`${definition.envPrefix}_CLIENT_ID`);
  const clientSecret = readStripeEnv(`${definition.envPrefix}_CLIENT_SECRET`);
  const redirectUri =
    readStripeEnv(`${definition.envPrefix}_REDIRECT_URI`) || `${PUBLIC_ORIGIN}/api/auth/${definition.id}/callback`;
  // Les points d'appel sont surchargeables, sinon aucun test ne pourrait suivre le flux de
  // bout en bout sans aller sur Internet. Le garde-fou de production est deux lignes plus
  // bas : en production, ils ne se surchargent pas.
  const authUrl = cleanText(process.env[`QROOD_${definition.envPrefix}_AUTH_URL`], 500) || definition.defaultAuthUrl;
  const tokenUrl = cleanText(process.env[`QROOD_${definition.envPrefix}_TOKEN_URL`], 500) || definition.defaultTokenUrl;
  const userinfoUrl =
    cleanText(process.env[`QROOD_${definition.envPrefix}_USERINFO_URL`], 500) || definition.defaultUserinfoUrl;

  if (!/^https?:\/\/[^\s/]+/.test(redirectUri)) {
    throw new Error(`${definition.envPrefix}_REDIRECT_URI doit être une URL HTTP ou HTTPS absolue.`);
  }
  if (IS_PRODUCTION && !redirectUri.startsWith("https://")) {
    throw new Error(`${definition.envPrefix}_REDIRECT_URI doit utiliser HTTPS en production.`);
  }
  if (IS_PRODUCTION
    && (authUrl !== definition.defaultAuthUrl
      || tokenUrl !== definition.defaultTokenUrl
      || userinfoUrl !== definition.defaultUserinfoUrl)) {
    throw new Error(`Les points d'appel ${definition.label} ne se surchargent pas en production.`);
  }

  return {
    ...definition,
    clientId,
    clientSecret,
    redirectUri,
    authUrl,
    tokenUrl,
    userinfoUrl,
    enabled: Boolean(clientId && clientSecret),
    // Un cookie et un chemin par fournisseur : celui de Google n'est pas même envoyé aux
    // routes de Microsoft, donc un parcours ne peut pas se relire chez l'autre.
    stateCookie: `qrood_oauth_state_${definition.id}`,
    returnCookie: `qrood_oauth_next_${definition.id}`,
    path: `/api/auth/${definition.id}`,
  };
}

const OAUTH_PROVIDERS = new Map(
  OAUTH_PROVIDER_DEFINITIONS.map((definition) => [definition.id, buildOAuthProvider(definition)]),
);

function findOAuthProvider(id) {
  return OAUTH_PROVIDERS.get(cleanText(id, 32)) || null;
}

// Seuls les fournisseurs entièrement configurés apparaissent côté interface : un bouton
// sans identifiants derrière lui n'aurait qu'à échouer, et son existence ne dépend pas
// d'un secret.
function listEnabledProviders() {
  return OAUTH_PROVIDER_DEFINITIONS
    .filter((definition) => OAUTH_PROVIDERS.get(definition.id).enabled)
    .map((definition) => ({ id: definition.id, label: definition.label }));
}

// `auth_provider` n'accepte que des valeurs nommées ici : une colonne qui accueille un
// fournisseur doit d'abord pouvoir l'écrire. La contrainte est interpolée dans les trois
// DDL qui la portent — schéma neuf, ajout de colonne, reprise de table — pour qu'ajouter
// un fournisseur ne se répète pas à chaque endroit.
const AUTH_PROVIDER_IDS = ["local", ...OAUTH_PROVIDER_DEFINITIONS.map((definition) => definition.id)];
const AUTH_PROVIDER_CHECK = `CHECK(auth_provider IN (${AUTH_PROVIDER_IDS.map((id) => `'${id}'`).join(",")}))`;


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
const SCHEMA_VERSION = 8;
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
    password_hash TEXT,
    created_at INTEGER NOT NULL,
    pending_email TEXT,
    -- Le rôle n'existe que par défaut faux, et aucune route ne l'écrit : il se
    -- promeut par une commande SQL explicite. Cette valeur par défaut n'est pas
    -- une précaution de migration, c'est la garantie structurelle qu'un compte
    -- créé par une route publique ne puisse pas en hériter.
    is_super_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_super_admin IN (0,1)),
    auth_provider TEXT NOT NULL DEFAULT 'local' ${AUTH_PROVIDER_CHECK},
    provider_id TEXT
  ) STRICT;

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    user_agent TEXT NOT NULL,
    fresh_until INTEGER NOT NULL DEFAULT 0
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

  -- Journal des interventions du super-admin. Les adresses sont dénormalisées :
  -- la ligne doit survivre à la suppression du compte qu'elle décrit, sinon
  -- l'histoire s'écrit avec les comptes qu'elle a effacés.
  CREATE TABLE IF NOT EXISTS admin_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_email TEXT NOT NULL,
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_email TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    metadata TEXT,
    created_at INTEGER NOT NULL
  ) STRICT;

  CREATE INDEX IF NOT EXISTS idx_admin_actions_created ON admin_actions(created_at DESC);

  -- Double authentification, ouverte à tout compte et pas seulement au rôle. Le
  -- secret actif n'est écrit qu'après confirmation d'un code : pending_secret
  -- permet de présenter le QR code avant qu'il ait été scanné, sans qu'un secret
  -- jamais vérifié devienne actif. last_counter empêche le rejeu d'un code déjà
  -- consommé dans la fenêtre de tolérance. Les codes de récupération ne sont
  -- stockés que hachés, comme les jetons, et retirés de la liste au premier usage.
  -- La clé est user_id : un compte ne peut avoir qu'une seule ligne, quel que
  -- soit le rôle qu'il porte.
  CREATE TABLE IF NOT EXISTS two_factor_auth (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT,
    confirmed_at INTEGER,
    pending_secret TEXT,
    pending_expires_at INTEGER,
    last_counter INTEGER,
    recovery_codes TEXT NOT NULL DEFAULT '[]',
    updated_at INTEGER NOT NULL
  ) STRICT;

  CREATE INDEX IF NOT EXISTS idx_two_factor_auth_pending
    ON two_factor_auth(pending_expires_at);

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

// Le rôle super-admin est ajouté par `ALTER TABLE` et non dans le `CREATE TABLE`
// ci-dessus, qui ne s'applique qu'aux bases neuves. `NOT NULL DEFAULT 0` rend la
// colonne valide pour toutes les lignes existantes sans les parcourir : personne
// ne devient administrateur par le simple fait d'ouvrir la base après mise à jour.
function ensureSuperAdminColumn() {
  const names = new Set(db.prepare("PRAGMA table_info(users)").all().map((column) => column.name));
  if (!names.has("is_super_admin")) {
    db.exec("ALTER TABLE users ADD COLUMN is_super_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_super_admin IN (0,1))");
  }
}

// Une session peut être « fraîche » : ouverte par le fournisseur d'identité, ou
// ré-authentifiée par lui dans les minutes précédentes. Cette preuve remplace le mot
// de passe pour les seules actions d'un compte qui n'en a pas — sans elle, un tel
// compte resterait coincé, sa seule voie d'accès étant précisément ce qu'on lui
// demanderait de prouver. `DEFAULT 0` : aucune session existante n'hérit d'une
// fraîcheur, la column n'existant qu'après cette migration.
function ensureFreshSessionColumn() {
  const names = new Set(db.prepare("PRAGMA table_info(sessions)").all().map((column) => column.name));
  if (!names.has("fresh_until")) {
    db.exec("ALTER TABLE sessions ADD COLUMN fresh_until INTEGER NOT NULL DEFAULT 0");
  }
}

// Le fournisseur d'identité est ajouté par `ALTER TABLE` et non dans le `CREATE TABLE`
// ci-dessus, qui ne s'applique qu'aux bases neuves. `NOT NULL DEFAULT 'local'` rend la
// colonne valide pour toutes les lignes existantes sans les parcourir : aucun compte
// créé avant la migration ne se retrouve lié à un fournisseur.
function ensureAuthProviderColumns() {
  const names = new Set(db.prepare("PRAGMA table_info(users)").all().map((column) => column.name));
  if (!names.has("auth_provider")) {
    db.exec(`ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local' ${AUTH_PROVIDER_CHECK}`);
  }
  if (!names.has("provider_id")) {
    db.exec("ALTER TABLE users ADD COLUMN provider_id TEXT");
  }
  // Un identifiant externe ne désigne qu'un compte, et un compte ne porte qu'un seul
  // identifiant de fournisseur : l'index est la garantie matérielle en cas de deux
  // callbacks simultanés, là où le SELECT voit le même état que la requête concurrente.
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider_identity
      ON users(auth_provider, provider_id)
      WHERE provider_id IS NOT NULL
  `);
  migrateUsersTableShape();
}

// Un compte créé par un fournisseur n'a pas de mot de passe : `password_hash` devient
// facultatif, `NULL` signifiant « aucun mot de passe local ». SQLite ne sait ni lever un
// `NOT NULL`, ni ajouter une valeur à une contrainte `CHECK`, donc la table est recréée
// à l'identique, lignes conservées, puis les index reposés. C'est aussi le seul moment où
// `auth_provider` peut apprendre à nommer un nouveau fournisseur : une base déjà en
// service garde sinon la liste figée au moment de sa création. Sept tables référencent
// `users` : `PRAGMA foreign_keys` est désactivé autour de l'opération — le pragma est
// ignoré à l'intérieur d'une transaction — et rétabli aussitôt après, que la reprise ait
// abouti ou non.
const USERS_COLUMNS = [
  "id",
  "display_name",
  "email",
  "password_hash",
  "created_at",
  "pending_email",
  "is_super_admin",
  "email_verified_at",
  "auth_provider",
  "provider_id",
];

function migrateUsersTableShape() {
  const declared = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").get()?.sql || "";
  const passwordIsMandatory = declared.includes("password_hash TEXT NOT NULL");
  // Une contrainte déjà conforme suffit à ne rien faire. La comparer à la liste plutôt
  // que chercher un `CHECK` suffit : c'est la seule restriction portant sur cette colonne.
  const providersAreCurrent = AUTH_PROVIDER_IDS.every((id) => declared.includes(`'${id}'`));
  if (!passwordIsMandatory && providersAreCurrent) return;

  const columns = db.prepare("PRAGMA table_info(users)").all().map((column) => column.name);
  const unexpected = columns.filter((name) => !USERS_COLUMNS.includes(name));
  const missing = USERS_COLUMNS.filter((name) => !columns.includes(name));
  if (unexpected.length || missing.length) {
    // Recopier en ignorant une colonne reviendrait à perdre des comptes en silence.
    // Le serveur refuse de démarrer : la liste est nommée, la correction est locale.
    throw new Error(
      `La table users ne correspond pas à la migration (en trop : ${unexpected.join(", ") || "aucune"} ; `
      + `manquantes : ${missing.join(", ") || "aucune"}).`,
    );
  }

  const selectList = USERS_COLUMNS.map((name) => `"${name}"`).join(", ");
  db.exec("PRAGMA foreign_keys = OFF;");
  try {
    db.exec("BEGIN;");
    db.exec(`
      CREATE TABLE users_retablies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        display_name TEXT NOT NULL,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT,
        created_at INTEGER NOT NULL,
        pending_email TEXT,
        is_super_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_super_admin IN (0,1)),
        email_verified_at INTEGER,
        auth_provider TEXT NOT NULL DEFAULT 'local' ${AUTH_PROVIDER_CHECK},
        provider_id TEXT
      ) STRICT;
    `);
    db.prepare(`INSERT INTO users_retablies SELECT ${selectList} FROM users;`).run();
    const copied = db.prepare("SELECT COUNT(*) AS total FROM users_retablies").get().total;
    const expected = db.prepare("SELECT COUNT(*) AS total FROM users").get().total;
    if (copied !== expected) {
      throw new Error(`la reprise de users a copié ${copied} lignes sur ${expected}.`);
    }
    db.exec("DROP TABLE users;");
    db.exec("ALTER TABLE users_retablies RENAME TO users;");
    db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_users_pending_email
        ON users(pending_email)
        WHERE pending_email IS NOT NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider_identity
        ON users(auth_provider, provider_id)
        WHERE provider_id IS NOT NULL;
    `);
    db.exec("COMMIT;");
  } catch (error) {
    db.exec("ROLLBACK;");
    throw error;
  } finally {
    db.exec("PRAGMA foreign_keys = ON;");
  }
}

// La double authentification n'appartient plus au seul rôle super-admin : la table
// est renommée, pas dupliquée. Deux tables auraient voulu dire deux jeux de règles
// TOTP, deux jeux de codes de récupération, et une divergence à la première
// correction de sécurité.
//
// Le schéma ci-dessus crée déjà `two_factor_auth` sur toute base, y compris ancienne :
// le simple `CREATE TABLE IF NOT EXISTS` précède cette fonction et pose donc une
// table neuve et vide avant que la legacy soit rencontrée. Un `RENAME TO` unconditional
// échouerait alors sur « il existe déjà une table de ce nom », et le serveur ne
// démarrerait plus du tout. D'où les deux voies : renommer quand la table cible
// n'existe pas, recopier sinon.
function migrateTwoFactorAuthGeneralization() {
  const tableExists = (name) =>
    Boolean(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));
  if (!tableExists("admin_two_factor")) return;
  db.exec(`
    BEGIN;
    ${
      tableExists("two_factor_auth")
        ? `INSERT OR IGNORE INTO two_factor_auth (
             user_id, secret, confirmed_at, pending_secret, pending_expires_at,
             last_counter, recovery_codes, updated_at
           )
           SELECT user_id, secret, confirmed_at, pending_secret, pending_expires_at,
                  last_counter, recovery_codes, updated_at
           FROM admin_two_factor;
           DROP TABLE admin_two_factor;`
        : "ALTER TABLE admin_two_factor RENAME TO two_factor_auth;"
    }
    DROP INDEX IF EXISTS idx_admin_two_factor_pending;
    CREATE INDEX IF NOT EXISTS idx_two_factor_auth_pending ON two_factor_auth(pending_expires_at);
    COMMIT;
  `);
}

ensureQrcodeLegacyKey();
ensureQrcodeStyleColumns();
ensureQrcodeActivityColumns();
ensureEmailVerificationColumns();
ensurePendingEmailColumn();
ensureSuperAdminColumn();
ensureAuthProviderColumns();
ensureFreshSessionColumn();
migrateEntreprisePlanRemoval();
migrateAuthTokenPurposes();
migrateTwoFactorAuthGeneralization();

// Politique de super-admin unique : seul florian.guichard66@gmail.com peut l'être.
function enforceUniqueSuperAdmin() {
  const canonicalEmail = "florian.guichard66@gmail.com";
  const canonical = db.prepare("SELECT id, is_super_admin, email FROM users WHERE LOWER(email) = ?").get(
    canonicalEmail.toLowerCase(),
  );
  if (canonical) {
    if (canonical.is_super_admin !== 1) {
      db.prepare("UPDATE users SET is_super_admin = 1 WHERE id = ?").run(canonical.id);
    }
  }
  const others = db.prepare(`
    SELECT id, email FROM users
    WHERE is_super_admin = 1 AND LOWER(email) <> ?
  `).all(canonicalEmail.toLowerCase());
  if (others.length > 0) {
    db.prepare(`
      UPDATE users SET is_super_admin = 0
      WHERE is_super_admin = 1 AND LOWER(email) <> ?
    `).run(canonicalEmail.toLowerCase());
  }
}

enforceUniqueSuperAdmin();

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
  // Le back-office est servi sans condition : la page elle-même ne rend aucune
  // donnée, tout passe par `/api/admin/*`, qui vérifie le rôle à chaque requête.
  // La masquer ici ne sécuriserait rien et ferait dépendre l'affichage d'une
  // variable d'environnement.
  ["/back-office", "admin.html"],
  ["/back-office.html", "admin.html"],
  ["/styles.css", "styles.css"],
  ["/app.js", "app.js"],
  ["/compte.js", "compte.js"],
  ["/admin.js", "admin.js"],
  ["/cursor.js", "cursor.js"],
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

// ── Parcours d'un fournisseur d'identité ────────────────────────────────────
//
// Le parcours OAuth est un aller-retour hors site : le navigateur revient du fournisseur
// par une navigation. Seul `SameSite=Lax` accompagne ce retour — `Strict` ne
// renverrait pas le cookie, et la connexion serait impossible à boucler. Le cookie
// reste `HttpOnly` (le script de la page ne peut ni le lire ni l'écrire) et borné au
// préfixe des routes de ce fournisseur : celui de Google n'est pas même envoyé aux
// routes de Microsoft, et il expire en dix minutes.
const OAUTH_STATE_TTL_MS = readInteger("QROOD_OAUTH_STATE_MINUTES", 10, 1, 30) * 60 * 1_000;

// Le cookie d'état porte le nonce qui voyage vers le fournisseur, et l'intention que
// ce aller-retour accomplit : ouvrir une session, relier une identité à un compte, ou
// ré-authentifier la session qui le demande. Une intention de liaison ou de
// ré-authentification est attachée au compte *et* à la session qui l'a émise : le
// retour relit les deux dans le cookie et les confronte à la session courante. Un
// aller commencé par un compte ne peut donc pas être terminé par un autre, et une
// session fermée entre-temps ne laisse pas une liaison en suspens qui s'appliquerait
// à quelqu'un d'autre.
//
// Le fournisseur n'y figure pas : il est déjà dans le nom et le chemin du cookie, si
// bien qu'un parcours ne peut pas se relire chez un autre fournisseur.
//
// Le cookie est signé. Sans signature, quiconque peut poser un cookie à ce nom — un
// hôte frère du même domaine, un trajet non chiffré, une fuite d'en-tête — choisirait
// lui-même le compte et la session visés dans la valeur, plantant ainsi une liaison
// qui s'appliquerait ensuite à la victime avec l'identité de l'attaquant.
const OAUTH_INTENTS = new Set(["login", "link", "reauth"]);

// La clé est lue de l'environnement pour que plusieurs instances ou un redémarrage la
// partagent. À défaut, une clé aléatoire par processus suffit : elle invalide les
// parcours en cours au redémarrage, ce qu'un flux de dix minutes ferait de toute façon.
const OAUTH_FLOW_KEY = readStripeEnv("OAUTH_FLOW_KEY") || randomBytes(32);

function signOauthFlow(payload) {
  return createHmac("sha256", OAUTH_FLOW_KEY).update(payload).digest("base64url").slice(0, 32);
}

function oauthFlowCookie(provider, state, intent, userId = 0, sessionId = 0) {
  const payload = `${state}.${intent}.${userId}.${sessionId}`;
  const attributes = [
    `${provider.stateCookie}=${payload}.${signOauthFlow(payload)}`,
    `Path=${provider.path}`,
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.floor(OAUTH_STATE_TTL_MS / 1000)}`,
  ];
  if (SECURE_COOKIES) attributes.push("Secure");
  return attributes.join("; ");
}

function clearOauthStateCookie(provider) {
  const attributes = [
    `${provider.stateCookie}=`,
    `Path=${provider.path}`,
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0",
  ];
  if (SECURE_COOKIES) attributes.push("Secure");
  return attributes.join("; ");
}

// Le décodage est strict, et la signature se vérifie avant tout usage : un cookie
// altéré ne rend pas un aller-retour valide, il en fait un aller-retour sans
// intention, donc un refus. Mieux vaut perdre une liaison que d'appliquer une
// intention que le cookie ne portait pas — ou qu'un tiers en ait fabriquée une.
function readOauthFlow(raw) {
  if (typeof raw !== "string") return null;
  const [state, intent, userId, sessionId, signature, ...rest] = raw.split(".");
  if (rest.length || !/^[A-Za-z0-9_-]{32,64}$/.test(state || "")) return null;
  if (!OAUTH_INTENTS.has(intent)) return null;
  if (!/^\d{1,15}$/.test(userId || "") || !/^\d{1,15}$/.test(sessionId || "")) return null;
  if (!safeTokenEquals(signOauthFlow(`${state}.${intent}.${userId}.${sessionId}`), signature || "")) return null;
  return { state, intent, userId: Number(userId), sessionId: Number(sessionId) };
}

// La page de retour voyage dans son propre cookie, encodée : un chemin peut contenir
// `;`, qui tronquerait un cookie en clair. Le décodage est encadré par la même
// validation que la valeur reçue en query string — un cookie altéré ne gagne rien.
function oauthReturnCookie(provider, path) {
  const attributes = [
    `${provider.returnCookie}=${Buffer.from(path, "utf8").toString("base64url")}`,
    `Path=${provider.path}`,
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.floor(OAUTH_STATE_TTL_MS / 1000)}`,
  ];
  if (SECURE_COOKIES) attributes.push("Secure");
  return attributes.join("; ");
}

function clearOauthReturnCookie(provider) {
  const attributes = [
    `${provider.returnCookie}=`,
    `Path=${provider.path}`,
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0",
  ];
  if (SECURE_COOKIES) attributes.push("Secure");
  return attributes.join("; ");
}

function getSession(request) {
  const token = parseCookies(request.headers.cookie).get("qrood_session");
  if (!token || !/^[A-Za-z0-9_-]{32,128}$/.test(token)) return null;
  const session = db.prepare(`
    SELECT s.id, s.user_id, s.csrf_token, s.last_seen_at, s.expires_at, s.fresh_until,
           u.id AS user_id_value, u.display_name, u.email, u.email_verified_at, u.pending_email,
           u.is_super_admin, u.auth_provider, u.provider_id,
           (u.password_hash IS NOT NULL) AS has_password
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
    isSuperAdmin: Boolean(session.is_super_admin),
    // Ces trois valeurs décrivent le compte, pas la session : elles servent à
    // l'interface pour proposer — ou refuser — la liaison Google, et à la garde qui
    // décide si une action d'identité peut se passer de mot de passe.
    authProvider: session.auth_provider,
    providerId: session.provider_id,
    hasPassword: Boolean(session.has_password),
    freshUntil: session.fresh_until || 0,
  };
}

function requireSession(request) {
  const session = getSession(request);
  if (!session) throw new HttpError(401, "Authentification requise.", "authentication_required");
  return session;
}

// Le rôle est relu depuis la base à chaque requête plutôt que mis en cache dans la
// session : c'est la seule façon qu'une révocation prenne effet sans attendre
// l'expiration du jeton. Le coût est un index sur une colonne, en regard du
// risque qu'un accès retiré reste ouvert plusieurs heures.
function requireSuperAdmin(request) {
  const session = requireSession(request);
  if (!isSuperAdmin(session.userId)) {
    throw new HttpError(403, "Ce compte n’a pas accès au back-office.", "super_admin_required");
  }
  return session;
}

function isSuperAdmin(userId) {
  const row = db.prepare("SELECT is_super_admin FROM users WHERE id = ?").get(userId);
  return Boolean(row?.is_super_admin);
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

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/u;

function validateEmail(value) {
  const email = cleanText(value, 254).toLowerCase();
  if (!EMAIL_PATTERN.test(email)) {
    throw new HttpError(400, "L’adresse e-mail est invalide.", "invalid_email");
  }
  return email;
}

// Même mise en forme que `validateEmail`, sans exception : le fournisseur n'est pas
// un client de l'API, donc une adresse absente ou fausse n'est pas une requête
// invalide, c'est une identité refusée.
function normalizeEmail(value) {
  const email = cleanText(value, 254).toLowerCase();
  return EMAIL_PATTERN.test(email) ? email : null;
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
// Règle unique de l'offre effective, volontairement isolée et pure : elle est
// appelée par `resolvePlanKey` (page du compte, contrôles de quota) comme par les
// listes du back-office, qui doivent afficher exactement la même offre. Dupliquée
// ailleurs, elle divergerait à la première évolution du catalogue, et le
// super-admin verrait une offre dans un écran et une autre dans l'autre.
function effectivePlanKey(row, timestamp) {
  // Le rôle est consulté avant toute logique d'abonnement parce que c'est le seul
  // endroit du code où une offre est servie sans paiement. Il doit donc primer sur
  // la grâce et sur le statut Stripe : sans cette lecture en tête, un super-admin
  // dont l'abonnement a expiré retomberait sur Découverte, et l'avantage serait
  // perdu au pire moment — en pleine maintenance.
  if (row.is_super_admin) return "ultra";
  if (!PLAN_CATALOG[row.plan] || !isEntitled(row, timestamp)) return DEFAULT_PLAN;
  return row.plan;
}

function resolvePlanKey(userId) {
  const row = db.prepare(`
    SELECT u.is_super_admin, s.id AS subscription_id, s.plan, s.status, s.grace_until,
           s.current_period_end, s.stripe_subscription_id, s.cancel_at_period_end
      FROM users u
      LEFT JOIN subscriptions s ON s.user_id = u.id
     WHERE u.id = ?
  `).get(userId);
  if (!row) return DEFAULT_PLAN;
  const timestamp = now();
  renewManualOffer(row, timestamp);
  return effectivePlanKey(row, timestamp);
}

// Durée d'une période offerte. Le même nombre sert à la première attribution et
// à chaque renouvellement : c'est lui qui définit ce que « un an » veut dire.
const MANUAL_OFFER_PERIOD_MS = 365 * 24 * 60 * 60 * 1_000;

// Renouvellement paresseux d'une offre accordée par l'administration : au premier
// accès constatant l'échéance, la période est repoussée d'un an plutôt que de
// laisser l'utilisateur retomber sur Découverte. Aucun cron n'est nécessaire —
// une tâche de fond qui n'a pas tourné laisserait l'accès tomber sans raison, et
// le comportement serait différent selon le jour de la semaine.
//
// La prolongation part de l'instant présent et non de l'échéance dépassée : après
// deux ans sans connexion, repartir de l'échéance recalculerait une date toujours
// dépassée, et l'utilisateur ne comprendrait pas pourquoi son accès saute.
//
// La ligne visée est identifiée par `id` et non par `user_id` : un compte peut
// conserver plusieurs lignes d'abonnement terminées dans son historique, et les
// toucher toutes reviendrait à ressusciter des abonnements que Stripe a clos.
function renewManualOffer(row, timestamp) {
  if (!row || row.is_super_admin) return;
  if (row.stripe_subscription_id) return;
  if (row.status !== "active" && row.status !== "trialing") return;
  // `cancel_at_period_end` à 1 signifie que l'offre s'éteint à l'échéance : c'est
  // le geste explicite de retrait, et il prime sur le renouvellement.
  if (row.cancel_at_period_end) return;
  if (!row.current_period_end) return;
  if (row.current_period_end > timestamp) return;

  // La ligne est visée par `id` : voir la note sur l'historique plus haut.
  const periodEnd = timestamp + MANUAL_OFFER_PERIOD_MS;
  db.prepare(`
    UPDATE subscriptions SET current_period_end = ?, updated_at = ? WHERE id = ?
  `).run(periodEnd, timestamp, row.subscription_id);
  row.current_period_end = periodEnd;
  // Aucun écrit dans `admin_actions` : ce tableau journalise des décisions
  // humaines avec un motif et un auteur, alors que ce renouvellement est une
  // règle du système. La trace est `updated_at`, que la fiche du back-office
  // affiche déjà.
}

// `grace_until` porte la grâce de 48 h décidée en cas de perte d'accès : elle se
// décompte depuis `current_period_end`, donc le décompte affiché et l'expiration
// enregistrée ne peuvent pas diverger.
function isEntitled(row, timestamp) {
  if (!row) return false;
  const stripeSubId = row.stripe_subscription_id;
  const isManual = !stripeSubId || stripeSubId === "";
  if (row.status === "active" || row.status === "trialing") {
    if (isManual && row.current_period_end) {
      return row.current_period_end > timestamp;
    }
    return true;
  }
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
  const user = db.prepare("SELECT display_name, email FROM users WHERE id = ?").get(userId);
  if (!user) throw new HttpError(404, "Compte introuvable.", "user_not_found");
  const stripe = await getStripe();

  // Un customer stocké peut avoir été supprimé côté Stripe, ou avoir été créé
  // avec d'autres clés (changement de compte, environnement de test). Sans cette
  // vérification, la checkout session échouerait avec « No such customer » et
  // l'utilisateur ne pourrait jamais souscrire.
  if (existing) {
    try {
      await stripe.customers.retrieve(existing.stripe_customer_id);
      return existing.stripe_customer_id;
    } catch (error) {
      if (error.code !== "resource_missing") throw error;
      console.warn(
        `qrood billing: customer Stripe ${existing.stripe_customer_id} introuvable, création d'un nouveau.`
      );
      db.prepare("DELETE FROM billing_customers WHERE user_id = ?").run(userId);
    }
  }

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
    SELECT id AS subscription_id, plan, status, current_period_end, cancel_at_period_end,
           grace_until, stripe_subscription_id
    FROM subscriptions
    WHERE user_id = ?
    ORDER BY (status NOT IN ('canceled', 'incomplete_expired')) DESC, updated_at DESC
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
      manual: false,
      autoRenew: false,
    };
  }
  // Le résumé est affiché avant toute résolution d'offre sur certains écrans : sans
  // ce renouvellement, la date affichée resterait celle d'une période dépassée alors
  // que l'accès est renouvelé, et l'interface annoncerait un accès échu.
  renewManualOffer(row, now());
  return {
    hasBillingAccount: Boolean(customer),
    plan: row.plan,
    status: row.status,
    cancelAtPeriodEnd: Boolean(row.cancel_at_period_end),
    currentPeriodEnd: row.current_period_end,
    graceUntil: row.grace_until,
    // Sans identifiant d'abonnement Stripe, la ligne décrit un accès accordé par
    // l'administration : l'afficher comme un renouvellement à venir serait faux.
    manual: !row.stripe_subscription_id,
    // Seule une offre manuelle sans arrêt programmé se prolonge d'elle-même. Un
    // abonnement Stripe suit le cycle de Stripe, et le rôle prime sur tout.
    autoRenew: !row.stripe_subscription_id && !row.cancel_at_period_end,
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

function createSession(userId, request, provenByProvider = false) {
  const token = randomToken(32);
  const csrfToken = randomToken(24);
  const timestamp = now();
  db.prepare(`
    INSERT INTO sessions (
      user_id, token_hash, csrf_token, created_at, last_seen_at, expires_at, user_agent, fresh_until
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    userId,
    hashToken(token),
    csrfToken,
    timestamp,
    timestamp,
    timestamp + SESSION_TTL_MS,
    cleanText(request.headers["user-agent"], 300),
    // Une session ouverte par le fournisseur d'identité est fraîche d'emblée : le
    // retour de Google vient de prouver le compte. Une session ouverte par mot de
    // passe ne l'est pas, et ne le devient que si l'utilisateur repasse par Google.
    provenByProvider ? timestamp + FRESH_WINDOW_MS : 0,
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

// Une redirection ne renvoie que l'adresse : le `Location` est relatif, donc il ne
// peut pas désigner un autre site que celui qui a construit la chaîne. Les pages
// d'arrivée sont des pages du site, jamais une donnée à interpréter.
function sendRedirect(response, location, extraHeaders = {}) {
  securityHeaders(response);
  response.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  response.end();
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
    // Lu sur la session du seul appelant : cette valeur ne décrit que « moi », et
    // sert à l'interface pour proposer le back-office. Elle ne dit rien des autres
    // comptes, dont le rôle n'est exposé que dans les routes d'administration.
    isSuperAdmin: Boolean(row.isSuperAdmin ?? row.is_super_admin),
  };
}

// La destination de retour ne peut être qu'un chemin de ce site. Tout ce qui
// n'est pas un chemin simple — une URL absolue, un `//.exemple.test`, un
// `/\exemple.test` que le navigateur réinterprète, un caractère de contrôle — est
// ramené à la racine : c'est la seule forme qui ne peut pas devenir une redirection
// ouverte.
const MAX_RETURN_PATH_LENGTH = 200;

function safeReturnPath(value) {
  const candidate = cleanText(value, MAX_RETURN_PATH_LENGTH);
  if (!candidate.startsWith("/")) return "/";
  if (candidate.startsWith("//") || candidate.includes("\\") || /[\s<>"']/.test(candidate)) return "/";
  return candidate;
}

function readReturnCookie(raw) {
  if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)) return "/";
  try {
    return safeReturnPath(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    return "/";
  }
}

// L'échec est rendu par un code court dans l'URL de retour, jamais par un texte : la
// page d'accueil affiche un message en français, et le serveur n'écrit rien dans un
// document. Les deux sorties — succès et échec — remettent à zéro le cookie d'état,
// que le navigateur n'enverra donc plus au retour suivant.
function sendAuthReturn(response, path, code, cookies, providerId = "") {
  const target = new URL(path, PUBLIC_ORIGIN);
  target.searchParams.set("oauth", code);
  // Le fournisseur accompagne le code : « Microsoft ne répond pas » et « Google n'a
  // pas confirmé votre adresse » ne se disent pas de la même façon, et l'interface ne
  // peut pas deviner lequel des deux a échoué. Ce n'est qu'un identifiant public, déjà
  // présent dans l'adresse d'origine du parcours.
  if (providerId) target.searchParams.set("oauth_provider", providerId);
  sendRedirect(response, `${target.pathname}${target.search}`, { "Set-Cookie": cookies });
}

// L'adresse d'autorisation, porteuse du nonce d'état. Les trois points d'entrée — le
// bouton de l'accueil, la liaison et la ré-authentification depuis le compte —
// construisent la même adresse : un seul endroit décide de ce que QROOD demande à
// chaque fournisseur, donc un seul endroit à vérifier.
function providerAuthorizationUrl(provider, state) {
  const authorization = new URL(provider.authUrl);
  authorization.searchParams.set("client_id", provider.clientId);
  authorization.searchParams.set("redirect_uri", provider.redirectUri);
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("scope", OAUTH_SCOPE);
  authorization.searchParams.set("state", state);
  // `select_account` évite qu'un compte déjà présent dans la session du fournisseur
  // s'impose à un utilisateur qui voulait en changer.
  for (const [key, value] of Object.entries(provider.authorization || {})) {
    authorization.searchParams.set(key, value);
  }
  return authorization.href;
}

// Prépare un aller-retour : l'adresse à ouvrir, et les deux cookies du retour. Le
// nonce est tiré ici et n'existe qu'ici et dans le cookie — le fournisseur ne fait que
// le recopier. La destination n'est libre que pour la connexion : une liaison ou une
// ré-authentification revient toujours à la page du compte, quelle que soit la
// demande reçue.
function prepareProviderFlow(provider, intent, options = {}) {
  const state = randomToken(32);
  return {
    url: providerAuthorizationUrl(provider, state),
    cookies: [
      oauthFlowCookie(provider, state, intent, options.userId || 0, options.sessionId || 0),
      oauthReturnCookie(provider, intent === "login" ? safeReturnPath(options.next) : "/compte"),
    ],
  };
}

// Un compte ne peut pas « avoir » un fournisseur qui ne l'est pas : les trois routes de
// liaison et de ré-authentification partagent cette porte, plutôt que de répondre
// chacune de leur manière à une configuration absente.
function requireProviderConfigured(provider) {
  if (!provider.enabled) {
    throw new HttpError(404, "La connexion avec un compte tiers n’est pas configurée.", "oauth_unavailable");
  }
}

// Le chemin `/api/auth/<fournisseur>/…` porte le fournisseur, la suite est identique
// pour tous : `start` ouvre le parcours, `callback` le referme, tout le reste est
// inexistant. Un nom inconnu ne rend pas une 404 de plus — il n'a jamais existé.
async function handleProviderAuthApi(provider, request, response, url) {
  requireProviderConfigured(provider);

  if (request.method === "GET" && url.pathname === `${provider.path}/start`) {
    checkRateLimit(`oauth-start:${getClientIp(request)}`, 10, 10 * 60 * 1_000);
    // Le bouton vit sur une page du site : la navigation est donc de même origine.
    // Un `state` fabriqué ailleurs ne franchit pas ce contrôle.
    verifyBrowserOrigin(request);
    const flow = prepareProviderFlow(provider, "login", { next: url.searchParams.get("next") });
    sendRedirect(response, flow.url, { "Set-Cookie": flow.cookies });
    return;
  }

  if (request.method === "GET" && url.pathname === `${provider.path}/callback`) {
    await completeProviderAuth(provider, request, response, url);
    return;
  }

  throw new HttpError(404, "Ressource introuvable.", "not_found");
}

async function completeProviderAuth(provider, request, response, url) {
  checkRateLimit(`oauth-callback:${getClientIp(request)}`, 20, 10 * 60 * 1_000);
  const cookies = parseCookies(request.headers.cookie);
  const flow = readOauthFlow(cookies.get(provider.stateCookie));
  const returnTo = readReturnCookie(cookies.get(provider.returnCookie));
  const clearCookies = [clearOauthStateCookie(provider), clearOauthReturnCookie(provider)];
  const finish = (code) => sendAuthReturn(response, returnTo, code, clearCookies, provider.id);

  try {
    // Le `state` relie le retour à l'aller. Sans lui, un callback forgé connecterait
    // l'auteur de la requête sur le compte de la personne dont il usurpe le nom. Il est
    // vérifié avant tout, y compris quand le fournisseur signale un refus : un abandon
    // rendu par un tiers ne doit pas non plus pouvoir s'afficher.
    if (!flow || !safeTokenEquals(flow.state, url.searchParams.get("state"))) {
      finish("state_invalide");
      return;
    }
    // Un fournisseur signale un refus de l'utilisateur par `error`, sans code : c'est un
    // abandon, pas une panne.
    if (url.searchParams.get("error")) {
      finish("refus");
      return;
    }
    const code = cleanText(url.searchParams.get("code"), 512);
    if (!code) {
      finish("code_manquant");
      return;
    }

    const identity = await fetchProviderIdentity(provider, code);
    if (!identity) {
      finish("identite_refusee");
      return;
    }

    // Une liaison ou une ré-authentification agit sur un compte précis, jamais sur
    // « celui qui se trouve être connecté ». La session est relue et comparée à celle
    // que le cookie nomme : sans cette comparaison, un aller commencé par un compte et
    // terminé par un autre rattacherait une identité au mauvais compte.
    if (flow.intent !== "login") {
      const session = getSession(request);
      if (!session || session.id !== flow.sessionId || session.userId !== flow.userId) {
        finish("session_expiree");
        return;
      }
      const refusal = flow.intent === "link"
        ? attachProviderIdentity(provider, session, identity)
        : refreshProviderProof(session, identity);
      if (refusal) {
        finish(refusal);
        return;
      }
      finish(flow.intent === "link" ? "liaison_reussie" : "reauth_reussie");
      return;
    }

    const account = resolveProviderAccount(provider, identity);
    if (account.refusal) {
      finish(account.refusal);
      return;
    }
    const createdSession = createSession(account.userId, request, true);
    // L'adresse annoncée par un fournisseur qui ne la certifie pas reste à confirmer :
    // le compte vient d'être ouvert, il reçoit donc son e-mail comme une inscription.
    // Un envoi qui échoue n'annule pas pour autant la session — l'utilisateur est
    // connecté, il pourra demander un nouvel envoi depuis son compte.
    if (account.pendingVerification) {
      try {
        await issueAndSendVerification(account.userId);
      } catch (error) {
        console.error(redactSecrets(error?.stack || error?.message || String(error)));
      }
    }
    sendRedirect(response, returnTo, {
      "Set-Cookie": [...clearCookies, sessionCookie(createdSession.token)],
    });
  } catch (error) {
    // Un fournisseur injoignable ne doit pas laisser de trace de pile dans la
    // réponse : le journal garde le diagnostic, l'utilisateur reçoit un code.
    console.error(redactSecrets(error?.stack || error?.message || String(error)));
    if (response.headersSent) return;
    finish("fournisseur_indisponible");
  }
}

// Rattache une identité de fournisseur à un compte connecté, sans rien changer d'autre :
// la liaison ouvre une seconde porte, elle ne remplace ni l'adresse ni le mot de passe.
// Le `WHERE provider_id IS NULL` est la garantie qu'une liaison ne peut pas remplacer
// une identité déjà attachée — deux onglets ouverts en même temps ne peuvent pas se
// disputer le compte. Renvoie le motif du refus, ou `null` si l'identité est attachée.
function attachProviderIdentity(provider, session, identity) {
  if (session.providerId) return "deja_lie";
  // La double authentification gagne sur tout fournisseur tiers. Un compte qui exige un
  // code à chaque connexion ne doit pas pouvoir être ouvert sans ce code : le retour
  // par une redirection n'a aucun champ où le saisir, donc ce mode de connexion lui est
  // refusé.
  if (isTwoFactorEnrolled(twoFactorRecord(session.userId))) return "deux_facteurs";
  try {
    const result = db.prepare(`
      UPDATE users SET auth_provider = ?, provider_id = ?
      WHERE id = ? AND provider_id IS NULL
    `).run(provider.id, identity.subject, session.userId);
    if (result.changes === 1) return null;
    // La ligne a changé entre la lecture et l'écriture : une autre liaison a abouti.
    return "deja_lie";
  } catch (error) {
    // L'index unique dit que cette identité appartient déjà à un autre compte. Elle ne
    // change pas de compte, même pour son détenteur : c'est ce qui empêche deux
    // comptes de se renvoyer la même adresse.
    if (String(error.message).includes("UNIQUE")) return "identite_deja_liee";
    throw error;
  }
}

// Ré-authentifie la session courante par l'identité qui lui est déjà attachée, en dater
// la preuve dans la session. Rien n'est modifié sur le compte : la preuve ne vaut que le
// temps de la fenêtre, et ne sert qu'aux actions qu'un mot de passe autorise. Elle
// n'ouvre jamais de session : elle n'est lisible que depuis celle-ci.
function refreshProviderProof(session, identity) {
  if (!session.providerId) return "identite_non_liee";
  // C'est l'identité rattachée qui doit se présenter, pas une autre : une identité
  // différente, chez ce fournisseur ou chez un autre, ne prouverait rien sur ce compte.
  if (!safeTokenEquals(session.providerId, identity.subject)) return "autre_identite";
  if (isTwoFactorEnrolled(twoFactorRecord(session.userId))) return "deux_facteurs";
  db.prepare("UPDATE sessions SET fresh_until = ? WHERE id = ? AND user_id = ?")
    .run(now() + FRESH_WINDOW_MS, session.id, session.userId);
  return null;
}

// Deux appels réseau, tous deux bornés : le jeton d'accès d'échange, puis le profil
// qui le porte. Aucun contenu n'est réutilisé pour une autre requête — ni le jeton
// du fournisseur, ni son audience. `redirect: "error"` ferme la porte à une
// redirection vers une autre origine : une réponse de jeton venue d'ailleurs ne
// serait pas un jeton.
async function fetchProviderIdentity(provider, code) {
  const tokenResponse = await withTimeout(fetch(provider.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      code,
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
      redirect_uri: provider.redirectUri,
      grant_type: "authorization_code",
    }).toString(),
    redirect: "error",
  }), OAUTH_HTTP_TIMEOUT_MS);
  if (!tokenResponse.ok) {
    throw new Error(`échange du code refusé (${tokenResponse.status})`);
  }
  const tokens = await tokenResponse.json();
  const accessToken = cleanText(tokens?.access_token, 512);
  if (!accessToken) throw new Error("le fournisseur n’a renvoyé aucun jeton d’accès");

  const profileResponse = await withTimeout(fetch(provider.userinfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    redirect: "error",
  }), OAUTH_HTTP_TIMEOUT_MS);
  if (!profileResponse.ok) {
    throw new Error(`lecture du profil refusée (${profileResponse.status})`);
  }
  const profile = await profileResponse.json();

  // `sub` est l'identifiant du compte chez le fournisseur, stable même quand
  // l'adresse change. C'est lui, jamais l'adresse, qui rattache une identité à un
  // compte. L'adresse, elle, se lit selon ce que le fournisseur sait certifier d'elle :
  // c'est le seul écart entre deux fournisseurs, et il est écrit dans le registre.
  const subject = cleanText(profile?.sub, 128);
  const claimed = provider.readIdentity(profile);
  if (!subject || !claimed) return null;
  return { subject, email: claimed.email, verified: claimed.verified, name: cleanText(profile?.name, MAX_NAME_LENGTH) };
}

// Ouvre le compte correspondant à une identité, ou crée ce compte s'il n'existe pas
// encore. Renvoie `{ userId }`, ou `{ refusal }` et le code court que l'interface
// traduira — le motif du refus ne traverse donc jamais le serveur en clair.
function resolveProviderAccount(provider, identity) {
  // Le compte se cherche par l'identifiant externe, jamais par l'adresse : une adresse
  // peut changer, le `sub` non. Une identité connue retrouve donc toujours son compte,
  // et l'index unique interdit qu'un même `sub` s'y attache deux fois.
  const known = db.prepare(`
    SELECT id FROM users WHERE auth_provider = ? AND provider_id = ?
  `).get(provider.id, identity.subject);
  if (known) {
    // La double authentification prime sur ce mode de connexion. Un compte qui exige
    // un code à chaque connexion ne s'ouvre pas par une redirection, faute de champ
    // où saisir ce code : mieux vaut un refus clair qu'une porte contournée.
    if (isTwoFactorEnrolled(twoFactorRecord(known.id))) return { refusal: "deux_facteurs" };
    return { userId: known.id };
  }

  // Aucune liaison automatique : une adresse en commun ne prouve rien. Un compte
  // peut déjà porter cette adresse, créé par quelqu'un qui n'a jamais confirmé la
  // sienne — lui remettre la session reviendrait à lui céder le compte. Le refus est
  // la même réponse pour un compte local et pour un second compte de fournisseur :
  // rien ne trahit l'existence du compte que l'adresse a déjà.
  if (db.prepare("SELECT id FROM users WHERE email = ?").get(identity.email)) {
    return { refusal: "email_deja_utilise" };
  }

  const fallback = [
    identity.name,
    cleanText(identity.email.split("@")[0], MAX_NAME_LENGTH),
    `Compte ${provider.label}`,
  ].find((candidate) => candidate.length >= 2) || `Compte ${provider.label}`;
  const timestamp = now();
  try {
    // Une adresse que le fournisseur certifie est marquée vérifiée sans e-mail à
    // envoyer : c'est sa preuve qui est conservée. Une adresse seulement annoncée
    // reste non confirmée, et le compte devra la confirmer par e-mail.
    const result = db.prepare(`
      INSERT INTO users (
        display_name, email, password_hash, created_at, email_verified_at, auth_provider, provider_id
      )
      VALUES (?, ?, NULL, ?, ?, ?, ?)
    `).run(fallback, identity.email, timestamp, identity.verified ? timestamp : null, provider.id, identity.subject);
    const userId = Number(result.lastInsertRowid);
    return identity.verified ? { userId } : { userId, pendingVerification: true };
  } catch (error) {
    // Deux retours simultanés pour une même identité : le second perd, il n'a pas à
    // dire pourquoi — le compte existe déjà, c'est tout.
    if (String(error.message).includes("UNIQUE")) return { refusal: "email_deja_utilise" };
    throw error;
  }
}

async function handleAuthApi(request, response, url) {
  // ── Connexion avec un compte tiers ─────────────────────────────────────────
  //
  // Un aller et un retour, tous deux en GET, tous deux sans session. Le `state` est
  // le seul lien entre les deux : tiré au hasard au départ, mis en cookie `HttpOnly`,
  // relu en comparaison constante au retour. Le fournisseur est déduit du chemin, donc
  // un ajout au registre rend ses routes existantes sans nouveau branchement ici. Un
  // nom inconnu n'est pas un fournisseur : il poursuit vers les routes habituelles,
  // qui répondront « introuvable ».
  const pathProvider = findOAuthProvider(url.pathname.split("/")[3]);
  if (pathProvider) {
    await handleProviderAuthApi(pathProvider, request, response, url);
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/auth/me") {
    const session = getSession(request);
    // Dit à l'interface quels boutons « continuer avec … » ont un sens. Ce n'est pas un
    // secret : sans identifiants configurés, la route répond de toute façon
    // « introuvable », et le serveur reste utilisable hors ligne.
    const providers = listEnabledProviders();
    if (!session) {
      sendJson(response, 200, { user: null, csrfToken: null, providers });
      return;
    }
    sendJson(response, 200, {
      user: publicUser(session),
      csrfToken: session.csrfToken,
      entitlement: resolveEntitlement(session.userId),
      subscription: getSubscriptionSummary(session.userId),
      providers,
      // La page du compte a besoin de savoir quelle identité est déjà attachée avant de
      // proposer le geste, et si un mot de passe existe : un compte créé par un
      // fournisseur n'en a pas, et les formulaires d'identité ne se présentent pas de la
      // même façon.
      linkedProvider: session.authProvider === "local" ? null : session.authProvider,
      hasPassword: session.hasPassword,
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
    // Le second facteur est vérifié avant toute création de session : le mot de
    // passe volé ne doit pas suffire à obtenir un cookie, même éphémère, car une
    // session créée puis invalidée resterait une surface d'attaque pendant le temps
    // de la requête.
    await verifyLoginTwoFactor(user.id, body);
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

  // ── Double authentification du compte ───────────────────────────────────────
  //
  // Ces routes exigent une session : c'est la contrepartie de leur existence. Un
  // secret d'authentification posé sans session ouvrirait le compte à quiconque
  // détient le cookie, et l'activation exige donc le mot de passe en plus.
  if (url.pathname.startsWith("/api/auth/2fa")) {
    await handleTwoFactorApi(request, response, url);
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
// suppression — exige une preuve récente : le mot de passe actuel pour un compte qui
// en a un, un passage récent par le fournisseur d'identité pour un compte qui n'en a
// pas. Un cookie volé sur un poste partagé donne l'accès à la bibliothèque, pas la
// propriété du compte : sans cette seconde preuve, un attaquant s'y installerait
// durablement en changeant l'adresse, ce qui coupe aussi la réinitialisation de mot
// de passe à la victime.
//
// La substitution n'est possible que dans un sens : un compte qui a un mot de passe le
// saisit toujours. La fenêtre de fraîcheur ne déroge à rien, elle n'existe que là où
// il n'y a rien à saisir.

async function requireCurrentPassword(session, body) {
  const row = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(session.userId);
  // Sans mot de passe, la preuve est l'aller-retour par le fournisseur, daté dans la
  // session. La fenêtre est courte et n'autorise que des actions déjà soumises au
  // jeton de session et au CSRF : elle ne permet pas d'ouvrir une session.
  if (row && !row.password_hash) {
    if (session.freshUntil > now()) return;
    throw new HttpError(
      403,
      "Reprouve ton identité avec Google pour continuer.",
      "reauth_required",
    );
  }
  if (typeof body.currentPassword !== "string" || body.currentPassword.length < 1 || body.currentPassword.length > 128) {
    throw new HttpError(400, "Saisis ton mot de passe actuel pour confirmer.", "current_password_required");
  }
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

  // -- Modes de connexion ----------------------------------------------------
  //
  // Relier une identité à un compte n'est pas un aller-retour d'anonyme vers un compte :
  // le mot de passe est demandé avant, car c'est lui qui prouve que le compte appartient
  // à celui qui demande. Un cookie de session volé ne suffirait pas à rattacher une
  // identité tierce, donc à se garantir un accès durable après la perte du cookie.
  //
  // Les trois routes renvoient l'adresse du fournisseur plutôt qu'une redirection : le
  // navigateur ne peut pas suivre une `Location` vers un autre site depuis une requête
  // faite en JavaScript, donc c'est l'interface qui l'ouvre.
  //
  // Un compte ne portant qu'une identité, la liaison est refusée dès qu'une autre est
  // attachée, et la ré-authentification n'accepte que celle qui l'est déjà. Rien n'est
  // remplacé ni repris sur une simple ressemblance d'adresse.
  const accountAction = url.pathname.match(/^\/api\/account\/([a-z0-9_-]+)\/(link|unlink|reauth)$/);
  const accountProvider = accountAction ? findOAuthProvider(accountAction[1]) : null;
  if (request.method === "POST" && accountProvider) {
    const action = accountAction[2];
    verifyCsrf(request, session);

    if (action === "unlink") {
      // Pas de garde de configuration ici, à la différence des deux autres : retirer une
      // identité ne demande rien au fournisseur. Sans lui, un lien serait prisonnier d'une
      // configuration disparue, sans aucun moyen de s'en défaire depuis le compte.
      checkRateLimit(`oauth-unlink:${session.userId}`, 5, 60 * 60 * 1_000);
      // L'identité ne peut venir que de son fournisseur : demander à l'un de retirer
      // celle d'un autre n'aurait aucun sens, ni à l'un ni à l'autre.
      if (session.authProvider !== accountProvider.id) {
        throw new HttpError(
          409,
          `Aucune identité ${accountProvider.label} n'est reliée à ce compte.`,
          "identity_not_linked",
        );
      }
      // Ce refus précède la preuve : un compte sans mot de passe ne pourra jamais
      // satisfaire la demande suivante, et le renvoyer vers le fournisseur pour découvrir
      // ensuite qu'il devait d'abord définir un mot de passe serait un détour.
      if (!session.hasPassword) {
        throw new HttpError(
          409,
          `Ce compte n'a pas de mot de passe : définir-en un avant de délier l'identité ${accountProvider.label}.`,
          "password_required_to_unlink",
        );
      }
      await requireCurrentPassword(session, requireObject(await readJson(request)));
      // L'identité devient de nouveau disponible pour un autre compte. Le délai de
      // réflexion n'est pas mis en place : il faudrait garder le `sub` en attente, donc
      // garder une trace de l'identité retirée, ce que la suppression du compte elle-même
      // ne fait pas non plus. Le retrait est immédiat ou il n'est pas.
      db.prepare(`
        UPDATE users SET auth_provider = 'local', provider_id = NULL
        WHERE id = ? AND provider_id IS NOT NULL
      `).run(session.userId);
      sendJson(response, 200, { ok: true });
      return;
    }

    // La liaison et la ré-authentification parlent toutes deux au fournisseur : sans lui,
    // le parcours n'a nulle part où aller.
    requireProviderConfigured(accountProvider);
    // Déliaison, liaison et ré-authentification partagent une même limite par compte :
    // elles ne sont pas trois fois plus permissives avec le même effet.
    // La ré-authentification est plus fréquente qu'une liaison et sert aux actes
    // sensibles : sa limite est plus large, celle de la liaison reste horaire.
    checkRateLimit(`oauth-${action}:${session.userId}`, action === "reauth" ? 10 : 5, 60 * 60 * 1_000);
    if (action === "link") {
      // Relier ne demande rien au compte : c'est précisément elle qui va lui donner une
      // identité. Le mot de passe précède tout, car c'est lui qui prouve que le compte
      // appartient à celui qui demande la liaison.
      await requireCurrentPassword(session, requireObject(await readJson(request)));
      // Seule une identité à rattacher manque à l'appel : « déjà relié » vaut pour le
      // fournisseur courant comme pour un autre, une identité n'en remplace jamais une
      // autre sans déliaison préalable.
      if (session.providerId) {
        throw new HttpError(
          409,
          "Ce compte est déjà relié à une identité de fournisseur. Délie-la avant d'en relier une autre.",
          "identity_already_linked",
        );
      }
    } else if (!session.providerId || session.authProvider !== accountProvider.id) {
      throw new HttpError(409, `Aucune identité ${accountProvider.label} n'est reliée à ce compte.`, "identity_not_linked");
    }
    // La double authentification gagne sur tout fournisseur tiers : un compte qui exige
    // un code à chaque connexion ne doit pas pouvoir être rouvert par un aller-retour,
    // qui n'a aucun champ où le saisir. Le refus vient après les garde-fous précédents :
    // parler de second facteur à un compte qui n'a rien à prouver serait un détour.
    if (isTwoFactorEnrolled(twoFactorRecord(session.userId))) {
      throw new HttpError(
        409,
        `Ce compte exige un code d'authentification à chaque connexion : la connexion ${accountProvider.label} y est désactivée.`,
        "two_factor_conflict",
      );
    }
    const flow = prepareProviderFlow(accountProvider, action, { userId: session.userId, sessionId: session.id });
    sendJson(response, 200, { url: flow.url }, { "Set-Cookie": flow.cookies });
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

// ── Back-office du super-admin ───────────────────────────────────────────────
// Toutes les routes ci-dessous exigent le rôle, sont réservées à l'écriture sur
// un autre compte, et journalisent leur intervention. Aucune ne modifie le rôle :
// `is_super_admin` n'est écrit par aucun `INSERT` ni `UPDATE` de l'application,
// seulement par une commande SQL Volontaire. C'est ce qui rend le rôle
// inexploitable depuis une faille : il n'y a pas de route où l'obtenir.

const ADMIN_REASON_MIN = 8;
const ADMIN_REASON_MAX = 300;

// Une raison courte ne prouve rien : « test » ou « urgent » ne disent ni qui a
// décidé, ni pourquoi. Le seuil est bas mais il exclut les motifs vides.
function validateAdminReason(value) {
  const reason = cleanText(value, ADMIN_REASON_MAX);
  if (reason.length < ADMIN_REASON_MIN) {
    throw new HttpError(
      400,
      `Indique la raison de l'intervention (${ADMIN_REASON_MIN} caractères minimum).`,
      "reason_required",
    );
  }
  return reason;
}

// Les adresses sont dénormalisées : la ligne doit survivre à la suppression du
// compte qu'elle décrit, sinon le journal s'écrit avec les comptes qu'il a effacés.
function recordAdminAction(actor, target, action, reason, metadata = null) {
  // La cible a pu être supprimée par l'action elle-même, et une clé étrangère ne
  // peut pas désigner une ligne disparue : la ligne est alors journalisée sans
  // identifiant, l'adresse dénormalisée suffit à la désigner. C'est aussi
  // pourquoi la suppression du compte est écrite *après* son effacement.
  const targetId =
    target?.id != null && db.prepare("SELECT 1 FROM users WHERE id = ?").get(target.id) ? target.id : null;
  db.prepare(`
    INSERT INTO admin_actions (
      actor_user_id, actor_email, target_user_id, target_email, action, reason, metadata, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    actor.userId,
    String(actor.email || "").toLowerCase(),
    targetId,
    String(target?.email || "").toLowerCase(),
    action,
    reason,
    metadata ? JSON.stringify(metadata) : null,
    now(),
  );
}

function adminTargetUser(id) {
  const user = db.prepare(`
    SELECT id, display_name, email, email_verified_at, pending_email, created_at, is_super_admin
    FROM users WHERE id = ?
  `).get(id);
  if (!user) throw new HttpError(404, "Compte introuvable.", "user_not_found");
  return user;
}

// Un super-admin ne s'attaque ni à lui-même ni à un autre super-admin, et le
// back-office ne touche pas du tout un compte porteur du rôle. La règle est plus
// large que la simple suppression parce qu'aucune maintenance légitime ne justifie
// d'avoir pour cible le seul compte qui peut administrer : si ce compte doit
// changer, son propriétaire décide, hors de l'application.
function requireAdminTarget(actor, target) {
  if (target.id === actor.userId) {
    throw new HttpError(400, "Utilise les pages de ton compte pour cette action.", "admin_self_action");
  }
  if (target.is_super_admin) {
    throw new HttpError(
      403,
      "Ce compte est super-admin : il est protégé et ne peut être ni modifié ni supprimé d'ici.",
      "super_admin_protected",
    );
  }
}

function adminSearchPattern(search) {
  const value = String(search || "").trim();
  if (!value) return null;
  // `ESCAPE` neutralise les jokers `%` et `_` : une recherche de « 100% » doit
  // chercher cette chaîne, pas « n'importe quoi ».
  return `%${value.replace(/[\\%_]/g, (character) => `\\${character}`)}%`;
}

function listAdminUsers(search, limit, offset) {
  const pattern = adminSearchPattern(search);
  const timestamp = now();
  const where = pattern ? "WHERE u.email LIKE ? ESCAPE '\\' OR u.display_name LIKE ? ESCAPE '\\'" : "";
  const params = pattern ? [...patternParams(pattern), limit, offset] : [limit, offset];
  const rows = db.prepare(`
    SELECT u.id, u.display_name, u.email, u.email_verified_at, u.created_at, u.is_super_admin,
           (SELECT COUNT(*) FROM qrcodes q WHERE q.user_id = u.id) AS qrcode_count,
           (SELECT COUNT(*) FROM qrcodes q WHERE q.user_id = u.id AND q.is_active = 1) AS active_count,
           (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ${timestamp}) AS session_count,
           (SELECT id FROM subscriptions WHERE user_id = u.id
             ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1) AS subscription_id,
           (SELECT plan FROM subscriptions WHERE user_id = u.id
             ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1) AS plan,
           (SELECT status FROM subscriptions WHERE user_id = u.id
             ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1) AS status,
           (SELECT grace_until FROM subscriptions WHERE user_id = u.id
             ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1) AS grace_until,
           (SELECT current_period_end FROM subscriptions WHERE user_id = u.id
             ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1) AS current_period_end,
           (SELECT cancel_at_period_end FROM subscriptions WHERE user_id = u.id
             ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1) AS cancel_at_period_end,
           (SELECT stripe_subscription_id FROM subscriptions WHERE user_id = u.id
             ORDER BY (status NOT IN ('canceled','incomplete_expired')) DESC, updated_at DESC LIMIT 1) AS stripe_subscription_id
    FROM users u
    ${where}
    ORDER BY u.id DESC
    LIMIT ? OFFSET ?
  `).all(...params);
  const total = db
    .prepare(`SELECT COUNT(*) AS total FROM users u ${where}`)
    .get(...(pattern ? patternParams(pattern) : [])).total;
  return { rows, total };
}

// Les jokers du motif sont introduits une seule fois ici, pour que `LIKE` et le
// `COUNT` portent exactement le même filtrage.
function patternParams(pattern) {
  return [pattern, pattern];
}

// Colonnes nommées une à une, jamais `SELECT *` : `contact_data` et `vcard` sont
// des données personnelles qu'aucune raison de maintenance ne justifie, et les
// lister ici les exposerait par simple oubli d'une colonne dans un `*`.
function adminQrcodeRows(userId) {
  return db.prepare(`
    SELECT q.id, q.name, q.mode, q.destination, q.is_active, q.created_at,
           (SELECT COALESCE(SUM(r.scan_count), 0) FROM scan_rollups r WHERE r.qrcode_id = q.id) AS scan_count
    FROM qrcodes q
    WHERE q.user_id = ?
    ORDER BY q.id DESC
  `).all(userId);
}

function listAdminActions(limit, offset) {
  const rows = db.prepare(`
    SELECT id, actor_email, target_email, action, reason, metadata, created_at
    FROM admin_actions
    ORDER BY id DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);
  const total = db.prepare("SELECT COUNT(*) AS total FROM admin_actions").get().total;
  return { rows, total };
}

// ── Double authentification du rôle ───────────────────────────────────────────
//
// RFC 6238 sur HMAC-SHA1, 6 chiffres, pas de 30 s. La fenêtre ±1 absorbe l'écart
// d'horloge entre le téléphone et le serveur ; le compteur consommé est mémorisé,
// sinon un code sniffé resterait rejouable pendant toute sa fenêtre.
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1;
const TOTP_SETUP_TTL_MS = 10 * 60 * 1_000;
const TOTP_SECRET_BYTES = 20;
const RECOVERY_CODE_COUNT = 8;
// 24 lettres (sans I ni O) et 8 chiffres (sans 0 ni 1) : 32 symboles, donc un
// tirage sans biais sur un octet, et rien qui se confonde à la lecture.
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function base32Encode(bytes) {
  let value = 0;
  let bits = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(text) {
  const cleaned = String(text || "").toUpperCase().replace(/[\s=]+/g, "");
  let value = 0;
  let bits = 0;
  const bytes = [];
  for (const character of cleaned) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index === -1) throw new HttpError(400, "Secret d'authentification illisible.", "invalid_two_factor_setup");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totpAtCounter(secret, counter) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", base32Decode(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

// Renvoie le compteur accepté, ou `null`. Le compteur est mémorisé pour qu'un
// code réutilisé dans la fenêtre soit refusé comme un rejeu.
function consumeTotpCode(userId, secret, code, at = now()) {
  const candidate = Buffer.from(String(code || "").trim());
  if (candidate.length !== TOTP_DIGITS || !/^\d+$/.test(candidate.toString())) return null;
  const record = twoFactorRecord(userId);
  const counter = Math.floor(at / 1_000 / TOTP_STEP_SECONDS);
  for (let drift = -TOTP_WINDOW; drift <= TOTP_WINDOW; drift += 1) {
    const candidateCounter = counter + drift;
    if (record?.last_counter != null && candidateCounter <= record.last_counter) continue;
    const expected = Buffer.from(totpAtCounter(secret, candidateCounter));
    if (timingSafeEqual(expected, candidate)) {
      db.prepare("UPDATE two_factor_auth SET last_counter = ? WHERE user_id = ?").run(candidateCounter, userId);
      return candidateCounter;
    }
  }
  return null;
}

function normalizeRecoveryCode(code) {
  return String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function recoveryCodeHash(code) {
  return createHash("sha256").update(normalizeRecoveryCode(code)).digest("hex");
}

function generateRecoveryCodes(count = RECOVERY_CODE_COUNT) {
  const codes = [];
  for (let index = 0; index < count; index += 1) {
    let raw = "";
    for (const byte of randomBytes(10)) raw += RECOVERY_ALPHABET[byte % 32];
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

function storedRecoveryCodes(record) {
  try {
    const parsed = JSON.parse(record?.recovery_codes || "[]");
    return Array.isArray(parsed) ? parsed.filter((entry) => typeof entry === "string") : [];
  } catch {
    return [];
  }
}

function twoFactorRecord(userId) {
  return db.prepare("SELECT * FROM two_factor_auth WHERE user_id = ?").get(userId) || null;
}

function isTwoFactorEnrolled(record) {
  return Boolean(record?.secret && record?.confirmed_at);
}

function twoFactorStatus(userId) {
  const record = twoFactorRecord(userId);
  const enrolled = isTwoFactorEnrolled(record);
  return {
    enrolled,
    confirmedAt: record?.confirmed_at ? isoDate(record.confirmed_at) : null,
    recoveryCodesRemaining: enrolled ? storedRecoveryCodes(record).length : 0,
    setupPending: Boolean(record?.pending_secret && record.pending_expires_at > now()),
  };
}

// Vérifie un second facteur déjà authentifié et renvoie le moyen par lequel il a
// servi, ou `null` si le code est refusé. Aucun appelant ne doit traiter un refus
// comme un simple échec de connexion : c'est le même refus pour un code expiré, un
// code déjà consommé et une clé de récupération épuisée.
//
// La clé de limitation est le compte et non l'IP : derrière un partage de connexion
// ou un VPN, une limite par adresse punirait un utilisateur légitime tout en
// laissant un attaquant libre d'enumer les codes depuis une autre adresse.
function verifyTwoFactorCode(userId, record, code) {
  if (consumeTotpCode(userId, record.secret, code) !== null) return "totp";
  if (consumeRecoveryCode(userId, record, code)) return "recovery";
  return null;
}

// Second facteur exigé sur chaque écriture d'exploitation. Tant que la double
// authentification n'est pas activée, le mot de passe tient lieu de seconde
// preuve : c'est une étape de plus, pas un facteur supplémentaire, et le journal
// dit lequel des deux a réellement servi.
async function requireAdminTwoFactor(session, body) {
  const record = twoFactorRecord(session.userId);
  if (!isTwoFactorEnrolled(record)) {
    await requireCurrentPassword(session, body);
    return "password";
  }
  const code = typeof body.twoFactorCode === "string" ? body.twoFactorCode.trim() : "";
  if (!code) {
    throw new HttpError(
      403,
      "Saisis le code de ton application d'authentification, ou un code de récupération.",
      "two_factor_required",
    );
  }
  // 10 essais par 5 minutes : un code à 6 chiffres s'énumère en 10^6 essais, la
  // fenêtre de 30 s ne suffit donc pas à le deviner de but en blanc.
  checkRateLimit(`admin-2fa:${session.userId}`, 10, 5 * 60 * 1_000);
  const accepted = verifyTwoFactorCode(session.userId, record, code);
  if (accepted) return accepted;
  throw new HttpError(403, "Code d'authentification invalide.", "invalid_two_factor_code");
}

function consumeRecoveryCode(userId, record, code) {
  const normalized = normalizeRecoveryCode(code);
  if (!normalized) return false;
  const candidate = Buffer.from(recoveryCodeHash(normalized));
  const codes = storedRecoveryCodes(record);
  const index = codes.findIndex((hash) => {
    const stored = Buffer.from(hash);
    return stored.length === candidate.length && timingSafeEqual(stored, candidate);
  });
  if (index === -1) return false;
  codes.splice(index, 1);
  db.prepare("UPDATE two_factor_auth SET recovery_codes = ?, updated_at = ? WHERE user_id = ?").run(
    JSON.stringify(codes),
    now(),
    userId,
  );
  return true;
}

// La ligne courante est la seule ligne non terminale — l'index unique
// `idx_subscriptions_live_user` le garantit. Trier seulement par `updated_at`
// laisserait une ligne d'historique récemment touchée passer devant elle : un
// webhook Stripe arrivé en retard après une résiliation suffit à faire displaysse
// l'ancien abonnement résilié au lieu de l'accès en cours.
// ── Double authentification d'un compte ──────────────────────────────────────
//
// Le mécanisme est celui du rôle super-admin, généralisé à tout compte : mêmes
// règles TOTP, mêmes codes de récupération, une seule table. Les routes sont
// séparées de `/api/admin/2fa/*` parce que les exigences ne sont pas les mêmes : ni
// rôle, ni journal d'intervention, ni motif — l'utilisateur agit sur son propre
// compte, et exiger une raison de huit caractères n'aurait aucun sens.

const TOTP_URI_ISSUER = "QROOD";

// Une seule fonction pour les deux surfaces : la chaîne servie à l'application
// d'authentification est celle qu'un scanner lit, et une divergence entre le
// back-office et `/compte` produirait un secret que l'un des deux écrans ne
// présenterait jamais.
function totpUri(secret, email) {
  return (
    `otpauth://totp/${encodeURIComponent(`${TOTP_URI_ISSUER}:${email}`)}` +
    `?secret=${secret}&issuer=${encodeURIComponent(TOTP_URI_ISSUER)}` +
    `&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`
  );
}

// Second facteur exigé à la connexion. Le message d'erreur distingue le code absent
// du code invalide : ce n'est pas une fuite, le mot de passe vient d'être validé et
// l'interface a besoin de savoir s'il doit afficher le champ de saisie ou refuser.
async function verifyLoginTwoFactor(userId, body) {
  const record = twoFactorRecord(userId);
  if (!isTwoFactorEnrolled(record)) return;
  const code = typeof body.twoFactorCode === "string" ? body.twoFactorCode.trim() : "";
  if (!code) {
    throw new HttpError(
      401,
      "Saisis le code de ton application d'authentification, ou un code de récupération.",
      "two_factor_required",
    );
  }
  // Même limite que sur une intervention d'exploitation, et par compte : un mot de
  // passe correct ne doit pas autoriser à deviner le second facteur.
  checkRateLimit(`login-2fa:${userId}`, 10, 5 * 60 * 1_000);
  if (verifyTwoFactorCode(userId, record, code)) return;
  throw new HttpError(401, "Code d'authentification invalide.", "invalid_two_factor_code");
}

async function handleTwoFactorApi(request, response, url) {
  const session = requireSession(request);

  if (request.method === "GET" && url.pathname === "/api/auth/2fa") {
    checkRateLimit(`2fa-read:${session.userId}`, 60, 60 * 1_000);
    sendJson(response, 200, twoFactorStatus(session.userId));
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/2fa/setup") {
    verifyCsrf(request, session);
    checkRateLimit(`2fa-setup:${session.userId}`, 5, 10 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    // Un compte sans mot de passe n'a qu'une porte, Google — et Google ne demande
    // aucun code d'authentification. Enroler un second facteur le laisserait sans
    // aucune façon de s'ouvrir : la double authentification ferme la connexion Google,
    // la ré-authentification Google est refusée, et il n'y a pas de mot de passe à
    // saisir. La seule sortie resterait la réinitialisation par e-mail, pour un compte
    // qui n'en a jamais connu. Le mot de passe passe donc avant tout.
    if (!session.hasPassword) {
      throw new HttpError(
        409,
        "Définis d'abord un mot de passe : sans lui, la double authentification te fermerait la seule porte qui t'ouvre.",
        "password_required_before_two_factor",
      );
    }
    // Le mot de passe est exigé : sur une session volée, c'est le seul facteur
    // encore connu de la victime.
    await requireCurrentPassword(session, body);
    const secret = base32Encode(randomBytes(TOTP_SECRET_BYTES));
    const expiresAt = now() + TOTP_SETUP_TTL_MS;
    // Réécrire `pending_secret` remplace une activation commencée et abandonnée :
    // deux secrets en attente laisseraient l'interface en présenter un au hasard,
    // sans que l'utilisateur sache lequel a été confirmé.
    db.prepare(`
      INSERT INTO two_factor_auth (user_id, pending_secret, pending_expires_at, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        pending_secret = excluded.pending_secret,
        pending_expires_at = excluded.pending_expires_at,
        updated_at = excluded.updated_at
    `).run(session.userId, secret, expiresAt, now());
    sendJson(response, 200, {
      secret,
      uri: totpUri(secret, session.email),
      expiresAt: isoDate(expiresAt),
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/2fa/confirm") {
    verifyCsrf(request, session);
    checkRateLimit(`2fa-confirm:${session.userId}`, 10, 5 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const record = twoFactorRecord(session.userId);
    if (!record?.pending_secret || record.pending_expires_at <= now()) {
      throw new HttpError(
        409,
        "L'activation a expiré : relance-la pour obtenir un nouveau QR code.",
        "two_factor_setup_expired",
      );
    }
    // Le code est validé contre le secret en attente, et non contre le secret actif :
    // sans cela, confirmer une nouvelle activation validerait le code de l'ancienne,
    // et l'interface apparenterait un secret qui n'a jamais été vu à un code que
    // l'utilisateur connaît déjà.
    if (consumeTotpCode(session.userId, record.pending_secret, body.code) === null) {
      throw new HttpError(403, "Ce code ne correspond pas au QR code affiché.", "invalid_two_factor_code");
    }
    const codes = generateRecoveryCodes();
    db.prepare(`
      UPDATE two_factor_auth
      SET secret = pending_secret,
          pending_secret = NULL,
          pending_expires_at = NULL,
          last_counter = NULL,
          confirmed_at = ?,
          recovery_codes = ?,
          updated_at = ?
      WHERE user_id = ?
    `).run(now(), JSON.stringify(codes.map(recoveryCodeHash)), now(), session.userId);
    // Une seule fois : la base n'en garde que des empreintes.
    sendJson(response, 200, { recoveryCodes: codes });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/2fa/recovery-codes") {
    verifyCsrf(request, session);
    checkRateLimit(`2fa-recovery:${session.userId}`, 5, 10 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const record = twoFactorRecord(session.userId);
    if (!isTwoFactorEnrolled(record)) {
      throw new HttpError(409, "La double authentification n'est pas active.", "two_factor_not_enrolled");
    }
    // Mot de passe puis second facteur : régénérer les codes de récupération est
    // exactement ce qu'un attaquant ferait après avoir capturé une session volée.
    // Le mot de passe seul ne suffirait pas à s'en rémunérer.
    await requireCurrentPassword(session, body);
    const code = typeof body.twoFactorCode === "string" ? body.twoFactorCode.trim() : "";
    if (!code) {
      throw new HttpError(403, "Saisis ton code d'authentification.", "two_factor_required");
    }
    checkRateLimit(`2fa-verify:${session.userId}`, 10, 5 * 60 * 1_000);
    if (!verifyTwoFactorCode(session.userId, record, code)) {
      throw new HttpError(403, "Code d'authentification invalide.", "invalid_two_factor_code");
    }
    const codes = generateRecoveryCodes();
    db.prepare("UPDATE two_factor_auth SET recovery_codes = ?, updated_at = ? WHERE user_id = ?").run(
      JSON.stringify(codes.map(recoveryCodeHash)),
      now(),
      session.userId,
    );
    sendJson(response, 200, { recoveryCodes: codes });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/auth/2fa/disable") {
    verifyCsrf(request, session);
    checkRateLimit(`2fa-disable:${session.userId}`, 5, 10 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const record = twoFactorRecord(session.userId);
    if (!isTwoFactorEnrolled(record)) {
      throw new HttpError(409, "La double authentification n'est pas active.", "two_factor_not_enrolled");
    }
    // Désactiver le second facteur ne demande jamais moins que ce qu'en demander
    // l'activation : mot de passe, puis code.
    await requireCurrentPassword(session, body);
    const code = typeof body.twoFactorCode === "string" ? body.twoFactorCode.trim() : "";
    if (!code) {
      throw new HttpError(403, "Saisis ton code d'authentification.", "two_factor_required");
    }
    checkRateLimit(`2fa-verify:${session.userId}`, 10, 5 * 60 * 1_000);
    if (!verifyTwoFactorCode(session.userId, record, code)) {
      throw new HttpError(403, "Code d'authentification invalide.", "invalid_two_factor_code");
    }
    db.prepare("DELETE FROM two_factor_auth WHERE user_id = ?").run(session.userId);
    sendJson(response, 200, { ok: true });
    return;
  }

  throw new HttpError(404, "Ressource introuvable.", "not_found");
}

function adminSubscriptionRow(userId) {
  return db.prepare(`
    SELECT id, plan, status, current_period_end, cancel_at_period_end, grace_until,
           stripe_subscription_id
    FROM subscriptions WHERE user_id = ?
    ORDER BY (status NOT IN ('canceled', 'incomplete_expired')) DESC, updated_at DESC
    LIMIT 1
  `).get(userId) || null;
}

async function handleAdminApi(request, response, url) {
  // Une seule garde, posée avant toute route : il n'existe aucune lecture publique
  // sous `/api/admin/`, pas même la liste vide.
  const session = requireSuperAdmin(request);

  if (request.method === "GET" && url.pathname === "/api/admin/users") {
    checkRateLimit(`admin-read:${session.userId}`, 240, 60 * 1_000);
    const { limit, offset } = parsePagination(url);
    const search = cleanText(url.searchParams.get("search") || "", 120);
    const { rows, total } = listAdminUsers(search, limit, offset);
    const timestamp = now();
    sendJson(response, 200, {
      users: rows.map((row) => {
        // Le renouvellement est appliqué ici aussi : sans lui, la liste afficherait
        // une offre retombée sur Découverte alors que la fiche du même compte
        // afficherait l'accès renouvelé, et l'écran se contredirait lui-même.
        renewManualOffer(row, timestamp);
        return {
          id: row.id,
          displayName: row.display_name,
          email: row.email,
          emailVerified: Boolean(row.email_verified_at),
          isSuperAdmin: Boolean(row.is_super_admin),
          createdAt: isoDate(row.created_at),
          qrcodeCount: row.qrcode_count,
          activeCount: row.active_count,
          sessionCount: row.session_count,
          plan: effectivePlanKey(row, timestamp),
          status: row.status || null,
        };
      }),
      total,
      limit,
      offset,
    });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/admin/audit") {
    checkRateLimit(`admin-read:${session.userId}`, 240, 60 * 1_000);
    const { limit, offset } = parsePagination(url);
    const { rows, total } = listAdminActions(limit, offset);
    sendJson(response, 200, {
      actions: rows.map((row) => ({
        id: row.id,
        actorEmail: row.actor_email,
        targetEmail: row.target_email,
        action: row.action,
        reason: row.reason,
        createdAt: isoDate(row.created_at),
      })),
      total,
      limit,
      offset,
    });
    return;
  }

  // ── Double authentification ─────────────────────────────────────────────────
  if (request.method === "GET" && url.pathname === "/api/admin/2fa") {
    checkRateLimit(`admin-read:${session.userId}`, 240, 60 * 1_000);
    sendJson(response, 200, twoFactorStatus(session.userId));
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/admin/2fa/setup") {
    verifyCsrf(request, session);
    checkRateLimit(`admin-2fa-setup:${session.userId}`, 5, 10 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const reason = validateAdminReason(body.reason);
    // Un secret d'authentification n'est jamais posé sur une session volée : le
    // mot de passe est exigé ici, car c'est le seul facteur encore connu.
    await requireCurrentPassword(session, body);
    const secret = base32Encode(randomBytes(TOTP_SECRET_BYTES));
    const expiresAt = now() + TOTP_SETUP_TTL_MS;
    db.prepare(`
      INSERT INTO two_factor_auth (user_id, pending_secret, pending_expires_at, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        pending_secret = excluded.pending_secret,
        pending_expires_at = excluded.pending_expires_at,
        updated_at = excluded.updated_at
    `).run(session.userId, secret, expiresAt, now());
    recordAdminAction(session, adminTargetUser(session.userId), "two_factor_setup", reason);
    sendJson(response, 200, {
      secret,
      uri: totpUri(secret, session.email),
      expiresAt: isoDate(expiresAt),
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/admin/2fa/confirm") {
    verifyCsrf(request, session);
    checkRateLimit(`admin-2fa-confirm:${session.userId}`, 10, 5 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const reason = validateAdminReason(body.reason);
    const record = twoFactorRecord(session.userId);
    if (!record?.pending_secret || record.pending_expires_at <= now()) {
      throw new HttpError(409, "L'activation a expiré : relance-la pour obtenir un nouveau QR code.", "two_factor_setup_expired");
    }
    if (consumeTotpCode(session.userId, record.pending_secret, body.code) === null) {
      throw new HttpError(403, "Ce code ne correspond pas au QR code affiché.", "invalid_two_factor_code");
    }
    const codes = generateRecoveryCodes();
    db.prepare(`
      UPDATE two_factor_auth
      SET secret = pending_secret,
          pending_secret = NULL,
          pending_expires_at = NULL,
          last_counter = NULL,
          confirmed_at = ?,
          recovery_codes = ?,
          updated_at = ?
      WHERE user_id = ?
    `).run(now(), JSON.stringify(codes.map(recoveryCodeHash)), now(), session.userId);
    recordAdminAction(session, adminTargetUser(session.userId), "two_factor_enabled", reason, {
      recoveryCodes: codes.length,
    });
    // Les codes ne sont renvoyés qu'ici, qu'une fois : la base n'en garde que les
    // empreintes. Les perdre est définitif, d'où le avertissement côté interface.
    sendJson(response, 200, { recoveryCodes: codes });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/admin/2fa/recovery-codes") {
    verifyCsrf(request, session);
    checkRateLimit(`admin-2fa-recovery:${session.userId}`, 5, 10 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const reason = validateAdminReason(body.reason);
    const record = twoFactorRecord(session.userId);
    if (!isTwoFactorEnrolled(record)) {
      throw new HttpError(409, "La double authentification n'est pas active.", "two_factor_not_enrolled");
    }
    await requireCurrentPassword(session, body);
    // Une session volée ne doit pas pouvoir remplacer les codes de récupération :
    // le mot de passe ne suffit pas, il faut le second facteur.
    await requireAdminTwoFactor(session, body);
    const codes = generateRecoveryCodes();
    db.prepare("UPDATE two_factor_auth SET recovery_codes = ?, updated_at = ? WHERE user_id = ?").run(
      JSON.stringify(codes.map(recoveryCodeHash)),
      now(),
      session.userId,
    );
    recordAdminAction(session, adminTargetUser(session.userId), "two_factor_recovery_regenerated", reason, {
      recoveryCodes: codes.length,
    });
    sendJson(response, 200, { recoveryCodes: codes });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/admin/2fa/disable") {
    verifyCsrf(request, session);
    checkRateLimit(`admin-2fa-disable:${session.userId}`, 5, 10 * 60 * 1_000);
    const body = requireObject(await readJson(request));
    const reason = validateAdminReason(body.reason);
    const record = twoFactorRecord(session.userId);
    if (!isTwoFactorEnrolled(record)) {
      throw new HttpError(409, "La double authentification n'est pas active.", "two_factor_not_enrolled");
    }
    await requireCurrentPassword(session, body);
    await requireAdminTwoFactor(session, body);
    db.prepare("DELETE FROM two_factor_auth WHERE user_id = ?").run(session.userId);
    recordAdminAction(session, adminTargetUser(session.userId), "two_factor_disabled", reason);
    sendJson(response, 200, { ok: true });
    return;
  }

  const userMatch = url.pathname.match(/^\/api\/admin\/users\/(\d{1,12})(\/[\w/-]+)?$/);
  if (userMatch && !userMatch[2] && request.method === "GET") {
    checkRateLimit(`admin-read:${session.userId}`, 240, 60 * 1_000);
    const target = adminTargetUser(Number(userMatch[1]));
    sendJson(response, 200, {
      user: {
        id: target.id,
        displayName: target.display_name,
        email: target.email,
        emailVerified: Boolean(target.email_verified_at),
        pendingEmail: target.pending_email,
        isSuperAdmin: Boolean(target.is_super_admin),
        createdAt: isoDate(target.created_at),
      },
      // Même résumé que sur /compte : deux Assembleurs d'abonnement divergent
      // au premier champ oublié, et le back-office montrerait alors un accès
      // offert comme s'il était facturé.
      subscription: getSubscriptionSummary(target.id),
      entitlement: resolveEntitlement(target.id),
      sessionCount: db
        .prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > ?")
        .get(target.id, now()).n,
      qrcodes: adminQrcodeRows(target.id),
    });
    return;
  }

  // ── Actions ────────────────────────────────────────────────────────────────
  if (request.method === "POST" && userMatch && userMatch[2]) {
    verifyCsrf(request, session);
    checkRateLimit(`admin-write:${session.userId}`, 120, 60 * 1_000);
    const target = adminTargetUser(Number(userMatch[1]));
    requireAdminTarget(session, target);
    const body = requireObject(await readJson(request));
    const reason = validateAdminReason(body.reason);
    const factor = await requireAdminTwoFactor(session, body);
    const audit = (action, target, metadata = null) =>
      recordAdminAction(session, target, action, reason, { factor, ...(metadata || {}) });
    const action = userMatch[2];

    if (action === "/password") {
      const password = validatePassword(body.newPassword);
      const passwordHash = await hashPassword(password);
      db.exec("BEGIN");
      try {
        db.prepare("UPDATE users SET password_hash = ?, email_verified_at = NULL WHERE id = ?").run(
          passwordHash,
          target.id,
        );
        // Les sessions tombent avec le mot de passe : un accès obtenu avec
        // l'ancien ne doit pas survivre à son remplacement. L'adresse repart à
        // zéro aussi, car elle ne prouve plus que qui que ce soit.
        db.prepare("DELETE FROM sessions WHERE user_id = ?").run(target.id);
        db.prepare("DELETE FROM auth_tokens WHERE user_id = ?").run(target.id);
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      audit("password_reset", target);
      sendJson(response, 200, { ok: true });
      return;
    }

    if (action === "/verify-email") {
      db.prepare("UPDATE users SET email_verified_at = ? WHERE id = ?").run(now(), target.id);
      db.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND purpose = 'email_verification'").run(target.id);
      audit("email_verified", target);
      sendJson(response, 200, { ok: true });
      return;
    }

    if (action === "/sessions/revoke") {
      const result = db.prepare("DELETE FROM sessions WHERE user_id = ?").run(target.id);
      audit("sessions_revoked", target, { count: result.changes });
      sendJson(response, 200, { ok: true, count: result.changes });
      return;
    }

    if (action === "/delete") {
      if (cleanText(body.confirmation, 32) !== "SUPPRIMER") {
        throw new HttpError(400, "Confirme la suppression en écrivant SUPPRIMER.", "confirmation_required");
      }
      if (hasLiveSubscription(target.id)) {
        throw new HttpError(
          409,
          "Résilie d'abord l'abonnement de ce compte, puis supprime-le.",
          "subscription_active",
        );
      }
      // users porte les clés étrangères en cascade : QR codes, scans, sessions et
      // abonnements partent avec le compte, en une transaction.
      db.exec("BEGIN");
      try {
        db.prepare("DELETE FROM users WHERE id = ?").run(target.id);
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      audit("account_deleted", target);
      sendJson(response, 200, { ok: true });
      return;
    }

    if (action === "/subscription/cancel") {
      const subscription = adminSubscriptionRow(target.id);
      if (!subscription) {
        throw new HttpError(404, "Aucun abonnement sur ce compte.", "no_subscription");
      }
      if (!subscription.stripe_subscription_id) {
        throw new HttpError(
          409,
          "Cet abonnement n'a pas d'identifiant Stripe : résilie-le depuis le portail, puis supprime le compte.",
          "no_stripe_subscription",
        );
      }
      // La résiliation passe par Stripe avant d'être écrite en base. Écrire d'abord
      // laisserait un compte sans abonnement ici mais toujours débité là, et le
      // webhook de résiliation ne réparerait rien : il arrive une fois, au moment
      // de l'action, pas à la demande suivante.
      const stripe = await getStripe();
      const atPeriodEnd = body.atPeriodEnd !== false;
      const updated = atPeriodEnd
        ? await stripe.subscriptions.update(subscription.stripe_subscription_id, {
            cancel_at_period_end: true,
          })
        : await stripe.subscriptions.cancel(subscription.stripe_subscription_id);
      const synced = syncSubscriptionFromStripe(updated);
      audit("subscription_canceled", target, {
        atPeriodEnd,
        status: synced?.status || null,
      });
      sendJson(response, 200, { ok: true, status: synced?.status || null });
      return;
    }

    if (action === "/subscription/grace") {
      const hours = Number(body.hours);
      if (!Number.isInteger(hours) || hours < 1 || hours > 720) {
        throw new HttpError(400, "Indique un nombre d'heures entre 1 et 720.", "invalid_hours");
      }
      const subscription = adminSubscriptionRow(target.id);
      if (!subscription) {
        throw new HttpError(404, "Aucun abonnement sur ce compte.", "no_subscription");
      }
      // La grâce ne compte que pour un abonnement résilié ou en pause. Sur un
      // abonnement actif elle ne servirait à rien, et l'écrire quand même
      // donnerait l'illusion d'avoir accordé quelque chose.
      const effective = subscription.status === "canceled" || subscription.status === "paused";
      let graceUntil = subscription.grace_until;
      if (effective) {
        const from = Math.max(now(), subscription.grace_until || 0);
        graceUntil = from + hours * 60 * 60 * 1_000;
        db.prepare("UPDATE subscriptions SET grace_until = ?, updated_at = ? WHERE user_id = ?").run(
          graceUntil,
          now(),
          target.id,
        );
      }
      audit("subscription_grace", target, { hours, effective });
      sendJson(response, 200, {
        ok: true,
        effective,
        graceUntil: isoDate(graceUntil),
        message: effective
          ? `Grâce prolongée jusqu'au ${isoDate(graceUntil)}.`
          : "La grâce n'a pas été prolongée : elle ne s'applique qu'à un abonnement résilié ou en pause.",
      });
      return;
    }

    if (action === "/subscription/plan") {
      const plan = typeof body.plan === "string" ? body.plan : "";
      if (!PLAN_CATALOG[plan]) {
        throw new HttpError(400, "Choisis une offre existante.", "invalid_plan");
      }
      const days = body.days === undefined ? 365 : Number(body.days);
      if (!Number.isInteger(days) || days < 1 || days > 3650) {
        throw new HttpError(400, "Indique une durée en jours entre 1 et 3650.", "invalid_days");
      }
      const subscription = adminSubscriptionRow(target.id);
      // Un abonnement réel reste maître : sans cette refus, l'offre écrite ici
      // serait écrasée par le prochain webhook, et l'écart passerait inaperçu.
      if (subscription?.stripe_subscription_id) {
        throw new HttpError(
          409,
          "Ce compte a un abonnement Stripe actif : résilie-le d'abord, sinon Stripe réécrira l'offre.",
          "stripe_subscription_active",
        );
      }
      const timestamp = now();
      const periodEnd = timestamp + days * 24 * 60 * 60 * 1_000;
      // Aucun identifiant Stripe : la ligne décrit un accès accordé par
      // l'administration, pas un paiement. `cancel_at_period_end` reste à 0, ce
      // qui autorise `renewManualOffer` à prolonger la période d'un an à chaque
      // échéance, sans facturation ni action de nettoyage.
      if (subscription) {
        // La ligne est visée par `id` : un compte peut conserver plusieurs lignes
        // d'abonnement terminées, et les réécrire toutes ressusciterait des
        // abonnements que Stripe a clos.
        db.prepare(`
          UPDATE subscriptions
          SET plan = ?, status = 'active', current_period_end = ?, cancel_at_period_end = 0,
              grace_until = NULL, updated_at = ?
          WHERE id = ?
        `).run(plan, periodEnd, timestamp, subscription.id);
      } else {
        db.prepare(`
          INSERT INTO subscriptions (
            user_id, plan, status, stripe_customer_id, stripe_subscription_id, stripe_price_id,
            current_period_end, cancel_at_period_end, grace_until, created_at, updated_at
          ) VALUES (?, ?, 'active', '', NULL, '', ?, 0, NULL, ?, ?)
        `).run(target.id, plan, periodEnd, timestamp, timestamp);
      }
      audit("subscription_granted", target, {
        factor,
        plan,
        days,
        currentPeriodEnd: isoDate(periodEnd),
        previousPlan: subscription?.plan || null,
        autoRenew: true,
      });
      sendJson(response, 200, {
        ok: true,
        plan,
        currentPeriodEnd: isoDate(periodEnd),
        autoRenew: true,
        message:
          `Accès ${PLAN_CATALOG[plan].label} offert jusqu'au ${isoDate(periodEnd)}, ` +
          `renouvelé automatiquement d'un an, sans facturation.`,
      });
      return;
    }

    throw new HttpError(404, "Intervention inconnue.", "not_found");
  }

  // ── Modération d'un QR code ───────────────────────────────────────────────
  const qrcodeMatch = url.pathname.match(/^\/api\/admin\/qrcodes\/(\d{1,12})\/activity$/);
  if (request.method === "POST" && qrcodeMatch) {
    verifyCsrf(request, session);
    checkRateLimit(`admin-write:${session.userId}`, 120, 60 * 1_000);
    const id = Number(qrcodeMatch[1]);
    const qrcode = db.prepare("SELECT id, user_id, name FROM qrcodes WHERE id = ?").get(id);
    if (!qrcode) throw new HttpError(404, "QR code introuvable.", "not_found");
    const owner = db.prepare("SELECT id, email, is_super_admin FROM users WHERE id = ?").get(qrcode.user_id);
    if (owner?.is_super_admin) {
      throw new HttpError(403, "Ce QR code appartient à un compte super-admin.", "super_admin_protected");
    }
    const body = requireObject(await readJson(request));
    const reason = validateAdminReason(body.reason);
    const factor = await requireAdminTwoFactor(session, body);
    if (typeof body.active !== "boolean") {
      throw new HttpError(400, "Indique si le QR code doit être actif.", "invalid_active");
    }
    db.prepare("UPDATE qrcodes SET is_active = ?, updated_at = ? WHERE id = ?").run(
      body.active ? 1 : 0,
      now(),
      id,
    );
    recordAdminAction(session, owner, body.active ? "qrcode_activated" : "qrcode_deactivated", reason, {
      factor,
      qrcodeId: id,
      qrcodeName: qrcode.name,
    });
    sendJson(response, 200, { ok: true });
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
  if (url.pathname.startsWith("/api/admin/")) {
    // La garde de rôle est dans le handler : elle s'applique donc aussi aux
    // routes inconnies sous ce préfixe, qui rendent 403 avant même le 404. Un
    // compte sans rôle ne peut pas énumérer les routes du back-office.
    await handleAdminApi(request, response, url);
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
