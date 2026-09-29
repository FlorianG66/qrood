// Construction des e-mails et transports d'envoi, sans dépendance externe.
//
// Les transports sont injectés (écriture disque ou `fetch`) : le module se
// teste donc sans serveur, sans SMTP et sans réseau. Il ne journalise rien et
// ne connaît pas la base : le serveur garde la main sur ce qui est écrit dans
// le journal, puisque le lien contenu dans un message est une autorisation à
// usage unique.

import { randomBytes } from "node:crypto";
import path from "node:path";

/** Transports acceptés. `outbox` est le développement, `api` la production. */
export const MAIL_TRANSPORTS = new Set(["outbox", "api"]);

/** Longueur maximale d'un destinataire, pour ne jamais laisser passer une injection d'en-tête. */
const MAX_ADDRESS_LENGTH = 254;

/**
 * Un destinataire est validé strictement : ni séparateur, ni espace, ni
 * retour à la ligne. Un `From` truqué dans un message est le premier levier
 * d'un envoi de spam à partir du nom de QROOD.
 */
export function isValidMailAddress(value) {
  const address = typeof value === "string" ? value.trim() : "";
  if (!address || address.length > MAX_ADDRESS_LENGTH) return false;
  return /^[^\s"',:;<>@\\]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$/.test(address);
}

function formatHours(hours) {
  if (hours % 24 === 0) {
    const days = hours / 24;
    return days === 1 ? "24 heures" : `${days} jours`;
  }
  return `${hours} heures`;
}

function formatMinutes(minutes) {
  if (minutes < 60) return `${minutes} minutes`;
  const hours = Math.round((minutes / 60) * 10) / 10;
  return `${hours} heure${hours > 1 ? "s" : ""}`;
}

/**
 * Message de confirmation d'adresse.
 *
 * Le lien est construit par l'appelant : ce module ne connaît ni l'origine
 * publique ni le format de l'URL, seulement le texte qui l'accompagne.
 */
export function buildVerificationMessage({ to, name, url, validHours = 24 }) {
  const greeting = name ? `Bonjour ${name},` : "Bonjour,";
  return {
    purpose: "email_verification",
    to,
    subject: "Confirmez votre adresse e-mail — QROOD",
    text: [
      greeting,
      "",
      "Confirmez votre adresse e-mail pour activer la création et la publication de vos QR codes sur QROOD.",
      "",
      `Ouvrir cette page : ${url}`,
      "",
      `Ce lien est valable ${formatHours(validHours)} et ne fonctionne qu'une fois. S'il expire, demande-en un nouveau depuis ton espace QROOD.`,
      "",
      "Si tu n'es pas à l'origine de cette inscription, ignore ce message : aucun compte n'est créé sans cette confirmation.",
      "",
      "— QROOD",
    ].join("\n"),
  };
}

/**
 * Message de réinitialisation.
 *
 * Le lien n'est envoyé qu'à l'adresse du compte : il n'y a donc rien à
 * divulger sur l'existence d'un compte, et le texte reste neutre sur ce
 * point pour ne rien confirmer à un tiers.
 */
export function buildResetMessage({ to, name, url, validMinutes = 60 }) {
  const greeting = name ? `Bonjour ${name},` : "Bonjour,";
  return {
    purpose: "password_reset",
    to,
    subject: "Choisissez votre nouveau mot de passe — QROOD",
    text: [
      greeting,
      "",
      "Un nouveau mot de passe a été demandé pour ce compte QROOD.",
      "",
      `Choisir un nouveau mot de passe : ${url}`,
      "",
      `Ce lien est valable ${formatMinutes(validMinutes)} et ne fonctionne qu'une fois. S'il est expiré, d'autres demandes restent possibles.`,
      "",
      "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message : votre mot de passe actuel reste valable et vos sessions ouvertes ne sont pas modifiées.",
      "",
      "— QROOD",
    ].join("\n"),
  };
}

/**
 * Transport de développement : un fichier JSON par message.
 *
 * Le fichier contient un lien à usage unique, donc il est écrit en `0o600` et
 * son nom ne porte ni l'adresse du destinataire ni le jeton. Le dossier doit
 * rester hors du dépôt : il est créé sous `data/`, déjà ignoré par git.
 */
export function createOutboxTransport({ directory, writeFile, mkdir, now = Date.now, randomSuffix }) {
  return {
    mode: "outbox",
    async send(message) {
      mkdir(directory, { recursive: true });
      const stamp = new Date(now()).toISOString().replace(/[:.]/g, "-");
      const suffix = randomSuffix ? randomSuffix() : randomBytes(6).toString("hex");
      const file = path.join(directory, `${stamp}-${suffix}.json`);
      const body = `${JSON.stringify({ ...message, writtenAt: new Date(now()).toISOString() }, null, 2)}\n`;
      await writeFile(file, body, { encoding: "utf8", mode: 0o600 });
      return { file };
    },
  };
}

/**
 * Transport de production : POST JSON vers une API d'envoi.
 *
 * Le corps est figé (`from`, `to`, `subject`, `text`) et l'URL doit être en
 * HTTPS : un lien de réinitialisation ne doit pas pouvoir être intercepté en
 * clair sur le trajet. La clé ne sort jamais du serveur.
 */
export function createApiTransport({ url, apiKey, from, fetch, timeoutMs = 10_000 }) {
  return {
    mode: "api",
    async send(message) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({ from, to: message.to, subject: message.subject, text: message.text }),
          signal: controller.signal,
        });
        if (!response.ok) {
          // Le corps de la réponse peut répéter la clé : il n'est pas recopié
          // dans l'erreur, le serveur n'a ainsi rien à masquer.
          throw new Error(`L'API d'envoi a répondu ${response.status}.`);
        }
        return { status: response.status };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

/**
 * Vérifie qu'une configuration de transport est utilisable, et renvoie le
 * message d'erreur sinon. Les deux familles de variables sont acceptées comme
 * pour Stripe : `QROOD_MAIL_*` d'abord, `MAIL_*` ensuite.
 */
export function validateMailConfiguration({ transport, apiUrl, apiKey, production }) {
  if (!MAIL_TRANSPORTS.has(transport)) {
    return `QROOD_MAIL_TRANSPORT doit valoir ${[...MAIL_TRANSPORTS].join(" ou ")}.`;
  }
  if (transport === "api" && (!apiUrl || !apiKey)) {
    return "Le transport « api » exige QROOD_MAIL_API_URL et QROOD_MAIL_API_KEY.";
  }
  if (transport === "api" && apiUrl && !apiUrl.startsWith("https://")) {
    return "QROOD_MAIL_API_URL doit être une URL HTTPS : un e-mail de réinitialisation ne circule pas en clair.";
  }
  if (production && transport !== "api") {
    return "En production, QROOD_MAIL_TRANSPORT doit valoir « api » : l'envoi dans un dossier local n'existe pas pour les utilisateurs.";
  }
  return null;
}
