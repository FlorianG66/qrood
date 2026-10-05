// Page « Mon compte ». Les formulaires y sont indépendants les uns des autres :
// chacun n'écrit que sa propre partie du compte, pour qu'une erreur sur le mot de
// passe ne fasse pas perdre un nom déjà enregistré.

(() => {
  const $ = (selector, root = document) => root.querySelector(selector);

  const TOKEN_KEY = "qrood:confirmation-email";

  const state = {
    csrfToken: null,
    user: null,
    entitlement: null,
    subscription: null,
    emailToken: null,
    toastTimer: null,
    twoFactor: null,
    twoFactorMode: null,
    twoFactorSecret: null,
    googleEnabled: false,
    hasPassword: true,
    googleLinked: false,
  };

  const elements = {};

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    cacheElements();
    bindEvents();
    // Le jeton est lu avant la session : un lien peut être ouvert alors que la
    // session a expiré, ou depuis un poste différent de celui qui l'a demandé.
    state.emailToken = readEmailToken();
    try {
      const result = await api("/api/auth/me");
      if (!result.user) {
        window.location.replace("/");
        return;
      }
      state.csrfToken = result.csrfToken;
      state.user = result.user;
      state.entitlement = result.entitlement;
      state.subscription = result.subscription;
      // Ces trois indicateurs décident de ce que la page peut proposer : un compte
      // sans mot de passe n'affiche pas les champs de mot de passe, et une identité
      // déjà reliée n'affiche pas le formulaire de liaison.
      state.googleEnabled = Boolean(result.googleEnabled);
      state.hasPassword = result.hasPassword !== false;
      state.googleLinked = Boolean(result.googleLinked);
      render();
      elements.accountMain.hidden = false;
      elements.accountLoading.remove();
      await Promise.all([confirmPendingEmailChange(), loadTwoFactor()]);
      handleOauthReturn();
    } catch (error) {
      elements.accountLoading.innerHTML = "";
      const message = document.createElement("p");
      message.className = "form-error";
      message.textContent = error.message || "Impossible de charger ton compte.";
      elements.accountLoading.append(message);
    }
  }

  // Le jeton est conservé en double : dans l'URL, le temps du clic, et en
  // sessionStorage le temps du détour par la connexion. Sans cette seconde copie,
  // un lien reçu par e-mail mais ouvert avant d'être connecté mènerait à l'accueil
  // et le changement d'adresse deviendrait impossible à confirmer.
  function readEmailToken() {
    const fromUrl = new URLSearchParams(window.location.search).get("confirmation-email");
    if (fromUrl) {
      try {
        window.sessionStorage.setItem(TOKEN_KEY, fromUrl);
      } catch {
        // Stockage indisponible : l'URL seule suffira pour cette visite.
      }
      return fromUrl;
    }
    try {
      return window.sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  }

  function clearEmailToken() {
    try {
      window.sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      // Rien à nettoyer si le stockage est bloqué.
    }
    window.history.replaceState({}, "", "/compte");
  }

  function cacheElements() {
    elements.accountMain = $("#accountMain");
    elements.accountLoading = $("#accountLoading");
    elements.displayName = $("#displayName");
    elements.currentEmail = $("#currentEmail");
    elements.emailStatus = $("#emailStatus");
    elements.pendingEmailNote = $("#pendingEmailNote");
    elements.newEmail = $("#newEmail");
    elements.emailPasswordGroup = $("#emailPasswordGroup");
    elements.oldPasswordGroup = $("#oldPasswordGroup");
    elements.deletePasswordGroup = $("#deletePasswordGroup");
    elements.googleCard = $("#googleCard");
    elements.googleStatus = $("#googleStatus");
    elements.googleNote = $("#googleNote");
    elements.googleLinkForm = $("#googleLinkForm");
    elements.googleUnlinkForm = $("#googleUnlinkForm");
    elements.googleActions = $("#googleActions");
    elements.googleReauthButton = $("#googleReauthButton");
    elements.planName = $("#planName");
    elements.planStatus = $("#planStatus");
    elements.planRenewal = $("#planRenewal");
    elements.planRenewalLabel = $("#planRenewalLabel");
    elements.planHint = $("#planHint");
    elements.exportButton = $("#exportButton");
    elements.backOfficeLink = $("#backOfficeLink");
    elements.twoFactorStatus = $("#twoFactorStatus");
    elements.twoFactorActions = $("#twoFactorActions");
    elements.twoFactorModal = $("#twoFactorModal");
    elements.twoFactorTitle = $("#twoFactorModalTitle");
    elements.twoFactorIntro = $("#twoFactorIntro");
    elements.twoFactorSetupBody = $("#twoFactorSetupBody");
    elements.twoFactorCodesBody = $("#twoFactorCodesBody");
    elements.twoFactorCodes = $("#twoFactorCodes");
    elements.twoFactorQr = $("#twoFactorQr");
    elements.twoFactorSecret = $("#twoFactorSecret");
    elements.twoFactorForm = $("#twoFactorForm");
    elements.twoFactorPasswordGroup = $("#twoFactorPasswordGroup");
    elements.twoFactorPassword = $("#twoFactorPassword");
    elements.twoFactorCodeGroup = $("#twoFactorCodeGroup");
    elements.twoFactorCode = $("#twoFactorCode");
    elements.twoFactorConfirmCodeGroup = $("#twoFactorConfirmCodeGroup");
    elements.twoFactorConfirmCode = $("#twoFactorConfirmCode");
    elements.twoFactorError = $("#twoFactorError");
    elements.twoFactorSubmit = $("#twoFactorSubmit");
    elements.toast = $("#toast");
    elements.toastMessage = $("#toastMessage");
  }

  function bindEvents() {
    $("#profileForm").addEventListener("submit", onProfileSubmit);
    $("#emailForm").addEventListener("submit", onEmailSubmit);
    $("#passwordForm").addEventListener("submit", onPasswordSubmit);
    $("#exportButton").addEventListener("click", onExport);
    $("#portalButton").addEventListener("click", onPortal);
    $("#deleteForm").addEventListener("submit", onDelete);
    $("#logoutButton").addEventListener("click", onLogout);
    $("#googleLinkForm").addEventListener("submit", onGoogleLink);
    $("#googleUnlinkForm").addEventListener("submit", onGoogleUnlink);
    elements.googleReauthButton.addEventListener("click", onGoogleReauth);
    elements.twoFactorActions.addEventListener("click", onTwoFactorClick);
    elements.twoFactorForm.addEventListener("submit", onTwoFactorSubmit);
    for (const button of document.querySelectorAll("[data-close-modal]")) {
      button.addEventListener("click", () => closeTwoFactorModal());
    }
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const request = { ...options, headers, credentials: "same-origin" };
    if (options.body !== undefined && typeof options.body !== "string") {
      headers.set("Content-Type", "application/json");
      request.body = JSON.stringify(options.body);
    }
    if (options.method && !["GET", "HEAD", "OPTIONS"].includes(options.method.toUpperCase()) && state.csrfToken) {
      headers.set("X-CSRF-Token", state.csrfToken);
    }

    let response;
    try {
      response = await fetch(path, request);
    } catch {
      throw new Error("Le serveur est inaccessible.");
    }
    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json") ? await response.json() : null;
    if (!response.ok) {
      const error = new Error(data?.error?.message || "La requête n'a pas pu être traitée.");
      error.status = response.status;
      error.code = data?.error?.code;
      throw error;
    }
    return data;
  }

  function showToast(message) {
    elements.toastMessage.textContent = message;
    elements.toast.classList.add("visible");
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => elements.toast.classList.remove("visible"), 3000);
  }

  // Un formulaire est désactivé pendant son envoi : sans cela, un double clic
  // sur « Supprimer » ou « Changer le mot de passe » part deux fois, et la
  // seconde requête échoue sur un jeton déjà consommé.
  async function withBusy(form, action) {
    const submit = form.querySelector('button[type="submit"]');
    const label = submit?.textContent;
    if (submit) submit.disabled = true;
    try {
      await action();
    } catch (error) {
      reportError(error);
    } finally {
      if (submit) {
        submit.disabled = false;
        submit.textContent = label;
      }
    }
  }

  // Un compte sans mot de passe n'a qu'une preuve possible, et elle vieillit. Le
  // message doit donc dire quoi faire, plutôt que de répéter un refus : la demande
  // n'a pas échoué, elle a expiré.
  function reportError(error) {
    if (error.code === "reauth_required") {
      revealReauth();
      showToast("Ta session n'est plus récente : prouve ton identité avec Google pour continuer.");
      return;
    }
    showToast(error.message || "L'opération a échoué.");
  }

  function render() {
    elements.displayName.value = state.user.displayName;
    elements.currentEmail.value = state.user.email;
    elements.emailStatus.textContent = state.user.emailVerified
      ? "Adresse confirmée."
      : "Adresse non confirmée : la création de QR codes reste bloquée tant que tu ne l'as pas confirmée.";

    // Le lien n'apparaît que pour le rôle concerné : l'afficher à tous
    // emperors d'arriver sur une page qui refuse l'accès n'aide personne.
    elements.backOfficeLink.hidden = !state.user.isSuperAdmin;

    showPendingEmail(state.user.pendingEmail);
    renderPlan();
    renderGoogle();
    renderPasswordFields();
    renderTwoFactor();
  }

  // ── Connexion Google ───────────────────────────────────────────────────────
  //
  // Google est une porte d'entrée, pas un compte à part : relier ajoute une entrée
  // sans rien remplacer, délier en retire une, et la page suit l'état réel plutôt
  // qu'un drapeau posé en mémoire.

  function renderGoogle() {
    elements.googleCard.hidden = !state.googleEnabled;
    if (!state.googleEnabled) return;

    const enrolled = Boolean(state.twoFactor?.enrolled);
    elements.googleStatus.textContent = state.googleLinked
      ? "Identité reliée : ton compte s'ouvre avec Google, à côté de son mot de passe."
      : "Aucune identité reliée : ton compte ne s'ouvre qu'avec son mot de passe.";

    // Une double authentification occupe déjà le rôle de second facteur. La proposer
    // quand même laisserait croire que Google peut s'y substituer : il ne le peut pas,
    // et le serveur refuserait l'aller-retour.
    if (enrolled) {
      elements.googleNote.hidden = false;
      elements.googleNote.textContent =
        "Ta double authentification demande déjà un code à chaque connexion : la connexion Google y est désactivée, et le serveur la refusera.";
      elements.googleLinkForm.hidden = true;
      elements.googleUnlinkForm.hidden = true;
      elements.googleActions.hidden = true;
      return;
    }

    elements.googleNote.hidden = state.hasPassword;
    elements.googleNote.textContent = state.hasPassword
      ? ""
      : "Ton compte n'a pas de mot de passe : Google tient lieu de preuve pour changer d'adresse, définir un mot de passe ou supprimer le compte. Cette preuve est valable une quinzaine de minutes, après quoi il faut la renouveler.";

    elements.googleLinkForm.hidden = state.googleLinked;
    elements.googleUnlinkForm.hidden = !state.googleLinked || !state.hasPassword;
    elements.googleActions.hidden = Boolean(state.hasPassword) || !state.googleLinked;
  }

  // La case de mot de passe disparaît quand le compte n'en a pas : la laisser visible,
  // vide et facultative, inviterait l'utilisateur à la remplir pour rien — et à croire
  // qu'un mot de passe existe quelque part.
  function renderPasswordFields() {
    for (const group of [elements.emailPasswordGroup, elements.oldPasswordGroup, elements.deletePasswordGroup]) {
      if (group) group.hidden = !state.hasPassword;
    }
  }

  // Le bouton de preuve est déjà sur la page ; c'est le refus d'une action qui le rend
  // visible, quand la fenêtre d'un compte sans mot de passe s'est refermée entre-temps.
  function revealReauth() {
    if (!state.googleEnabled || state.hasPassword || !state.googleLinked || state.twoFactor?.enrolled) return;
    elements.googleActions.hidden = false;
    elements.googleCard.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  // Un aller-retour par le fournisseur ne se poursuit pas depuis une requête
  // JavaScript : le serveur renvoie l'adresse, et c'est la page qui l'ouvre.
  async function startGoogleFlow(path, body = {}) {
    const result = await api(path, { method: "POST", body });
    window.location.assign(result.url);
  }

  function onGoogleLink(event) {
    event.preventDefault();
    withBusy(event.currentTarget, async () => {
      await startGoogleFlow("/api/account/google/link", { currentPassword: $("#googleLinkPassword").value });
    });
  }

  function onGoogleUnlink(event) {
    event.preventDefault();
    withBusy(event.currentTarget, async () => {
      await api("/api/account/google/unlink", {
        method: "POST",
        body: { currentPassword: $("#googleUnlinkPassword").value },
      });
      // Le lien et le mot de passe viennent de disparaître de la page : elle est
      // rechargée pour que rien n'y reste, et pour que le bouton « Déconnexion » ne
      // repose pas sur un état que le serveur ne partage plus.
      window.location.assign("/compte");
    });
  }

  function onGoogleReauth() {
    elements.googleReauthButton.disabled = true;
    startGoogleFlow("/api/account/google/reauth").catch((error) => {
      reportError(error);
      elements.googleReauthButton.disabled = false;
    });
  }

  // Le retour du fournisseur se lit ici : la liaison et la ré-authentification
  // reviennent toutes deux à cette page, avec un code plutôt qu'un message.
  const OAUTH_MESSAGES = {
    liaison_reussie: "Identité Google reliée à ton compte.",
    reauth_reussie: "Identité prouvée : tu peux à nouveau modifier ton compte.",
    refus: "Connexion Google annulée.",
    state_invalide: "Demande expirée. Recommence depuis cette page.",
    code_manquant: "Google n'a pas renvoyé de code d'autorisation. Recommence.",
    session_expiree: "Ta session a changé pendant la connexion : reprends la demande ici.",
    identite_refusee: "Google n'a pas confirmé ton adresse. Un compte Google vérifié est nécessaire.",
    fournisseur_indisponible: "Google ne répond pas. Réessaie dans un instant.",
    deux_facteurs: "Ton compte exige un code d'authentification : connecte-toi avec ton mot de passe.",
    google_non_lie: "Aucune identité Google n'est reliée à ce compte.",
    deja_lie: "Ton compte est déjà relié à une identité Google.",
    identite_deja_liee: "Cette identité Google est déjà reliée à un autre compte.",
    autre_identite: "L'identité Google qui s'ouvre n'est pas celle de ce compte.",
    email_deja_utilise: "Un compte existe déjà avec cette adresse : connecte-toi par mot de passe.",
  };

  function handleOauthReturn() {
    const code = new URLSearchParams(window.location.search).get("oauth");
    if (!code) return;
    window.history.replaceState({}, "", "/compte");
    showToast(OAUTH_MESSAGES[code] || "La connexion Google n'a pas abouti.");
  }

  // L'offre nommée ici est l'offre effective, celle qui décide des quotas, et non
  // celle stockée dans `subscriptions` : le rôle super-admin accorde Ultra sans
  // qu'aucun abonnement existe, et afficher « Découverte » sous des quotas
  // illimités serait un mensonge de la page.
  function renderPlan() {
    const summary = state.subscription;
    const entitlement = state.entitlement;
    const roleGrantsPlan = Boolean(state.user.isSuperAdmin) && entitlement?.plan === "ultra";
    if (!summary && !entitlement) {
      elements.planName.textContent = "—";
      elements.planStatus.textContent = "—";
      elements.planRenewal.textContent = "—";
      elements.planRenewalLabel.textContent = "Renouvellement";
      elements.planHint.textContent = "";
      return;
    }
    elements.planName.textContent = entitlement?.label || planLabelFor(entitlement?.plan);
    elements.planStatus.textContent = roleGrantsPlan
      ? "Avantage de rôle, aucun abonnement"
      : summary?.manual
        ? "Offert, aucun abonnement"
        : summary.status || "Aucun abonnement actif";
    elements.planRenewal.textContent = summary?.currentPeriodEnd
      ? new Date(summary.currentPeriodEnd).toLocaleDateString("fr-FR")
      : "—";
    elements.planRenewalLabel.textContent = summary?.manual ? "Jusqu'au" : "Renouvellement";
    elements.planHint.textContent = summary?.manual
      ? summary.autoRenew
        ? "Cet accès a été accordé par l'administration : il est renouvelé d'un an automatiquement, et rien n'est facturé."
        : "Cet accès a été accordé par l'administration : il s'arrête à cette date, et rien n'est facturé."
      : summary?.cancelAtPeriodEnd
      ? "Ton abonnement se termine à cette date et ne sera pas renouvelé."
      : roleGrantsPlan
        ? "Ton rôle super-admin accorde l'offre Ultra : elle s'applique sans abonnement et sans facturation."
        : "";
    // Sans compte de facturation, le portail n'existerait pas : le bouton ne
    // mènerait qu'à une erreur.
    $("#portalButton").hidden = !summary?.hasBillingAccount;
  }

  function planLabelFor(plan) {
    return String(plan || "decouverte").replace(/^./, (letter) => letter.toUpperCase());
  }

  function showPendingEmail(email) {
    elements.pendingEmailNote.hidden = !email;
    if (email) {
      elements.pendingEmailNote.textContent =
        `Un changement vers ${email} attend encore ta confirmation. Ouvre le lien reçu à cette adresse pour l'activer.`;
    }
  }

  // Le lien de confirmation arrive par e-mail et peut être ouvert après coup,
  // depuis un autre poste, ou avant d'être connecté. Le jeton n'est retiré de
  // l'URL qu'une fois accepté : le faire avant l'échange le perdrait
  // définitivement si le réseau coupait au mauvais moment, et il faut bien le
  // laisser en place pour que le second essai serve à quelque chose.
  async function confirmPendingEmailChange() {
    const token = state.emailToken;
    if (!token) return;
    try {
      const result = await api("/api/account/email/confirm", { method: "POST", body: { token } });
      clearEmailToken();
      state.emailToken = null;
      state.user = result.user;
      render();
      showToast("Ton adresse e-mail est mise à jour.");
    } catch (error) {
      // Un lien périmé ou déjà utilisé ne sera jamais valable : on l'écarte pour
      // qu'il ne redemande rien à chaque visite. Une panne réseau, elle, se
      // traduit par l'absence de code : le jeton reste et le nouvel essai passe.
      if (error.status === 400) {
        clearEmailToken();
        state.emailToken = null;
      }
      showToast(error.message || "Ce lien de confirmation n'est plus valide.");
    }
  }

  async function onProfileSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    await withBusy(form, async () => {
      const result = await api("/api/account/profile", {
        method: "PATCH",
        body: { displayName: $("#displayName").value },
      });
      state.user = result.user;
      showToast("Nom enregistré.");
    });
  }

  async function onEmailSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    await withBusy(form, async () => {
      const result = await api("/api/account/email", {
        method: "POST",
        body: { email: $("#newEmail").value, currentPassword: $("#emailPassword").value },
      });
      showPendingEmail(result.pendingEmail);
      $("#emailPassword").value = "";
      $("#newEmail").value = "";
      showToast("Lien de confirmation envoyé.");
    });
  }

  async function onPasswordSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const password = $("#newPassword").value;
    if (password !== $("#confirmPassword").value) {
      showToast("Les deux mots de passe ne correspondent pas.");
      return;
    }
    await withBusy(form, async () => {
      await api("/api/account/password", {
        method: "POST",
        body: { currentPassword: $("#oldPassword").value, newPassword: password },
      });
      form.reset();
      // Un compte qui vient de recevoir son mot de passe n'est plus un compte sans
      // mot de passe : les champs réapparaissent, et Google cesse d tenir lieu de
      // preuve pour la suite.
      state.hasPassword = true;
      render();
      showToast("Mot de passe mis à jour.");
    });
  }

  async function onExport() {
    const button = elements.exportButton;
    button.disabled = true;
    try {
      const payload = await api("/api/account/export", { method: "POST" });
      // Le fichier est construit ici plutôt que laissé au serveur : la réponse
      // contient déjà le JSON, et un lien temporaire serait lisible par un tiers.
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `qrood-donnees-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
      showToast("Export téléchargé.");
    } catch (error) {
      showToast(error.message || "L'export a échoué.");
    } finally {
      button.disabled = false;
    }
  }

  async function onPortal() {
    try {
      const result = await api("/api/billing/portal", { method: "POST" });
      window.location.assign(result.url);
    } catch (error) {
      showToast(error.message || "Impossible d'ouvrir l'espace de facturation.");
    }
  }

  async function onDelete(event) {
    event.preventDefault();
    const form = event.currentTarget;
    await withBusy(form, async () => {
      await api("/api/account/delete", {
        method: "POST",
        body: {
          currentPassword: $("#deletePassword").value,
          confirmation: $("#deleteConfirmation").value,
        },
      });
      window.location.assign("/");
    });
  }

  // ── Double authentification ────────────────────────────────────────────────
  //
  // La protection se règle depuis le compte lui-même, et pas depuis le
  // back-office : c'est la seule porte qui reste ouverte quand aucun Super-admin
  // n'a accès au serveur. Chaque écriture demande le mot de passe puis le code,
  // parce que désactiver le second facteur sur une session volée laisserait le
  // compte sans rien d'autre que le mot de passe.

  async function loadTwoFactor() {
    try {
      state.twoFactor = await api("/api/auth/2fa");
      renderTwoFactor();
    } catch (error) {
      elements.twoFactorStatus.textContent = error.message || "État indisponible.";
    }
  }

  function renderTwoFactor() {
    const status = state.twoFactor;
    if (!status) return;
    elements.twoFactorActions.replaceChildren();
    // Un compte sans mot de passe ne peut pas activer la double authentification : elle
    // fermerait la connexion Google, qui est sa seule porte, et le serveur la refuse.
    // L'annoncer ici évite un bouton qui mènerait à un cul-de-sac.
    const blocked = !status.enrolled && !state.hasPassword;
    elements.twoFactorStatus.textContent = status.enrolled
      ? `Active. Un code de 6 chiffres sera demandé à chaque connexion. ${status.recoveryCodesRemaining} code(s) de récupération restant(s).`
      : blocked
        ? "Inactive, et indisponible : ton compte n'a pas de mot de passe. Google est ta seule porte d'entrée, et la double authentification la fermerait sans te laisser d'autre moyen de l'ouvrir."
        : "Inactive : ton mot de passe est aujourd'hui le seul facteur de ton compte.";

    const add = (id, label, danger = false) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `button ${danger ? "button-danger" : "button-light"} button-small`;
      button.dataset.twoFactor = id;
      button.textContent = label;
      elements.twoFactorActions.append(button);
    };
    if (status.enrolled) {
      add("recovery-codes", "Nouveaux codes de récupération");
      add("disable", "Désactiver", true);
    } else if (!blocked) {
      add("setup", "Activer");
    }
    // Activer ou désactiver le second facteur change ce que vaut une identité Google :
    // la page du compte doit le refléter sans attendre un rechargement.
    renderGoogle();
  }

  function onTwoFactorClick(event) {
    const button = event.target.closest("button[data-two-factor]");
    if (!button) return;
    openTwoFactorDialog(button.dataset.twoFactor);
  }

  function openTwoFactorDialog(mode) {
    state.twoFactorMode = mode;
    state.twoFactorSecret = null;
    elements.twoFactorError.hidden = true;
    elements.twoFactorSetupBody.hidden = false;
    elements.twoFactorCodesBody.hidden = true;
    elements.twoFactorQr.hidden = true;
    elements.twoFactorQr.replaceChildren();
    elements.twoFactorSecret.hidden = true;
    elements.twoFactorSecret.textContent = "";
    elements.twoFactorForm.reset();
    elements.twoFactorPassword.required = true;
    elements.twoFactorPasswordGroup.hidden = false;
    elements.twoFactorCodeGroup.hidden = true;
    elements.twoFactorCode.required = false;
    // La confirmation seule n'a pas son propre champ : elle réutilise celui du QR.
    elements.twoFactorConfirmCodeGroup.hidden = mode === "setup";
    elements.twoFactorConfirmCode.required = mode !== "setup";

    // Le QR n'a de sens que pour une première activation : en régénérant des
    // codes ou en désactivant, il n'y a aucun secret à présenter.
    if (mode === "setup") {
      elements.twoFactorTitle.textContent = "Activer la double authentification";
      elements.twoFactorIntro.textContent =
        "Un code de 6 chiffres demandé à chaque connexion, en plus de ton mot de passe.";
      elements.twoFactorSubmit.textContent = "Afficher le QR code";
    } else if (mode === "recovery-codes") {
      elements.twoFactorTitle.textContent = "Nouveaux codes de récupération";
      elements.twoFactorIntro.textContent =
        "Les codes précédents cessent d'être acceptés. Les nouveaux ne s'affichent qu'une fois.";
      elements.twoFactorSubmit.textContent = "Générer les codes";
    } else {
      elements.twoFactorTitle.textContent = "Désactiver la double authentification";
      elements.twoFactorIntro.textContent =
        "Tes connexions ne demanderont plus qu'un mot de passe. Tu peux la réactiver à tout moment.";
      elements.twoFactorSubmit.textContent = "Désactiver";
    }
    elements.twoFactorModal.hidden = false;
    elements.twoFactorPassword.focus();
  }

  function closeTwoFactorModal() {
    elements.twoFactorModal.hidden = true;
    // Les codes de récupération disparaissent avec la modale : ils ne sont
    // jamais stockés en clair, donc les laisser à l'écran jusqu'au rechargement
    // les exposerait à quiconque ouvre la page ensuite.
    state.twoFactorSecret = null;
    state.twoFactorMode = null;
    elements.twoFactorForm.reset();
  }

  async function onTwoFactorSubmit(event) {
    event.preventDefault();
    const mode = state.twoFactorMode;
    const password = elements.twoFactorPassword.value;
    elements.twoFactorError.hidden = true;
    elements.twoFactorSubmit.disabled = true;
    try {
      if (mode === "setup" && !state.twoFactorSecret) {
        const result = await api("/api/auth/2fa/setup", {
          method: "POST",
          body: { currentPassword: password },
        });
        state.twoFactorSecret = result.secret;
        renderTwoFactorQr(result);
        elements.twoFactorCodeGroup.hidden = false;
        elements.twoFactorCode.required = true;
        elements.twoFactorPasswordGroup.hidden = true;
        elements.twoFactorPassword.required = false;
        elements.twoFactorSubmit.textContent = "Activer";
        elements.twoFactorCode.focus();
        return;
      }
      if (mode === "setup") {
        const result = await api("/api/auth/2fa/confirm", {
          method: "POST",
          body: { code: elements.twoFactorCode.value.trim() },
        });
        await loadTwoFactor();
        showRecoveryCodes(result.recoveryCodes);
        return;
      }
      if (mode === "recovery-codes") {
        const result = await api("/api/auth/2fa/recovery-codes", {
          method: "POST",
          body: { currentPassword: password, twoFactorCode: elements.twoFactorConfirmCode.value.trim() },
        });
        await loadTwoFactor();
        showRecoveryCodes(result.recoveryCodes);
        return;
      }
      await api("/api/auth/2fa/disable", {
        method: "POST",
        body: { currentPassword: password, twoFactorCode: elements.twoFactorConfirmCode.value.trim() },
      });
      closeTwoFactorModal();
      await loadTwoFactor();
      showToast("Double authentification désactivée.");
    } catch (error) {
      elements.twoFactorError.textContent = error.message || "L'opération a échoué.";
      elements.twoFactorError.hidden = false;
    } finally {
      elements.twoFactorSubmit.disabled = false;
    }
  }

  function showRecoveryCodes(codes) {
    elements.twoFactorCodes.replaceChildren();
    for (const code of codes) {
      const item = document.createElement("li");
      item.className = "recovery-item";
      item.textContent = code;
      elements.twoFactorCodes.append(item);
    }
    elements.twoFactorSetupBody.hidden = true;
    elements.twoFactorCodesBody.hidden = false;
  }

  function renderTwoFactorQr({ uri, secret }) {
    elements.twoFactorSecret.textContent = `À saisir à la main si le scan échoue : ${secret}`;
    elements.twoFactorSecret.hidden = false;
    const host = elements.twoFactorQr;
    host.hidden = false;
    host.replaceChildren();
    // Le secret reste lisible dans la page si la bibliothèque de QR n'a pas
    // chargé : sans cela, l'activation serait bloquée sans issue.
    if (typeof window.qrcode !== "function") {
      elements.twoFactorQr.hidden = true;
      return;
    }
    const qr = window.qrcode(0, "M");
    qr.addData(uri);
    qr.make();
    const modules = qr.getModuleCount();
    const margin = 4;
    const scale = 8;
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = (modules + margin * 2) * scale;
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", "QR code de configuration de l'authentification");
    const context = canvas.getContext("2d");
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = "#111111";
    for (let row = 0; row < modules; row += 1) {
      for (let column = 0; column < modules; column += 1) {
        if (!qr.isDark(row, column)) continue;
        context.fillRect((column + margin) * scale, (row + margin) * scale, scale, scale);
      }
    }
    host.append(canvas);
  }

  async function onLogout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch {
      // La session peut déjà être close : le but est d'en sortir, pas de
      // rester sur une page devenue inaccessible.
    }
    window.location.assign("/");
  }
})();
