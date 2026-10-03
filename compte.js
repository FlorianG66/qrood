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
      render();
      elements.accountMain.hidden = false;
      elements.accountLoading.remove();
      await confirmPendingEmailChange();
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
    elements.planName = $("#planName");
    elements.planStatus = $("#planStatus");
    elements.planRenewal = $("#planRenewal");
    elements.planRenewalLabel = $("#planRenewalLabel");
    elements.planHint = $("#planHint");
    elements.exportButton = $("#exportButton");
    elements.backOfficeLink = $("#backOfficeLink");
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
      showToast(error.message || "L'opération a échoué.");
    } finally {
      if (submit) {
        submit.disabled = false;
        submit.textContent = label;
      }
    }
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
