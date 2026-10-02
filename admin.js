// Back-office du super-admin.
//
// Deux règles structurent ce fichier. La première : la protection d'un compte
// super-admin est visible dans l'interface, pas seulement refusée par le serveur.
// Un bouton désactivé explique la règle ; une erreur 403 découverte après coup
// laisse croire à un bug. La seconde : aucune écriture n'est déclenchée sans
// motif, parce que le journal est la seule trace qui survive au rôle.
(() => {
  const PAGE_SIZE = 20;
  const state = {
    csrfToken: null,
    offset: 0,
    total: 0,
    search: "",
    users: [],
    selected: null,
    dialogAction: null,
    toastTimer: null,
    twoFactor: null,
    twoFactorMode: null,
    twoFactorSecret: null,
  };
  const elements = {};

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    cacheElements();
    bindEvents();
    try {
      const me = await api("/api/auth/me");
      if (!me.user) {
        window.location.replace("/");
        return;
      }
      state.csrfToken = me.csrfToken;
      // Le rôle vient de la session que le serveur vient de lire en base : le
      // retirer de `QROOD_ADMIN_EMAILS` ne le concernait pas, mais une révocation
      // en base est prise en compte ici sans rechargement de page.
      if (!me.user.isSuperAdmin) {
        elements.deniedNote.textContent = me.user.emailVerified
          ? "Ce compte n'a pas le rôle super-admin. Sa promotion se fait par une commande SQL explicite, jamais depuis l'application."
          : "Confirme d'abord l'adresse de ce compte, puis demande la promotion.";
        elements.deniedMain.hidden = false;
        elements.adminLoading.hidden = true;
        return;
      }
      elements.adminMain.hidden = false;
      elements.adminLoading.hidden = true;
      // L'état de la double authentification décide du libellé du champ de
      // sécurité des interventions : le charger avant le reste évite d'afficher
      // « mot de passe » à quelqu'un qui n'en a plus besoin.
      await loadTwoFactor();
      await Promise.all([loadUsers(), loadAudit()]);
    } catch (error) {
      elements.deniedNote.textContent = error.message || "Le back-office est indisponible.";
      elements.deniedMain.hidden = false;
      elements.adminLoading.hidden = true;
    }
  }

  function cacheElements() {
    for (const id of [
      "adminLoading", "deniedMain", "deniedNote", "adminMain", "searchInput", "usersCount",
      "userList", "usersPrev", "usersNext", "detailCard", "detailTitle", "detailProtected",
      "detailFacts", "qrcodeList", "detailActions", "auditList", "actionModal", "actionTitle",
      "actionDescription", "actionForm", "actionFields", "actionError", "actionConfirm",
      "actionFactorLabel", "actionFactorHint", "actionFactor",
      "twoFactorStatus", "twoFactorActions", "twoFactorModal", "twoFactorTitle",
      "twoFactorSetupBody", "twoFactorCodesBody", "twoFactorCodes", "twoFactorQr",
      "twoFactorSecret", "twoFactorForm", "twoFactorPassword", "twoFactorReason",
      "twoFactorCodeGroup", "twoFactorCode", "twoFactorConfirmCodeGroup", "twoFactorConfirmCode",
      "twoFactorPasswordGroup", "twoFactorReasonGroup", "twoFactorIntro",
      "twoFactorError", "twoFactorSubmit",
      "toast", "toastMessage", "logoutButton",
    ]) {
      elements[id] = document.getElementById(id);
    }
  }

  function bindEvents() {
    let searchTimer = null;
    elements.searchInput.addEventListener("input", (event) => {
      window.clearTimeout(searchTimer);
      const value = event.target.value;
      // La recherche frappe la base à chaque frappe : un court délai évite
      // d'envoyer une requête par lettre, sans faire attendre la saisie.
      searchTimer = window.setTimeout(() => {
        state.search = value.trim();
        state.offset = 0;
        loadUsers();
      }, 250);
    });
    elements.usersPrev.addEventListener("click", () => {
      state.offset = Math.max(0, state.offset - PAGE_SIZE);
      loadUsers();
    });
    elements.usersNext.addEventListener("click", () => {
      state.offset += PAGE_SIZE;
      loadUsers();
    });
    elements.userList.addEventListener("click", (event) => {
      const row = event.target.closest("button[data-user-id]");
      if (row) selectUser(Number(row.dataset.userId));
    });
    elements.detailActions.addEventListener("click", onActionClick);
    elements.qrcodeList.addEventListener("click", onQrcodeClick);
    elements.actionForm.addEventListener("submit", onDialogSubmit);
    elements.twoFactorActions.addEventListener("click", onTwoFactorClick);
    elements.twoFactorForm.addEventListener("submit", onTwoFactorSubmit);
    for (const button of document.querySelectorAll("[data-close-modal]")) {
      button.addEventListener("click", () => elements[button.dataset.closeModal].hidden = true);
    }
    elements.logoutButton.addEventListener("click", onLogout);
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

  async function onLogout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch {
      // La session peut déjà être close : le but est d'en sortir.
    }
    window.location.assign("/");
  }

  async function loadUsers() {
    try {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(state.offset) });
      if (state.search) params.set("search", state.search);
      const result = await api(`/api/admin/users?${params}`);
      state.users = result.users;
      state.total = result.total;
      renderUsers();
    } catch (error) {
      showToast(error.message || "La liste des comptes est indisponible.");
    }
  }

  function renderUsers() {
    elements.userList.replaceChildren();
    const from = state.total === 0 ? 0 : state.offset + 1;
    const to = Math.min(state.offset + PAGE_SIZE, state.total);
    elements.usersCount.textContent = `${from}–${to} sur ${state.total} compte${state.total === 1 ? "" : "s"}`;
    elements.usersPrev.disabled = state.offset <= 0;
    elements.usersNext.disabled = state.offset + PAGE_SIZE >= state.total;

    for (const user of state.users) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "admin-row";
      row.dataset.userId = String(user.id);
      if (state.selected?.id === user.id) row.classList.add("admin-row-selected");
      row.append(
        cell(user.isSuperAdmin ? `${user.displayName} · super-admin` : user.displayName),
        cell(user.email),
        cell(`${user.qrcodeCount} QR${user.activeCount ? ` · ${user.activeCount} actif(s)` : ""}`),
        cell(user.status ? `${user.plan} · ${user.status}` : user.plan),
      );
      elements.userList.append(row);
    }
    if (state.users.length === 0) {
      const empty = document.createElement("p");
      empty.className = "field-hint";
      empty.textContent = "Aucun compte ne correspond à cette recherche.";
      elements.userList.append(empty);
    }
  }

  function cell(text) {
    const span = document.createElement("span");
    span.className = "admin-cell";
    span.textContent = text;
    return span;
  }

  const PLAN_LABELS = { decouverte: "Découverte", pro: "Pro", ultra: "Ultra" };

  function planLabel(key) {
    return PLAN_LABELS[key] || key;
  }

  // Une ligne sans identifiant Stripe n'est pas un abonnement payé : la nommer
  // comme tel éviterait de chercher une résiliation qui n'existe pas.
  function subscriptionLabel(subscription) {
    if (!subscription?.status) return "aucun";
    if (subscription.manual) return `offert (${planLabel(subscription.plan)}) · ${subscription.status}`;
    return `${subscription.status}${subscription.cancelAtPeriodEnd ? " · fin programmée" : ""}`;
  }

  async function selectUser(userId) {
    state.selected = { id: userId };
    renderUsers();
    try {
      const detail = await api(`/api/admin/users/${userId}`);
      state.detail = detail;
      elements.detailCard.hidden = false;
      renderDetail(detail);
      elements.detailCard.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      showToast(error.message || "Cette fiche est indisponible.");
    }
  }

  function renderDetail(detail) {
    const { user, subscription, entitlement } = detail;
    elements.detailTitle.textContent = `${user.displayName} — ${user.email}`;
    // La protection est annoncée avant les boutons, et les boutons sont retirés :
    // une action impossible ne doit pas rester affichée comme disponible.
    const protectedAccount = Boolean(user.isSuperAdmin);
    elements.detailProtected.hidden = !protectedAccount;
    elements.detailFacts.replaceChildren(
      fact("Adresse", user.emailVerified ? "confirmée" : "non confirmée"),
      fact("Inscrit le", formatDate(user.createdAt)),
      fact("Rôle", user.isSuperAdmin ? "super-admin (Ultra de droit)" : "utilisateur"),
      fact("Offre effective", `${entitlement.plan} (${entitlement.used}/${entitlement.maxQrcodes ?? "∞"} QR, ${entitlement.usedActive}/${entitlement.maxActive ?? "∞"} actifs)`),
      fact("Abonnement", subscriptionLabel(subscription)),
      fact("Échéance", formatDate(subscription?.currentPeriodEnd)),
      fact("Grâce jusqu'au", formatDate(subscription?.graceUntil)),
      fact("Sessions ouvertes", String(detail.sessionCount)),
    );

    elements.qrcodeList.replaceChildren();
    for (const qrcode of detail.qrcodes) {
      const row = document.createElement("div");
      row.className = "admin-row admin-row-static";
      row.append(
        cell(`#${qrcode.id} ${qrcode.name}`),
        cell(qrcode.mode === "contact" ? "carte de contact" : qrcode.destination || "—"),
        cell(`${qrcode.scan_count} scan(s)`),
        cell(qrcode.is_active ? "actif" : "désactivé"),
      );
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button button-light button-small";
      button.dataset.action = "qrcode-activity";
      button.dataset.qrcodeId = String(qrcode.id);
      button.dataset.active = String(!qrcode.is_active);
      button.textContent = qrcode.is_active ? "Désactiver" : "Réactiver";
      // Le QR code d'un super-admin est couvert par la même protection que son compte.
      button.hidden = protectedAccount;
      row.append(button);
      elements.qrcodeList.append(row);
    }
    if (detail.qrcodes.length === 0) {
      const empty = document.createElement("p");
      empty.className = "field-hint";
      empty.textContent = "Ce compte n'a aucun QR code.";
      elements.qrcodeList.append(empty);
    }

    elements.detailActions.replaceChildren();
    if (protectedAccount) return;
    for (const action of ACTIONS) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `button button-small ${action.danger ? "button-danger" : "button-dark"}`;
      button.dataset.action = action.id;
      button.textContent = action.label;
      elements.detailActions.append(button);
    }
  }

  function fact(term, value) {
    const wrapper = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    wrapper.append(dt, dd);
    return wrapper;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("fr-FR");
  }

  // Chaque entrée décrit aussi les champs que la boîte de dialogue doit demander.
  // La raison n'en fait pas partie : elle est toujours demandée, pour toutes.
  const ACTIONS = [
    {
      id: "password",
      label: "Réinitialiser le mot de passe",
      title: "Réinitialiser le mot de passe",
      description: "Toutes les sessions du compte sont fermées et l'adresse doit être reconfirmée.",
      fields: [{ name: "newPassword", label: "Nouveau mot de passe", type: "password", required: true, autocomplete: "new-password" }],
    },
    {
      id: "verify-email",
      label: "Confirmer l'adresse",
      title: "Confirmer l'adresse",
      description: "Utile quand la boîte de confirmation n'est plus accessible. L'opérateur engage sa responsabilité sur la preuve de cette adresse.",
      fields: [],
    },
    {
      id: "sessions/revoke",
      label: "Fermer toutes les sessions",
      title: "Fermer les sessions",
      description: "Déconnecte le compte partout, y compris les navigateurs qui n'ont pas encore expiré.",
      fields: [],
    },
    {
      id: "subscription/plan",
      label: "Offrir une offre",
      title: "Offrir une offre",
      description: "Écrit l'offre en base, sans passer par Stripe et sans facturation. Un abonnement Stripe actif doit être résilié d'abord, sinon Stripe réécrirait l'offre.",
      fields: [
        { name: "plan", label: "Offre", type: "select", options: ["decouverte", "pro", "ultra"], defaultValue: "pro", required: true },
        { name: "days", label: "Durée en jours", type: "number", value: "365", required: true },
      ],
    },
    {
      id: "subscription/cancel",
      label: "Résilier l'abonnement",
      title: "Résilier l'abonnement",
      description: "L'opération est exécutée chez Stripe, puis répercutée en base.",
      fields: [{ name: "atPeriodEnd", label: "Résilier à la fin de la période en cours", type: "checkbox", defaultChecked: true }],
    },
    {
      id: "subscription/grace",
      label: "Prolonger la grâce",
      title: "Prolonger la grâce",
      description: "La grâce ne s'applique qu'à un abonnement résilié ou en pause ; sur un abonnement actif elle n'a aucun effet.",
      fields: [{ name: "hours", label: "Nombre d'heures à ajouter", type: "number", value: "48", required: true }],
    },
    {
      id: "delete",
      label: "Supprimer le compte",
      title: "Supprimer le compte",
      danger: true,
      description: "QR codes, statistiques, sessions et abonnements partent avec le compte. Un abonnement encore vivant doit être résilié d'abord.",
      fields: [{ name: "confirmation", label: "Écris SUPPRIMER pour confirmer", type: "text", required: true, autocomplete: "off" }],
    },
  ];

  function onActionClick(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const action = ACTIONS.find((entry) => entry.id === button.dataset.action);
    if (action) openDialog(action);
  }

  function onQrcodeClick(event) {
    const button = event.target.closest("button[data-action='qrcode-activity']");
    if (!button) return;
    const active = button.dataset.active === "true";
    openDialog({
      id: "qrcode-activity",
      title: active ? "Réactiver le QR code" : "Désactiver le QR code",
      description: active
        ? "Le QR code publiera de nouveau son lien et ses statistiques."
        : "Le QR code renvoie une page d'explication : le lien imprimé cesse de rediriger.",
      danger: !active,
      fields: [],
      qrcodeId: Number(button.dataset.qrcodeId),
      active,
      buttonLabel: active ? "Réactiver" : "Désactiver",
    });
  }

  function openDialog(action) {
    // L'action courante est conservée en mémoire plutôt que retrouvée dans le
    // catalogue : la désactivation d'un QR code n'y figure pas, et une recherche
    // par identifiant la laisserait indéfinie.
    state.dialogAction = action;
    elements.actionTitle.textContent = action.title;
    elements.actionDescription.textContent = action.description;
    elements.actionError.hidden = true;
    elements.actionConfirm.className = `button ${action.danger ? "button-danger" : "button-dark"}`;
    elements.actionConfirm.textContent = action.buttonLabel || "Confirmer";
    elements.actionFields.replaceChildren();
    for (const field of action.fields || []) {
      elements.actionFields.append(buildField(field));
    }
    syncFactorField();
    elements.actionModal.hidden = false;
  }

  // Le même champ sert au mot de passe de repli et au code de l'application.
  // Le libellé suit l'état réel plutôt que ce que la page suppose : après
  // activation, demander un mot de passe ici serait Accepted par le navigateur
  // puis refusé par le serveur.
  function syncFactorField() {
    const enrolled = Boolean(state.twoFactor?.enrolled);
    elements.actionFactorLabel.textContent = enrolled ? "Code de sécurité" : "Mot de passe actuel";
    elements.actionFactor.autocomplete = enrolled ? "one-time-code" : "current-password";
    elements.actionFactorHint.textContent = enrolled
      ? "Code de 6 chiffres de l'application d'authentification, ou code de récupération."
      : "Sans double authentification, le mot de passe prouve que c'est bien toi.";
  }

  function buildField(field) {
    const group = document.createElement("div");
    group.className = "field-group";
    const id = `action-${field.name}`;
    const label = document.createElement("label");
    label.setAttribute("for", id);
    label.textContent = field.label;
    group.append(label);

    let input;
    if (field.type === "checkbox") {
      input = document.createElement("input");
      input.type = "checkbox";
      if (field.defaultChecked) input.checked = true;
    } else if (field.type === "select") {
      input = document.createElement("select");
      for (const value of field.options) {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = planLabel(value);
        input.append(option);
      }
      input.value = field.defaultValue || field.options[0];
    } else {
      input = document.createElement("input");
      input.type = field.type;
      if (field.autocomplete) input.autocomplete = field.autocomplete;
      if (field.value) input.value = field.value;
      if (field.type === "number") {
        input.min = "1";
        input.max = "720";
      }
    }
    input.id = id;
    input.name = field.name;
    if (field.required) input.required = true;
    group.append(input);
    return group;
  }

  async function onDialogSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const action = state.dialogAction;
    if (!action) return;
    const payload = { reason: form.elements.reason.value.trim() };

    if (action.id === "qrcode-activity") {
      payload.active = action.active;
    } else {
      for (const field of action.fields || []) {
        const value = form.elements[field.name];
        payload[field.name] = field.type === "checkbox" ? value.checked : value.value.trim();
      }
    }
    // Envoyée sous le nom que le serveur attend pour l'état courant : un champ
    // nommé « mot de passe » qui contient un code serait simplement ignoré.
    const factor = form.elements.factor.value.trim();
    if (state.twoFactor?.enrolled) payload.twoFactorCode = factor;
    else payload.currentPassword = factor;

    elements.actionConfirm.disabled = true;
    try {
      let result = null;
      if (action.id === "qrcode-activity") {
        await api(`/api/admin/qrcodes/${action.qrcodeId}/activity`, { method: "POST", body: payload });
        showToast(payload.active ? "QR code réactivé." : "QR code désactivé.");
      } else {
        result = await api(`/api/admin/users/${state.selected.id}/${action.id}`, { method: "POST", body: payload });
        showToast(messageFor(action, result));
      }
      elements.actionModal.hidden = true;
      state.dialogAction = null;
      form.reset();
      await Promise.all([selectUser(state.selected.id), loadAudit()]);
    } catch (error) {
      elements.actionError.textContent = error.message || "L'intervention a échoué.";
      elements.actionError.hidden = false;
    } finally {
      elements.actionConfirm.disabled = false;
    }
  }

  // Une intervention qui n'a rien changé ne doit pas être annoncée comme réussie :
  // dire « la grâce n'a pas été prolongée » est plus utile que « terminé ».
  function messageFor(action, result) {
    if (action.id === "subscription/grace" && result?.effective === false) {
      return result.message || "La grâce n'a pas été prolongée.";
    }
    if (action.id === "sessions/revoke") {
      return `${result?.count ?? 0} session(s) fermée(s).`;
    }
    if (action.id === "subscription/plan" && result?.message) {
      return result.message;
    }
    return "Intervention enregistrée.";
  }

  // ── Double authentification ─────────────────────────────────────────────────

  async function loadTwoFactor() {
    try {
      state.twoFactor = await api("/api/admin/2fa");
      renderTwoFactor();
    } catch (error) {
      elements.twoFactorStatus.textContent = error.message || "État indisponible.";
    }
  }

  function renderTwoFactor() {
    const status = state.twoFactor;
    if (!status) return;
    elements.twoFactorActions.replaceChildren();
    elements.twoFactorStatus.textContent = status.enrolled
      ? `Active depuis le ${formatDate(status.confirmedAt)}. ${status.recoveryCodesRemaining} code(s) de récupération restant(s).`
      : "Inactive : chaque intervention demande le mot de passe du compte.";

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
    } else {
      add("setup", "Activer");
    }
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
    elements.twoFactorReasonGroup.hidden = false;
    elements.twoFactorCodeGroup.hidden = true;
    elements.twoFactorCode.required = false;
    elements.twoFactorConfirmCodeGroup.hidden = mode === "setup";
    elements.twoFactorConfirmCode.required = mode !== "setup";
    elements.twoFactorSecret.hidden = mode === "setup";

    if (mode === "setup") {
      elements.twoFactorTitle.textContent = "Activer la double authentification";
      elements.twoFactorIntro.textContent = "Un code de 6 chiffres demandé à chaque intervention, en plus de la session.";
      elements.twoFactorSubmit.textContent = "Afficher le QR code";
    } else if (mode === "recovery-codes") {
      elements.twoFactorTitle.textContent = "Nouveaux codes de récupération";
      elements.twoFactorIntro.textContent = "Les codes précédents cessent d'être acceptés. Les nouveaux ne s'affichent qu'une fois.";
      elements.twoFactorSubmit.textContent = "Générer les codes";
    } else {
      elements.twoFactorTitle.textContent = "Désactiver la double authentification";
      elements.twoFactorIntro.textContent = "Les interventions ne demanderont plus qu'un code. Cette écriture est journalisée.";
      elements.twoFactorSubmit.textContent = "Désactiver";
    }
    elements.twoFactorModal.hidden = false;
  }

  async function onTwoFactorSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const mode = state.twoFactorMode;
    const reason = elements.twoFactorReason.value.trim();
    const password = elements.twoFactorPassword.value;
    elements.twoFactorError.hidden = true;
    elements.twoFactorSubmit.disabled = true;
    try {
      if (mode === "setup" && !state.twoFactorSecret) {
        const result = await api("/api/admin/2fa/setup", {
          method: "POST",
          body: { reason, currentPassword: password },
        });
        state.twoFactorSecret = result.secret;
        renderTwoFactorQr(result);
        elements.twoFactorCodeGroup.hidden = false;
        elements.twoFactorCode.required = true;
        elements.twoFactorPasswordGroup.hidden = true;
        elements.twoFactorPassword.required = false;
        elements.twoFactorSubmit.textContent = "Activer";
        return;
      }
      if (mode === "setup") {
        // La confirmation renvoie les codes de récupération : en demander une
        // seconde série invaliderait les premiers, sans raison.
        const result = await api("/api/admin/2fa/confirm", {
          method: "POST",
          body: { reason, code: elements.twoFactorCode.value.trim() },
        });
        await Promise.all([loadTwoFactor(), loadAudit()]);
        showRecoveryCodes(result.recoveryCodes);
        return;
      }
      if (mode === "recovery-codes") {
        const result = await api("/api/admin/2fa/recovery-codes", {
          method: "POST",
          body: {
            reason,
            currentPassword: password,
            twoFactorCode: elements.twoFactorConfirmCode.value.trim(),
          },
        });
        await Promise.all([loadTwoFactor(), loadAudit()]);
        showRecoveryCodes(result.recoveryCodes);
        return;
      }
      await api("/api/admin/2fa/disable", {
        method: "POST",
        body: {
          reason,
          currentPassword: password,
          twoFactorCode: elements.twoFactorConfirmCode.value.trim(),
        },
      });
      elements.twoFactorModal.hidden = true;
      showToast("Double authentification désactivée.");
      await Promise.all([loadTwoFactor(), loadAudit()]);
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
    elements.twoFactorQr.hidden = false;
    const host = elements.twoFactorQr;
    host.replaceChildren();
    // Le secret reste lisible dans la page si la bibliothèque de QR n'a pas
    // chargé : sans cela, l'activation serait bloquée sans issue.
    if (typeof window.qrcode !== "function") {
      const fallback = document.createElement("p");
      fallback.className = "field-hint";
      fallback.textContent = "Le QR code n'a pas pu être dessiné : saisis le secret à la main.";
      host.append(fallback);
      return;
    }
    const qr = window.qrcode(0, "M");
    qr.addData(uri);
    qr.make();
    const modules = qr.getModuleCount();
    const scale = 6;
    const margin = 4;
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

  async function loadAudit() {
    try {
      const result = await api("/api/admin/audit?limit=50&offset=0");
      elements.auditList.replaceChildren();
      for (const entry of result.actions) {
        const row = document.createElement("div");
        row.className = "admin-row admin-row-static";
        row.append(
          cell(formatDate(entry.createdAt)),
          cell(entry.actorEmail),
          cell(entry.targetEmail || "—"),
          cell(entry.action),
          cell(entry.reason),
        );
        elements.auditList.append(row);
      }
      if (result.actions.length === 0) {
        const empty = document.createElement("p");
        empty.className = "field-hint";
        empty.textContent = "Aucune intervention enregistrée.";
        elements.auditList.append(empty);
      }
    } catch (error) {
      showToast(error.message || "Le journal est indisponible.");
    }
  }

  function showToast(message) {
    elements.toastMessage.textContent = message;
    elements.toast.classList.add("visible");
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => elements.toast.classList.remove("visible"), 3000);
  }
})();
