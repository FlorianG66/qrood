# TODO

Sujet de suivi du projet QROOD. Format lisible par l'extension **Todo Tree** (VS Code) : `- [ ]` à faire, `- [x] livré.

Dernière mise à jour : 5 octobre 2026.

---

## Connexion avec un compte tiers (Google, Microsoft, autre)

Tranché : intégration directe des fournisseurs, sans service intermédiaire. Un compte Google se connecte ; Microsoft et les autres suivront le même schéma. La connexion et la page profil sont livrées ; le reste de la liste est ce qui reste à faire.

- [x] Table `users.auth_provider` / `users.provider_id`, et `password_hash` rendu facultatif — un compte créé par un fournisseur n'a rien à y écrire
- [x] Index unique `(auth_provider, provider_id)` : un identifiant externe ne désigne qu'un compte
- [x] Route de démarrage `/api/auth/google/start`, avec `state` tiré au hasard
- [x] Route de retour `/api/auth/google/callback` : échange du code, lecture du profil, création ou ouverture de session
- [x] `state` vérifié au retour en comparaison constante, cookie `HttpOnly` borné à dix minutes et aux routes Google
- [x] Cookie d'état signé (HMAC, clé `QROOD_OAUTH_FLOW_KEY` ou aléatoire par processus) : sans signature, un tiers capable de poser ce cookie - hôte frère du domaine, trajet non chiffré, fuite d'en-tête - désignerait le compte et la session d'une victime et lui relierait sa propre identité Google
- [x] Redirection après connexion contrainte au domaine QROOD (open redirect), `Location` relatif
- [x] Aucune liaison automatique : une adresse déjà portée par un compte existant est refusée, sans rien lui demander
- [x] Refus d'une identité dont l'adresse n'est pas déclarée vérifiée par le fournisseur
- [x] Compte retrouvé par l'identifiant externe, pas par l'adresse : un changement d'adresse chez Google ne perd pas l'accès
- [x] Interface : bouton « Continuer avec Google », affiché seulement si le serveur le dit configuré
- [x] Interface : messages d'échec écrits par le front, code court dans l'URL, jamais de texte venu du serveur
- [x] Tests : flux complet, `state` absent/différent/rejoué, identité non prouvée, compte existant, open redirect, compte sans mot de passe, migration d'une base antérieure
- [x] Points d'appel du fournisseur surchargeables hors production, pour que les tests ne sortent pas du réseau local
- [x] Page profil : lier et délier une identité Google, pour réunir un compte local et un compte Google — le mot de passe actuel est exigé dans les deux sens, et l'adresse du fournisseur n'entre jamais dans le compte
- [x] Liaison astreinte à la session : refus sans session, sur une autre session, ou après fermeture de la session d'origine
- [x] Second facteur tranché : la double authentification prime. Un compte qui exige un code ne se connecte pas par Google, n'y relie rien, et ne s'en sert pas pour se prouver — Google est un facteur parmi d'autres, jamais un substitut
- [x] Compte créé par Google : voie sans mot de passe ouverte. Le retour du fournisseur date la session (`sessions.fresh_until`, quinze minutes par défaut), et cette preuve remplace le mot de passe pour l'adresse, le mot de passe et la suppression. Un mot de passe défini la referme
- [x] Interface : section « Connexion Google » sur `/compte`, messages du retour (`liaison_reussie`, `reauth_reussie`, refus), champs de mot de passe masqués quand le compte n'en a pas
- [x] Délier reste possible sans configuration Google : retirer une identité ne demande rien au fournisseur, faute de quoi un lien survivrait à la disparition des identifiants sans aucun moyen de s'en défaire
- [x] Un compte sans mot de passe ne peut pas activer la double authentification : elle lui fermerait partout sa seule porte - connexion Google, liaison, ré-authentification et suppression d'un lien. Refus rendu avant l'émission de tout secret, bouton masqué sur `/compte`
- [x] Un compte sans mot de passe ne peut pas être délié, et le refus nomme le mot de passe à définir avant de renvoyer vers une preuve Google qui n'y pourrait rien
- [x] Tests : liaison, session étrangère, priorité de la double authentification, fenêtre de preuve qui expire, identité relibérée, cookie d'état forgé, activation A2F sans mot de passe — quatorze scénarios au total
- [ ] Microsoft, puis tout autre fournisseur : même schéma, en généralisant le `state` au-delà de Google
- [ ] Vérifier en navigateur : bouton, section du compte, messages d'échec, retour sur la bonne page

## A2F pour les comptes utilisateurs

L'A2F existe mais est réservé au super-admin : points d'entrée sous `/api/admin/2fa`, table `admin_two_factor`, interface uniquement sur `/back-office`. Un compte classique ne peut ni activer ni utiliser de second facteur.

- [ ] Routes distinctes `/api/auth/2fa/*`, séparées des routes admin
- [ ] Vérification du second facteur dans `POST /api/auth/login`
- [ ] Décider si `admin_two_factor` est généralisée ou si deux mécanismes coexistent
- [ ] Codes de récupération par compte, comme pour le rôle admin

## À vérifier au navigateur

Livré, mais jamais ouvert dans un vrai navigateur : aucun outil de pilotage navigateur n'est disponible ici. La validation passe par la syntaxe, la correspondance des identifiants HTML/JS et les tests d'API.

- [ ] Suppression d'un compte : toast « Compte supprimé. », fiche refermée, liste mise à jour (correctif `e696e64`)
- [ ] Mise à jour instantanée de toutes les interventions du back-office (même correctif)
- [ ] Rendu de la modale A2F : QR code, secret de secours, codes de récupération
- [ ] Raccourci `/compte` → `/back-office` et affichage conditionné au rôle
- [ ] Affichage d'une offre offerte sur `/compte` (« Offert, aucun abonnement », « Jusqu'au »)
- [ ] Bouton « Continuer avec Google » dans la modale d'authentification, et messages d'échec du retour
- [ ] Section « Connexion Google » sur `/compte` : champs masqués pour un compte sans mot de passe, lien de preuve révélé après un refus `reauth_required`, avertissement avant une déliaison
- [ ] A2F sur `/compte` : pas de bouton « Activer » sans mot de passe, et la ligne d'état qui explique pourquoi

Si un point se reproduit, le diagnostic se fait dans le navigateur : `jsdom` et `linkedom` ne sont pas installés, et `admin.js` n'a pas de point d'entrée testable sans ajouter une dépendance.

## Risques connus

- [x] **Expiration des offres offertes** — corrigé : `isEntitled()` (`server.mjs`) exige maintenant `current_period_end` pour une offre manuelle, et `renewManualOffer()` repousse la période d'un an au premier accès constatant l'échéance. Renouvellement paresseux, sans cron : le comportement ne dépend pas du jour de la semaine. La ligne courante est ciblée par `id`.
- [x] **Offre offerte et historique** — l'écriture cible `WHERE id = ?`, plus toutes les lectures de la ligne courante. Le tri est passé à « non terminale d'abord » : un webhook Stripe tardif après une résiliation faisait passer l'ancien abonnement résilié devant l'accès en cours. Test ajouté sur un compte à deux lignes.
- [ ] **Parallélisme du rafraîchissement** — après une intervention, liste, journal et fiche se rechargent en parallèle sans jeton de requête. Non observé ; sérialiser ralentirait l'interface.
- [ ] **Avertissement `buildx`** — `deploy.sh` déclenche un avertissement Docker (`Bake` configuré sans `buildx`). Le build passe par le driver par défaut, sans conséquence observée.

---

## Archivé — livré

### Back-office super-admin — `e6bbcb1`

- [x] Rôle `users.is_super_admin` avec un défaut structurel à 0 : aucune route publique ne peut l'écrire
- [x] Compte canonique unique `florian.guichard66@gmail.com`, promu au démarrage, rôle retiré aux autres
- [x] Ultra de droit pour le super-admin, sans abonnement ni Stripe
- [x] `/back-office` : liste, recherche, fiche détaillée, QR codes du compte, journal des interventions
- [x] Sept interventions : mot de passe, confirmation d'adresse, fermeture des sessions, offre, résiliation, grâce, suppression
- [x] Chaque écriture exige rôle, CSRF, raison d'au moins 8 caractères et re-authentification
- [x] Auto-protection : ni soi-même (400) ni un autre super-admin (403)
- [x] Audit horodaté : acteur, cible, raison, IP, facteur, métadonnées
- [x] Migration v6 du schéma, 9 scénarios de test

### Double authentification du rôle super-admin — `e6bbcb1`

- [x] TOTP RFC 6238 (HMAC-SHA1, 30 s, fenêtre ±1), anti-rejeu par compteur
- [x] Confirmation obligatoire : le secret en attente expire, rien n'est actif sans code à 6 chiffres validé
- [x] 8 codes de récupération uniques, hachés SHA-256, consommables une seule fois
- [x] Activation, désactivation, régénération, champ « Code de sécurité » dans chaque intervention
- [x] Sans A2F : mot de passe exigé à chaque intervention. Avec A2F : code TOTP ou de récupération

### Offre d'abonnement et raccourci — `07f5fcd`

- [x] Action « Offrir une offre » : Découverte, Pro ou Ultra, durée de 1 à 3650 jours (365 par défaut)
- [x] Écriture directe en base, sans Stripe, sans facturation
- [x] Refus `409 stripe_subscription_active` si un abonnement Stripe réel existe
- [x] `/compte` affiche « Offert, aucun abonnement » et « Jusqu'au » au lieu d'un faux renouvellement
- [x] Résumé unifié via `getSubscriptionSummary()`, partagé par `/compte` et le back-office
- [x] Raccourci `/compte` → `/back-office`, visible uniquement pour le super-admin
- [x] Audit `subscription_granted` avec facteur, offre, durée, période, offre précédente

### Correctif de suppression — `e696e64`

- [x] La suppression réussissait, mais le rechargement de la fiche renvoyait 404 et affichait « Compte introuvable » par-dessus le succès
- [x] `refreshAfterAction()` remet liste, fiche et journal à jour ; sélection vidée et fiche refermée après suppression
- [x] `selectUser()` accepte un mode silencieux : plus de défilement automatique hors clic
- [x] Messages distincts pour suppression, réinitialisation et confirmation d'adresse

### Offre offerte, échéance et renouvellement — courant

- [x] `renewManualOffer()` : une offre manuelle échue est repoussée d'un an à partir de l'instant présent, jamais du reliquat de période dépassée
- [x] `cancel_at_period_end` à 0 sur l'offre accordée : il autorise le renouvellement, et reste le geste explicite de retrait quand il passe à 1
- [x] Un abonnement Stripe n'est jamais renouvelé par cette règle : son cycle appartient à Stripe
- [x] Super-admin prioritaire, avant toute logique d'abonnement
- [x] Renouvellement appliqué à la page du compte, à la fiche et à la liste du back-office, pour que les écrans ne se contredisent pas
- [x] `autoRenew` exposé dans le résumé, affiché sur `/compte` et dans la fiche du back-office
- [x] Aucun écrit dans `admin_actions` : le journal reste réservé aux décisions humaines

### Divers — commits antérieurs

- [x] Scripts de déploiement Windows et VPS, Caddy, Docker Compose
- [x] Correctifs d'interface : saccades de statistiques, animations de compteurs, fond sous les modales, libellé du curseur, générateur cassé sur mobile
- [x] Export PNG 1024 et SVG, personnalisation des deux couleurs, vCard 3.0
- [x] Statistiques de scan avec réconciliation des agrégats au démarrage
- [x] Migration automatique et idempotente des QR codes stockés en `localStorage`
- [x] Nettoyage des comptes de test, sauvegarde conservée dans `data/`

---

## Conventions

- Messages de commit en français, sans accents : le terminal les rend mal
- Chaque intervention admin passe par une route `/api/admin/*`, jamais d'accès direct à la session d'un autre compte
- Tests avec `npm test` (`node --test`), sans dépendance de test externe
- Déploiement : `deploy.ps1 "message"` puis `ssh ubuntu@137.74.162.116 "cd ~/qraft && bash deploy.sh"`. Le script échoue s'il n'y a rien à commiter, c'est le comportement attendu quand tout est déjà poussé
- Configurer Todo Tree : voir `.vscode/settings.json` (dossier ignoré par git, à recréer localement)