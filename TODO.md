# TODO

Sujet de suivi du projet QROOD. Format lisible par l'extension **Todo Tree** (VS Code) : `- [ ]` à faire, `- [x] livré.

Dernière mise à jour : 2 octobre 2026.

---

## Connexion avec un compte tiers (Google, Microsoft, autre)

- [ ] Trancher : service intermédiaire (Auth0, Clerk, Supabase Auth) ou intégration directe des fournisseurs
- [ ] Trancher quels fournisseurs, et dans quel ordre
- [ ] Trancher si le mot de passe devient facultatif — `users.password_hash` est `NOT NULL`, un compte créé par OAuth n'a rien à y mettre
- [ ] Table `user_identities` (compte ↔ fournisseur ↔ identifiant externe), une ligne par mode de connexion rattaché à un compte
- [ ] Route de démarrage `/auth/:provider`
- [ ] Route de retour `/auth/:provider/callback`
- [ ] Paramètre `state` vérifié au retour : sans lui, le callback est ouvert à la réutilisation
- [ ] Redirection après connexion contrainte au domaine QROOD (open redirect)
- [ ] Liaison par adresse e-mail uniquement si le fournisseur la déclare vérifiée, et jamais d'écrasement silencieux d'un compte existant
- [ ] Page profil : lier et délier un mode de connexion
- [ ] Tests : linkage, rejet d'e-mail non vérifié, rejeu de `state`, open redirect, compte sans mot de passe

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

Si un point se reproduit, le diagnostic se fait dans le navigateur : `jsdom` et `linkedom` ne sont pas installés, et `admin.js` n'a pas de point d'entrée testable sans ajouter une dépendance.

## Risques connus

- [ ] **Expiration des offres offertes** — `isEntitled()` (`server.mjs:1479`) renvoie `true` pour tout abonnement `active` sans lire `current_period_end`. Une offre offerte à durée fixe peut rester active au-delà de sa date de fin : le statut est écrit une fois et aucun webhook Stripe ne le changera, l'écriture étant manuelle. L'interface annonce pourtant « Jusqu'au ». À corriger avant de vendre ce mécanisme.
- [ ] **Offre offerte et historique** — l'écriture d'offre cible `WHERE user_id = ?` sans restreindre à la ligne courante : plusieurs lignes d'abonnement terminées pour un même compte seraient toutes modifiées. Le test ne couvre qu'un compte à une seule ligne.
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