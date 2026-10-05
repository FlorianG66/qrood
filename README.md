# QROOD

QROOD est une plateforme web de génération de QR codes avec comptes utilisateurs, bibliothèque personnelle et statistiques de scan.

Un QR code de lien peut utiliser une URL de suivi QROOD (`/r/…`) : un scan est mesuré, puis l’utilisateur est redirigé vers la destination. En mode local, l’origine par défaut est `http://localhost:3000` : afin qu’un téléphone puisse lire le QR code, QROOD encode directement la destination saisie tant qu’aucune origine publique ou réseau joignable n’est configurée. Un QR code de coordonnées ouvre une page de contact QROOD (`/c/…`) qui permet de télécharger la vCard, ou encode directement la vCard en mode local. Les QR codes doivent être enregistrés dans un compte ; le suivi s’active lorsque l’origine QROOD est joignable par le scanner.

## Prérequis

- Node.js **22.5 ou plus récent** (le projet utilise le module natif `node:sqlite`)
- PowerShell pour le script de lancement sous Windows

Une dépendance npm est nécessaire : le SDK officiel [`stripe`](https://www.npmjs.com/package/stripe). `start-server.ps1` l’installe automatiquement au premier lancement ; sinon :

```powershell
npm ci
```

Sans cette dépendance, le serveur démarre normalement mais **refuse toute facturation** (`503 billing_not_configured`). Le reste de la plateforme, y compris les offres gratuites, reste pleinement opérationnel.

## Lancer la plateforme

```powershell
powershell -ExecutionPolicy Bypass -File .\start-server.ps1
```

Ouvrez ensuite [http://localhost:3000/](http://localhost:3000/).

Le port et l’arrêt automatique après inactivité sont configurables :

```powershell
.\start-server.ps1 -Port 3000 -IdleTimeoutMinutes 30
```

Le serveur s’arrête automatiquement après 30 minutes sans requête métier (les probes `/api/health` ne réactivent pas ce délai). `Ctrl+C` permet de l’arrêter manuellement. La base SQLite est créée dans `data/qrood.sqlite` et n’est jamais servie comme fichier statique.

## Fonctionnalités

- Création à partir d’une URL HTTP/HTTPS ou d’une vCard 3.0
- Aperçu en direct, personnalisation des deux couleurs
- Export PNG 1024 px et SVG vectoriel
- Copie du contenu encodé
- Inscription et connexion par e-mail/mot de passe
- Connexion avec un compte Google, sans liaison automatique à un compte existant
- Sessions serveur avec cookie `HttpOnly` et `SameSite=Strict`
- Bibliothèque personnelle accessible sur les autres navigateurs après connexion
- Statistiques : nombre de scans, évolution sur 30 jours, dernier scan, type d’appareil et domaine de provenance
- Agrégats quotidiens conservés pour garder les totaux ; événements de scan bruts limités et conservés 365 jours
- Réconciliation des agrégats à chaque démarrage : un événement brut absent d’un agrégat est réintégré une seule fois
- Au-delà de 100 domaines de provenance distincts pour un QR code, les nouveaux domaines sont regroupés sous « Autres sources »
- Suppression et modification des QR codes avec contrôle de propriété
- Section Tarifs publique, lisible sans compte, avec les montants lus sur Stripe
- Migration automatique, isolée par compte et idempotente des QR codes précédemment stockés dans `localStorage` (50 par session, y compris les anciennes vCard). Une erreur réseau, de session ou de serveur n’est jamais comptée comme un échec : l’élément est repris à la session suivante

## Abonnements

Trois offres, avec deux compteurs indépendants : le nombre de QR codes **enregistrés** et le nombre de QR codes **actifs** en même temps.

| Offre | Enregistrés | Actifs | Statistiques | Personnalisation | Prix |
| --- | --- | --- | --- | --- | --- |
| Découverte | 5 | 1 | 30 jours | couleurs, marges | offert |
| Pro | 25 | illimités | 365 jours | + dégradés, arrondis | 12 € TTC / mois |
| Ultra | illimités | illimités | 730 jours | + logo, formes `dot` et `leaf` | 29 € TTC / mois |

Prix **TTC** : les Prices Stripe sont créés avec `tax_behavior: inclusive`, donc le montant affiché est celui que le client paie, TVA comprise. L'interface lit `tax_behavior` sur le Price et n'ajoute le suffixe « HT » que pour un Price `exclusive`.

### Section Tarifs

La page d'accueil comporte une section Tarifs entre la bibliothèque et le guide, lisible sans compte : c'est le catalogue qui décide d'un abonnement, il doit donc être public.

Les montants ne sont jamais écrits en dur dans l'interface. `GET /api/billing/offers` les lit sur les Prices Stripe (mémorisés une heure par le serveur), et la section affiche ce que le serveur renvoie :

| Situation | Affichage |
| --- | --- |
| Price actif en euros, abonnement mensuel | montant et `/ mois` |
| Price archivé, désactivé, hors euros ou non mensuel | aucun montant, offre « Bientôt disponible » |
| Aucun Price configuré | aucun montant, bandeau expliquant que la facturation n'est pas activée |
| Serveur injoignable | message d'erreur et bouton « Réessayer » |

Un montant absent n'est jamais remplacé par une valeur de repli : le test d'intégration vérifie explicitement qu'aucun prix n'est inventé sans configuration Stripe. Les montants du README ci-dessus servent de référence de recette, pas de source de vérité — un Price modifié dans le dashboard Stripe change l'affichage sans toucher au code.

Les boutons d'appel à l'action reprennent les règles du serveur plutôt que de les deviner :

- **Découverte** — crée un compte, ou ramène à l'éditeur si le compte existe déjà ; un abonné est renvoyé vers le portail, seul chemin qui évite deux abonnements vivants ;
- **Pro** et **Ultra** — ouvrent Stripe Checkout, ou la fenêtre de connexion pour un visiteur.

L'offre courante n'est signalée que pour un compte connecté : un visiteur n'a pas d'offre, et l'indiquer le ferait passer pour abonné.

### Activation et désactivation d’un QR code

Un QR code actif mais au-delà du quota d’actifs continue de fonctionner. Au-delà, la création ou l’activation d’un QR code supplémentaire est refusée (`402`), avec un message qui propose de désactiver un QR code existant plutôt que de changer d’offre.

Un QR code **désactivé** renvoie `410 Gone` sur `/r/…`, `/c/…` et `/c/…/vcard` et affiche une page d’explication. Il reste dans la bibliothèque, et sa réactivation lui rend son lien, sa destination et ses statistiques. L’accès n’est jamais bloqué brutalement : un changement d’offre laisse les QR codes existants publier leurs liens.

Quand le quota d’actifs est dépassé, l’interface affiche une bannière sans geler le compte, et propose une désactivation groupée.

### Perte d’accès

| Situation | Effet |
| --- | --- |
| `active`, `trialing` | accès normal |
| `past_due`, `unpaid` | accès conservé, les relances Stripe sont en cours |
| `canceled`, `paused` | grâce de **48 h** après `current_period_end`, puis retour sur Découverte |
| `incomplete`, `incomplete_expired` | aucun droit (Checkout abandonné) |

Le retour sur Découverte ne supprime rien : les QR codes publiés continuent de répondre, et les options de personnalisation premium déjà utilisées restent modifiables tant qu’elles ne sont pas changées.

## Facturation Stripe

### Mise en place

1. Créer deux produits récurrifs mensuels en **euros**, avec Stripe Tax activé et le Price réglé sur **taxes incluses**, puis noter les `price_…` :
   - Pro : **12,00 € TTC** / mois (soit 10,00 € HT en France)
   - Ultra : **29,00 € TTC** / mois (soit 24,17 € HT en France)
2. Activer le portail client (paramètres Stripe) pour la résiliation et le changement de carte.
3. Déclarer les variables d’environnement :

```powershell
$env:QROOD_STRIPE_SECRET_KEY = "sk_live_…"
$env:QROOD_STRIPE_WEBHOOK_SECRET = "whsec_…"
$env:QROOD_STRIPE_PRICE_PRO = "price_…"
$env:QROOD_STRIPE_PRICE_ULTRA = "price_…"
```

Le préfixe `STRIPE_` (`STRIPE_SECRET_KEY`, `STRIPE_PRICE_PRO`, …) est aussi accepté, sans le `QROOD_`. Une seule des deux offres payantes suffit pour activer la facturation.

**Ces clés ne doivent jamais être versionnées.** Le serveur ne lit aucun fichier `.env` : les variables viennent de l’environnement du processus. Deux conséquences à connaître.

- Les définir dans la session PowerShell, comme ci-dessus. Elles meurent à la fermeture du terminal, ce qui est le comportement souhaité en développement.
- Ne jamais écrire les clés dans un fichier suivi par git, même brièvement. Si un `.env` est créé malgré tout, il est déjà ignoré (`.env`, `.env.*`), mais il ne sera pas lu par le serveur : il ne sert qu’à consigner des valeurs, pas à les fournir.

En production, l’hébergeur fournit ces variables depuis son propre coffre (Secrets Manager, variables de plateforme, etc.) : aucune clé n’est alors présente sur le disque.

Le serveur masque systématiquement les secrets avant écriture dans le journal — une erreur du SDK Stripe ne peut donc pas y déposer la clé, y compris dans sa forme déjà partiellement masquée (`sk_test_****…`). Un test de non-régression le vérifie à chaque exécution de la suite.

4. Déclarer le webhook, sur l’URL publique :

```
POST https://qr.example.com/api/billing/stripe/webhook
```

Événements à surveiller :

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`

Pour l’é développement local, utiliser le CLI Stripe :

```powershell
stripe listen --forward-to localhost:3000/api/billing/stripe/webhook
```

Le secret affiché par la commande (`whsec_…`) va dans `QROOD_STRIPE_WEBHOOK_SECRET`.

### Fonctionnement

- Le paiement passe par **Stripe Checkout** hébergé (`mode: subscription`), entièrement automatisé, avec adresse de facturation obligatoire et `automatic_tax` : aucune saisie ni validation de paiement côté QROOD.
- Un compte ne peut avoir **qu’un seul** abonnement non terminal, garanti par un index unique en base. Acheter une seconde offre est refusé (`409`) et l’utilisateur est envoyé vers le portail client, seul chemin qui évite la coexistence de deux abonnements.
- La clé d’offre vient de `metadata.plan` écrit à la création du Checkout, avec le `price` en repli : un remappage manuel dans le dashboard Stripe ne peut pas changer l’offre servie.
- Les webhooks sont vérifiés par signature sur le corps brut, et **idempotents** : le même `event.id` n’est appliqué qu’une fois. En cas d’erreur, le marqueur est effacé pour que Stripe puisse réessayer.
- Après un Checkout, l’interface appelle `POST /api/billing/confirm` avec le `session_id` : l’offre est donc visible immédiatement, sans attendre la livraison du webhook.
- Un webhook dont le Price n’est pas reconnu n’accorde aucun accès payant, et le journal serveur le signale explicitement.


## Sécurité intégrée

- Mots de passe hachés avec `scrypt` et sel aléatoire ; aucun mot de passe en clair n’est stocké
- Jetons de session aléatoires ; seuls leurs hachages sont conservés en base
- Jetons CSRF et vérification de l’origine pour les requêtes modifiables
- Requêtes SQL préparées et validation stricte des données
- Limitation des tentatives de connexion, d’inscription, de création, de scan et de téléchargement public ; déduplication des scans rapprochés
- En-têtes CSP, HSTS en production, `X-Frame-Options`, `nosniff` et politique de référent
- Refus des URL contenant des identifiants, des URL javascript/data et des destinations réseau privées/local par défaut (adresses IP IPv4/IPv6, IPv4-mapped et suffixes locaux)
- Aucun stockage d’adresse IP : ni dans les statistiques (un `Referer` qui est une adresse IP est ignoré), ni dans les tables ; la clé de déduplication des scans est un hachage transitoire conservé uniquement en mémoire
- Limitation du nombre de domaines de provenance par QR code pour que les agrégats ne puissent pas croître sans borne
- Fichiers SQL et code serveur exclus du service de fichiers statiques

## Back-office super-admin

`/back-office` est servi sans session — la page elle-même ne contient aucune donnée — et refuse d'afficher quoi que ce soit à un compte sans rôle. Toutes les écritures passent par l'API `/api/admin/*`, jamais par une session usurpée.

Le rôle tient dans une colonne, `users.is_super_admin`, et il est unique par construction : à chaque démarrage, le serveur accorde le rôle à `florian.guichard66@gmail.com` et le retire à tous les autres. Un rôle super-admin surveyant par erreur est donc corrigé au démarrage suivant, pas seulement ignoré.

Conséquences assumées :

- **Ultra sans abonnement.** Le super-admin dispose de l'offre Ultra de droit ; son quota est illimité sans passer par Stripe. `/compte` affiche cette origine explicitement, pour ne pas laisser croire à un abonnement payant.
- **Protection symétrique.** Un compte super-admin n'accepte aucune intervention depuis le back-office, pas même la sienne : ses QR codes et ses statistiques passent par les mêmes endpoints que les autres, et sont refusés. La page annonce la règle et retire les boutons au lieu de renvoyer une erreur après coup.
- **Écritures justifiées et journalisées.** Toute intervention exige un rôle, un jeton CSRF, une raison d'au moins 8 caractères, et le journal (`admin_actions`) est écrit avant la réponse : une intervention non journalisée n'a pas eu lieu. Le journal survit à la suppression du compte visé.
- **Offrir une offre.** L'action « Offrir une offre » écrit l'offre choisie (Découverte, Pro ou Ultra) et sa durée directement en base, sans passer par Stripe et sans rien facturer. Elle est refusée sur un compte qui a un abonnement Stripe actif : Stripe est alors maître, et l'offre écrite ici serait écrasée au prochain webhook sans que personne ne soit prévenu. L'accès offert s'éteint seul à sa date d'expiration (`cancel_at_period_end`), et `/compte` l'affiche comme « Offert, aucun abonnement » plutôt que comme un renouvellement.
- **Aucune donnée personnelle exposée.** Les listes et les détails renvoient l'identifiant, le pseudo et les compteurs d'activité ; ni secret de QR code, ni adresse e-mail complète, ni destination privée.

### Double authentification du rôle

Tant que la double authentification n'est pas activée, chaque intervention demande le **mot de passe** du compte super-admin. Une fois activée, elle demande un **code TOTP** de 6 chiffres (RFC 6238, HMAC-SHA1, 30 s, tolérance d'une fenêtre) **ou** un code de récupération à usage unique ; le mot de passe seul ne suffit plus.

- L'activation passe par `/back-office` : mot de passe + raison, puis scan du QR code (`otpauth://`) ou saisie manuelle du secret, puis validation d'un code. Tant que ce code n'est pas validé, le secret présenté n'est pas actif — un secret jeté au hasard ne peut pas bloquer le compte.
- Les codes de récupération sont affichés une seule fois et stockés hachés (SHA-256) ; les régénérer invalide les précédents.
- Chaque code est consommé au premier usage : le serveur mémorise le dernier compteur accepté, si bien qu'un code rejoué dans la fenêtre de tolérance est refusé.
- Le journal note le facteur réellement utilisé (`password`, `totp`, `recovery`), ce qui distingue une intervention validée par le propriétaire d'une intervention validée par un mot de passe volé.
- Les tentatives sont limitées par période, activation et désactivation comprises.

## Connexion avec un compte Google

### Mise en place

1. Créer un client OAuth de type « Application Web » dans la console Google, avec l'autorisation `openid email profile` et l'URI de redirection exacte :

   ```
   https://qr.example.com/api/auth/google/callback
   ```

2. Déclarer les variables d'environnement :

```powershell
$env:QROOD_GOOGLE_CLIENT_ID = "…apps.googleusercontent.com"
$env:QROOD_GOOGLE_CLIENT_SECRET = "GOCSPX-…"
```

Le préfixe `GOOGLE_` est aussi accepté, sans le `QROOD_`. Sans ces deux valeurs, aucun bouton ne s'affiche et les routes répondent `404 oauth_unavailable` : le reste de la plateforme fonctionne normalement. `GOOGLE_REDIRECT_URI` n'est à définir que si l'URI de redirection déclarée chez Google n'est pas celle déduite de `QROOD_PUBLIC_ORIGIN`.

Les points d'appel du fournisseur (`QROOD_GOOGLE_AUTH_URL`, `QROOD_GOOGLE_TOKEN_URL`, `QROOD_GOOGLE_USERINFO_URL`) sont surchargeables uniquement hors production : le serveur refuse de démarrer si l'un d'eux est modifié alors que `NODE_ENV=production`. C'est ce qui permet aux tests de suivre le flux de bout en bout sans sortir du réseau local.

### Fonctionnement

- Le bouton n'est affiché que si le serveur confirme qu'un fournisseur est configuré : la décision est relue à chaque chargement, jamais supposée par l'interface.
- Le parcours est le flux `code` d'OAuth 2.0 : aller sur `/api/auth/google/start`, échange du code contre un jeton d'accès, puis lecture du profil. Les deux appels réseau sont bornés à dix secondes et refusent toute redirection vers une autre origine.
- Le compte est cherché par l'identifiant externe du fournisseur (`sub`), jamais par l'adresse : une adresse Google peut changer, l'identifiant non.
- **Aucune liaison automatique.** Si un compte existe déjà avec cette adresse, la connexion est refusée. Une adresse en commun ne prouve rien — un compte peut avoir été créé par quelqu'un qui n'a jamais confirmé la sienne, et le lui remettre reviendrait à lui céder le compte.
- Une identité dont l'adresse n'est pas déclarée vérifiée par le fournisseur est refusée, sans créer de compte.
- Le `state` est tiré au hasard, mis dans un cookie `HttpOnly` borné à dix minutes et aux seules routes Google, puis relu en comparaison constante. Le cookie est effacé par la réponse, succès ou échec.
- La destination de retour ne peut être qu'un chemin de ce site : une URL absolue, un `//exemple.test` ou un `/\exemple.test` sont ramenés à la racine. Le `Location` rendu est relatif, il ne peut donc pas désigner un autre site.
- Un compte créé par Google n'a pas de mot de passe (`password_hash` est `NULL`) et ne peut pas être ouvert par `POST /api/auth/login` : la réponse est identique à celle d'une adresse inconnue, sans révéler que le compte existe.
- L'adresse déclarée vérifiée par Google est enregistrée comme vérifiée : c'est la preuve du fournisseur qui vaut confirmation, aucun e-mail n'est envoyé.
- Les échecs sont rendus par un code court dans l'URL de retour (`?oauth=…`) ; le message est écrit par l'interface, jamais par le serveur. Aucun secret du fournisseur n'est écrit dans le journal.

**Non couvert à ce stade :** la page profil ne sait pas encore lier ou délier une identité Google, donc un compte local et un compte Google ne peuvent pas être réunis. Un compte créé par Google n'a pas de second facteur propre : l'identité Google en tient lieu, y compris lorsqu'un mot de passe existe aussi sur ce compte.

## Configuration

Les variables d’environnement sont utiles pour une installation derrière un proxy HTTPS :

```powershell
$env:QROOD_PUBLIC_ORIGIN = "https://qr.example.com"
$env:QROOD_HOST = "0.0.0.0"
$env:QROOD_SECURE_COOKIES = "true"
$env:QROOD_TRUST_PROXY = "true" # uniquement si le proxy est fiable
$env:NODE_ENV = "production"
powershell -ExecutionPolicy Bypass -File .\start-server.ps1
```

`QROOD_PUBLIC_ORIGIN` doit être l’origine publique HTTPS réellement accessible par les scanners de QR codes. En production, le serveur refuse une origine HTTP ou des cookies non sécurisés. `QROOD_TRUST_PROXY=true` n’est activable que si le reverse proxy **réécrit** `X-Forwarded-For` : un en-tête fourni par le client serait sinon accepté tel quel pour le rate limiting et la déduplication des scans.

Par défaut, l’interface reste en **mode direct local** : le QR code contient le lien saisi, car `localhost` désigne le téléphone qui scanne et non le PC qui héberge QROOD. Pour activer le suivi depuis un téléphone, configurez une origine réellement joignable par ce téléphone (par exemple une adresse HTTPS publique, ou une adresse réseau locale avec `QROOD_HOST=0.0.0.0` et les règles de pare-feu appropriées), puis redémarrez le serveur. Pour autoriser explicitement une destination locale ou privée (développement interne uniquement) :

```powershell
$env:QROOD_ALLOW_PRIVATE_DESTINATIONS = "true"
```

### Limite connue : alias DNS privés

Le contrôle des destinations privée est purement lexical : il compare l’hôte à une liste de suffixes et examine l’adresse IP lorsqu’elle est écrite directement dans l’URL. Un nom public qui pointe vers une adresse privée (`interne.exemple.com` → `10.0.0.5`) n’est pas résolu par le serveur, qui ne ferait que transformer chaque scan en résolution DNS. Ces destinations doivent donc être modérées à la création du QR code (liste d’unités de travail autorisées, revue des signalements), ou le déploiement doit rester sur un réseau où lesQR codes ne sont pas lisibles par des visiteurs non autorisés.

## Tests

```powershell
npm test
```

Le test d’intégration démarre un serveur isolé sur un port libre et une base temporaire, puis vérifie :

- les comptes, les cookies `HttpOnly`/`SameSite=Strict`, le CSRF (y compris une déconnexion refusée sans jeton, qui ne doit pas tuer la session) ;
- l’isolation entre utilisateurs, y compris la réutilisation d’une clé d’import legacy par un autre compte ;
- le refus des destinations privées IPv4/IPv6, des URL `javascript:` et des identifiants dans les URL ;
- les redirections mesurées avant `Location`, les vCards pliées à 75 octets et le contraste des couleurs ;
- la déduplication des scans, l’absence d’adresse IP dans les statistiques, la réconciliation des agrégats au redémarrage, l’idempotence de cette réconciliation et la purge des événements bruts de plus de 365 jours ;
- les quotas d’offres (enregistrés et actifs), le refus `402`, la désactivation avec page `410` et sa réactivation, la non-régression des options premium et la grâce de 48 h ;
- la facturation refusée sans configuration Stripe, le refus du double abonnement, ainsi que le rejet des webhooks non signés, forgés ou rejoués.

Le back-office est couvert par `test/admin.test.mjs` (huit scénarios sur un serveur et une base temporaires) :

- la page servie sans session et l'absence de toute donnée avant authentification ;
- la politique de rôle au démarrage : un seul super-admin, jamais deux après une élévation accidentelle ;
- Ultra de droit sans abonnement ;
- l'absence de secret et de donnée personnelle dans les listes et les détails ;
- le refus des écritures sans rôle, sans jeton CSRF, sans raison ou visant un compte super-admin ;
- l'application effective des actions, avec un journal qui survit à la suppression du compte visé ;
- l'offre offerte : refus des offres inexistantes et des durées hors bornes, échéance conforme à la durée demandée, remplacement d'un accès précédent sans accumuler de lignes, refus sur un compte porteur d'un abonnement Stripe, et mention au journal de l'offre, de la durée et de l'offre précédente ;
- la double authentification : repli par mot de passe, activation par code confirmé, rejet d'un code rejoué, code de récupération à usage unique, et mention du facteur utilisé au journal.

La connexion Google est couverte par `test/oauth.test.mjs`, qui fait tourner un faux fournisseur sur une autre machine (sept scénarios) :

- le flux complet : aller, échange du code authentifié, lecture du profil, création d'un compte sans mot de passe, session ouverte et identité retrouvée sur le retour suivant, même quand l'adresse du fournisseur a changé ;
- le `state` : absent, différent, rejoué après effacement du cookie, code injecté sans échange préalable, refus de Google et code manquant ;
- les identités non prouvées (adresse non vérifiée, absente ou mal formée) et un fournisseur qui répond mal, sans secret dans le journal ;
- le refus de reprendre ou de lier un compte existant, et le fait qu'un compte sans mot de passe ne s'ouvre pas par `POST /api/auth/login` ;
- la destination de retour : un chemin du site est conservé, toute adresse extérieure est ramenée à la racine ;
- l'absence de configuration : `404 oauth_unavailable` et `googleEnabled: false` ;
- la migration d'une base d'avant la connexion Google : `password_hash` rendu facultatif, comptes conservés, références et index reposés, second démarrage sans effet.

## Passage en production

Avant une mise en ligne publique, ajouter au minimum :

1. HTTPS avec un certificat valide et un reverse proxy fiable.
2. Vérification des adresses e-mail et procédure de réinitialisation de mot de passe.
3. Sauvegardes chiffrées et politique de conservation des données.
4. Rate limiting partagé (Redis ou équivalent) si plusieurs instances Node.js sont utilisées.
5. Migration vers PostgreSQL et une gestion de clés/rotation si l’activité devient importante.
6. Une politique de modération des destinations et de suppression des comptes.

Le mode local fourni est sécurisé pour le développement et l’usage local, mais une exposition publique nécessite ces mesures d’exploitation supplémentaires.

## Licence

Code source publié pour consultation. **Tous droits réservés** — aucune licence
ouverte n’est accordée : la reproduction, la modification et la réutilisation du
code, en tout ou partie, sont interdites sans autorisation écrite préalable.

Projet en cours de développement, non achevé.
