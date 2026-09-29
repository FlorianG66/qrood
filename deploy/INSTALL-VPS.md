# Mise en production de QROOD (VPS OVH)

Guide pas à pas, prévu pour un VPS **OVH sous Debian/Ubuntu**. Le kit se trouve
dans le dossier `deploy/` : `Caddyfile`, `qrood.env`, `qrood.service`,
`backup.sh`.

Temps total : ~45 minutes. Avant de commencer, s'assurer de trois accès :

- le **VPS** (user root ou sudo) ;
- le tableau de bord **Stripe** (mode live) ;
- l'API **Resend** (ou un service mail acceptant `{from, to, subject, text}`
  avec une clé Bearer, comme Brevo).

---

## 1. DNS (OVH) — à faire en premier, propagation parfois lente

1. Tableau de bord OVH → **Domaine** → votre domaine → onglet **Zone DNS**.
2. **Ajouter un enregistrement** : type `A`, sous-domaine vide (`@`), cible =
   **adresse IPv4 du VPS** (visible dans l'espace client, onglet serveur).
3. Vérifier la propagation : `dig +short qrood.fr` doit renvoyer l'IP
   du VPS. Tant que ce n'est pas le cas, Caddy ne peut pas délivrer de
   certificat HTTPS.

> ⚠️ **Le nom de domaine est gravé dans chaque QR code à la création.**
> Utiliser exactement le même nom partout (`https://qrood.fr`).

## 2. Node.js 22 sur le VPS

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version   # doit être 22.13 ou plus (sinon il faut --experimental-sqlite)
```

## 3. Code et dépendances

```bash
sudo useradd -r -s /usr/sbin/nologin qrood
sudo mkdir -p /opt/qrood
cd /tmp && git clone https://github.com/FlorianG66/qrood.git qrood && sudo chown -R qrood:qrood qrood
sudo mv qrood /opt/qrood
cd /opt/qrood && sudo -u qrood npm install --omit=dev
```

## 4. Stripe : basculer en mode live et créer l'offre

1. **Mettre le compte en live** : bouton **« Activer le paiement » / Go live**
   (compte déjà configuré → c'est un simple basculement).
2. **Produits** → **Ajouter un produit** (2 fois) :
   - Pro : montant **12,00** EUR, récurrent **mensuel**,
     **« Les taxes sont incluses dans le prix » (inclusive)** ;
   - Ultra : **29,00** EUR, récurrent mensuel, taxes incluses.
   - Noter l'ID de chaque tarif (`price_live_…`).
   - ⚠️ Sur Stripe le montant est saisi en euros (12,00 / 29,00) mais stocké
     en centimes (`unit_amount` 1200 / 2900) : ne pas confondre avec le
     centième.
3. **Developers → Clés API** : copier la clé secrète publiable `sk_live_…`.
4. **Developers → Webhooks → Ajouter un endpoint** :
   URL `https://qrood.fr/api/billing/stripe/webhook`.
   Événements : `checkout.session.completed`, `customer.subscription.created`,
   `customer.subscription.updated`, `customer.subscription.deleted`.
   Copier le **secret de signature** `whsec_live_…`.
5. **Réglages → Taxe** : ajouter l'inscription du pays (**FR**) si les
   factures doivent montrer la TVA (uniquement si l'entreprise est assujettie).

## 5. E-mail (Resend)

1. Créer un compte **resend.com** (gratuit pour démarrer), **API Keys** → créer
   une clé `re_…`.
2. Pour démarrer immédiatement, `QROOD_MAIL_FROM` peut être
   **`onboarding@resend.dev`** (aucune vérification de domaine nécessaire).
3. Plus tard, vérifier son domaine chez Resend (un enregistrement DNS) et
   passer à `no-reply@qrood.fr`.

## 6. Fichier de configuration

```bash
sudo cp /opt/qrood/deploy/qrood.env /etc/qrood.env
sudo nano /etc/qrood.env   # remplacer toutes les valeurs <...>
```

## 7. Caddy (HTTPS automatique)

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
sudo cp /opt/qrood/deploy/Caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile   # vérifier le nom de domaine qrood.fr
sudo systemctl reload caddy
sudo systemctl enable caddy
```

## 8. Service QROOD

```bash
sudo cp /opt/qrood/deploy/qrood.service /etc/systemd/system/qrood.service
sudo systemctl daemon-reload
sudo systemctl enable --now qrood
journalctl -u qrood -f   # la ligne « qrood server listening on https://… » confirme le démarrage
```

## 9. Vérifications avant publication

```bash
curl -fsS https://qrood.fr/api/health            # 200 OK
curl -fsS https://qrood.fr/api/billing/offers     # 3 offres, pro/ultra en EUR
```
Puis un vrai parcours : création de compte → e-mail de confirmation reçu →
création d'un QR → achat avec la carte test `4242 4242 4242 4242`.

## 10. Sauvegardes

```bash
crontab -e
```
```cron
0 3 * * * /opt/qrood/deploy/backup.sh >/dev/null
```

- `QROOD_IDLE_TIMEOUT_MINUTES=0` (déjà dans `qrood.env`) désactive l'arrêt par
  inactivité ; le service ne meurt plus de lui-même, et `Restart=always`
  le relance en moins de 3 s en cas de pépin.
- `backup.sh` produit un instantané cohérent (sauvegarde SQLite compatible
  WAL), conservé 14 jours.