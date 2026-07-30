# KINVOS License Server — Cloudflare Workers

Serveur central de gestion des licences pour tous vos logiciels (EasyClinic, EasyLaundry, Academia, ClassPro, etc.), conçu pour Cloudflare Workers + D1.

## Installation

```bash
npm install -g wrangler          # si pas déjà installé
wrangler login                   # connecte votre compte Cloudflare
```

## 1. Créer la base de données D1

```bash
npx wrangler d1 create kinvos-db
```

Cette commande affiche un `database_id`. Copiez-le dans `wrangler.toml`, à la place de `COLLEZ_ICI_L_ID_RENVOYE`.

## 2. Appliquer le schéma

```bash
npx wrangler d1 execute kinvos-db --remote --file=./migrations/0001_init.sql
```

## 3. Définir la clé d'administration (secret)

```bash
npx wrangler secret put ADMIN_API_KEY
```
Choisissez une clé longue et aléatoire — c'est celle que le tableau de bord utilisera dans l'en-tête `x-admin-key`.

## 4. Déployer

```bash
npx wrangler deploy
```

Wrangler vous donne une URL du type `https://kinvos-license-server.VOTRE-SOUS-DOMAINE.workers.dev`. C'est cette URL qu'il faut mettre :
- dans le tableau de bord (`license-manager-kinvos.html`) pour les appels admin
- dans chaque logiciel client (ex : `index.html` d'EasyClinic), à la place de `KINVOS_SERVEUR_URL`, en ajoutant `/api/verify` à la fin

## Tester en local avant de déployer

```bash
npx wrangler dev
```

## Routes admin (protégées — en-tête `x-admin-key: <votre clé>`)

| Méthode | Route | Description |
|---|---|---|
| GET | /api/admin/software | Liste des logiciels |
| POST | /api/admin/software | Ajouter un logiciel `{ name, code }` |
| DELETE | /api/admin/software/:id | Supprimer un logiciel |
| GET | /api/admin/licenses | Liste des licences (filtre `?software_id=`) |
| POST | /api/admin/licenses | Générer une licence `{ software_id, client_name, client_email, type, max_devices, price }` |
| POST | /api/admin/licenses/:id/renew | Renouveler une licence |
| POST | /api/admin/licenses/:id/toggle | Activer/désactiver une licence |
| DELETE | /api/admin/licenses/:id | Supprimer une licence |
| GET | /api/admin/clients | Liste des clients |

`type` accepte : `mensuel`, `annuel`, `vie`.

## Route publique — appelée par chaque logiciel client

```
POST /api/verify
Content-Type: application/json

{
  "license_key": "EL-A1B2-C3D4-E5F6",
  "device_fingerprint": "identifiant-unique-de-la-machine"
}
```

Réponses possibles :
```json
{ "valid": true, "type": "annuel", "expiration": "2027-07-30T10:00:00.000Z" }
{ "valid": false, "reason": "CLE_INCONNUE" }
{ "valid": false, "reason": "LICENCE_EXPIREE", "expiration": "..." }
{ "valid": false, "reason": "LICENCE_DEJA_UTILISEE", "max_devices": 1 }
{ "valid": false, "reason": "LICENCE_DESACTIVEE" }
```

## Ce qui n'est PAS encore inclus (à ajouter si besoin)

- Envoi automatique du code de licence par email ou WhatsApp
- Authentification admin avancée (actuellement : une seule clé API partagée)
- Statistiques de revenus détaillées, historique/logs d'activité
- Interface admin branchée dessus (le tableau de bord actuel utilise encore un stockage local — il faudra remplacer ses appels `window.storage` par des `fetch()` vers ces routes)
