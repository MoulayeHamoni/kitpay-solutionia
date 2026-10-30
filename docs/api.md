# API REST

Base URL en local : `http://localhost:3000`
Base URL en prod : votre domaine, par exemple `https://kitpay.mon-domaine.com`.

Toutes les routes v1 attendent un header `Authorization: Bearer <api-key>`
au format `kp_test_...` (sandbox) ou `kp_live_...` (production).

Les reponses sont toujours en JSON. En cas d'erreur, le corps a la forme :

```json
{
  "error": {
    "code": "kyc_required",
    "message": "Live mode requires KYC validation. Use kp_test_ keys until your KYC is approved.",
    "param": "method"
  }
}
```

## POST /api/v1/intents

Cree un intent de paiement.

### Headers

| Header             | Valeur                       | Obligatoire | Description                                     |
|--------------------|------------------------------|-------------|-------------------------------------------------|
| Authorization      | Bearer kp_test_... / kp_live_... | oui     | Cle API.                                        |
| Content-Type       | application/json             | oui         |                                                 |
| Idempotency-Key    | chaine libre <= 255 chars    | non         | Rejoue la meme reponse pendant 24h si repete.   |

### Body

```json
{
  "amount": 5000,
  "method": "Bankily",
  "customer_phone": "46112233",
  "description": "Commande #1234",
  "success_url": "https://votre-site.com/kitpay/success",
  "cancel_url": "https://votre-site.com/kitpay/cancel",
  "metadata": {"order_id": "1234", "user_id": "abc"},
  "expires_in": 900
}
```

### `customer_phone` (string, requis)

Numero du client qui va envoyer le paiement, au format canonique 8 chiffres de Mauritanie (sans espaces, sans `+222`, sans tiret). Exemple : `"46112233"`.

Le serveur canonicalise automatiquement les variantes humaines a l'entree (strip des espaces, du `+222`, des tirets, des parentheses). Les formats accepts :
- `"46112233"` (canonique, 8 chiffres)
- `"+222 46 11 22 33"` (avec espaces et prefixe pays -- canonicalise cote serveur)
- `"+22246112233"` (sans espaces, avec prefixe)

Si vous stockez le numero chez vous, stockez la forme canonique a 8 chiffres : c'est celle qui est comparee au telephone extrait des SMS d'operateurs (qui sortent toujours en 8 chiffres).

| Champ                | Type                              | Obligatoire | Note                                           |
|----------------------|-----------------------------------|-------------|------------------------------------------------|
| amount               | entier positif (MRU)              | oui         | Entre 1 et 1 000 000.                         |
| method               | enum                              | oui         | `Bankily`, `Masrvi`, `Sedad`, `BIM`, `Click`, `BCIPAY` |
| customer_phone       | chaine                            | non         | Numero du payeur au format 8 chiffres (voir ci-dessus). Ameliore le matching Tier 1. |
| description          | chaine <= 255                     | non         | Affiche sur la page hosted et le recu email.   |
| success_url          | URL http(s)                       | non         | Redirection apres paiement reussi.             |
| cancel_url           | URL http(s)                       | non         | Redirection apres annulation ou expiration.    |
| metadata             | objet cle-valeur                  | non         | Renvoye tel quel dans les webhooks.            |
| expires_in           | entier (secondes) entre 60 et 3600 | non        | Defaut 900 (15 minutes).                       |
| merchant_operator_id | uuid                              | non         | Explicite le compte operateur a debiter (si plusieurs). |

### Reponse 201

```json
{
  "ref": "KP-A3F9X2",
  "amount": 5000,
  "method": "Bankily",
  "status": "pending",
  "mode": "live",
  "matched_tier": null,
  "merchant_phone": "+222 46 XX XX XX",
  "merchant_code": null,
  "customer_phone": "46112233",
  "description": "Commande #1234",
  "success_url": "https://votre-site.com/kitpay/success",
  "cancel_url": "https://votre-site.com/kitpay/cancel",
  "metadata": {"order_id": "1234"},
  "expires_at": "2026-09-22T16:30:00Z",
  "paid_at": null,
  "hosted_url": "https://kitpay.mon-domaine.com/pay/KP-A3F9X2",
  "client_secret": "kpcs_a1b2c3d4e5f6a1b2c3d4e5f6",
  "created_at": "2026-09-22T16:15:00Z"
}
```

Utiliser `hosted_url` pour rediriger le client. Utiliser `ref` pour tout
appel ulterieur.

### Codes d'erreur

| Code HTTP | Code interne           | Signification                                          |
|-----------|------------------------|--------------------------------------------------------|
| 401       | unauthorized           | Bearer manquant ou invalide.                           |
| 403       | kyc_required           | Mode live demande mais marchand pas encore KYC valide. |
| 409       | idempotency_conflict   | Idempotency-Key deja utilise avec un body different.   |
| 422       | missing_param, amount_too_low, unknown_method, no_operator_for_method, multiple_operators_specify_id, invalid_url | Erreur de validation. |
| 429       | rate_limit             | Trop d'appels. Voir header `X-RateLimit-Reset`.        |
| 500       | internal_error         | Erreur serveur.                                        |

### Exemple cURL

```bash
curl -X POST https://kitpay.mon-domaine.com/api/v1/intents \
  -H "Authorization: Bearer kp_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: order-1234" \
  -d '{
    "amount": 5000,
    "method": "Bankily",
    "success_url": "https://votre-site.com/kitpay/success?order=1234",
    "cancel_url": "https://votre-site.com/kitpay/cancel?order=1234",
    "metadata": {"order_id": "1234"}
  }'
```

## GET /api/v1/intents/{ref}

Recupere un intent par sa reference.

### Reponse 200

Meme shape que la reponse de `POST /v1/intents`, avec les champs
`status`, `matched_tier`, `paid_at` mis a jour.

### Exemple cURL

```bash
curl https://kitpay.mon-domaine.com/api/v1/intents/KP-A3F9X2 \
  -H "Authorization: Bearer kp_live_..."
```

## GET /api/v1/intents

Liste les intents du marchand (paginee).

### Query params

| Param          | Type            | Defaut | Note                             |
|----------------|-----------------|--------|----------------------------------|
| limit          | 1 <= n <= 100   | 25     | Nombre max d'intents retournes.  |
| status         | enum            | -      | Filtre par status.               |
| method         | enum            | -      | Filtre par methode de paiement.  |
| starting_after | ref             | -      | Cursor pour la pagination.       |

### Reponse 200

```json
{
  "data": [
    { "ref": "KP-A3F9X2", "amount": 5000, "status": "paid", ... },
    { "ref": "KP-B7C4Y8", "amount": 1200, "status": "pending", ... }
  ],
  "has_more": true,
  "next_cursor": "KP-B7C4Y8"
}
```

## POST /api/v1/intents/{ref}/cancel

Annule un intent pending. Retourne l'intent mis a jour avec
`status="cancelled"`. Ne fait rien si l'intent est deja terminal (paid,
expired, cancelled).

### Exemple cURL

```bash
curl -X POST https://kitpay.mon-domaine.com/api/v1/intents/KP-A3F9X2/cancel \
  -H "Authorization: Bearer kp_live_..."
```

## POST /api/v1/test/simulate-payment

Utile uniquement en mode test (`kp_test_*`). Simule la reception d'un
SMS et passe l'intent en `paid`, ce qui declenche aussi
`enqueue_webhook_delivery`.

### Body

```json
{ "ref": "KP-A3F9X2" }
```

### Reponse 200

L'intent mis a jour, `status="paid"`, `matched_tier=1`.

## Rate limiting

Chaque cle API a une limite par minute definie par le plan du marchand
(defaut : 60 appels par minute pour le plan free). Les headers de
reponse indiquent l'etat courant :

- `X-RateLimit-Limit` : plafond par minute.
- `X-RateLimit-Remaining` : appels restants dans la fenetre.
- `X-RateLimit-Reset` : secondes avant reinitialisation.

Depasser la limite renvoie `429 rate_limit`.

## Idempotence

Fournir un header `Idempotency-Key` unique par operation logique (par
exemple `order-1234`). Pendant 24h, tout POST avec la meme cle renvoie
la meme reponse. Si le body change avec la meme cle, l'API renvoie
`409 idempotency_conflict`.
