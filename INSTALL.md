# INSTALL - KitPay SolutionIA

Guide pas a pas pour deployer une instance complete. Compter environ une
demi-journee, dont la moitie en attente (creation de compte Supabase,
propagation DNS, verification KYC operateur).

Toutes les commandes shell sont donnees pour bash. Sur Windows PowerShell,
adapter `openssl rand -hex 32` en `[Convert]::ToHexString((1..32 | %{Get-Random -Max 256}))`.

---

## 1. Prerequis

### Comptes a creer

- **Supabase** ([supabase.com](https://supabase.com)) - gratuit jusqu'a 500 Mo
  et 2 Go de trafic sortant par mois. Choisir la region `eu-central-1`
  (Francfort) pour la latence la plus faible avec la Mauritanie.
- **Netlify** ([netlify.com](https://netlify.com)) OU **Vercel**
  ([vercel.com](https://vercel.com)) - gratuit pour un projet
  hobby/personnel.
- **Resend** ([resend.com](https://resend.com)) - 3 000 emails gratuits par
  mois. Facultatif si vous n'envoyez pas de recus par email.
- **Telegram** - creer un bot via [@BotFather](https://t.me/BotFather).
  Facultatif si vous ne voulez pas de notifications internes.
- **cron-job.org** ([cron-job.org](https://cron-job.org)) - gratuit, un
  seul job requis. Ou n'importe quel autre scheduler externe.

### Materiel

- **Un telephone Android** avec une carte SIM Bankily/Masrvi active et le
  numero declare aupres de chaque operateur mobile money que vous voulez
  supporter. C'est ce telephone qui recevra les SMS de confirmation.
- **Une machine de dev** avec Node.js 18 ou plus, Git, et un editeur.

### Ce qu'il faut declarer aupres de chaque operateur

Pour chaque operateur (Bankily, Masrvi, BIM, Click, BCIPAY, Sedad), vous
devez etre inscrit en tant que **marchand accepteur** et disposer soit
d'un numero soit d'un code marchand. Sinon les paiements arriveront
comme un simple transfert entre personnes physiques et vous n'aurez pas
la meme fluidite pour le client.

---

## 2. Cloner et installer les dependances

```bash
git clone https://github.com/<your-user>/kitpay-solutionia.git
cd kitpay-solutionia
npm install
```

---

## 3. Creer le projet Supabase

1. Se connecter a [supabase.com](https://supabase.com), cliquer sur
   **New project**.
2. Nom : `kitpay` (peu importe, c'est interne).
3. Region : **Frankfurt (eu-central-1)**.
4. Mot de passe de la base : generer un mot de passe long, le noter dans
   un gestionnaire de mots de passe.
5. Attendre que le projet soit provisionne (2 a 3 minutes).

Une fois provisionne, aller dans **Settings > API** et noter :
- **Project URL** : `https://<PROJECT_REF>.supabase.co`
- **API keys** : cliquer sur **Reveal** pour la cle `sb_publishable_...`
  (utilisee cote client) et pour la cle `sb_secret_...` (service role,
  a garder secrete).

---

## 4. Appliquer les migrations SQL

Dans le dashboard Supabase, ouvrir **SQL Editor > New query**.

Copier et executer les fichiers du dossier `supabase/` **dans l'ordre
alphanumerique**, un par un :

```
schema.sql
migration_v2.sql
migration_v3_multitenant.sql
migration_v4_operator_names.sql
v5_apply_v3_v4_if_missing.sql
v6_supabase_auth_link.sql
v7_merchant_plans.sql
v8_merchant_members.sql
v9_merchant_operators.sql
v10_payment_intents_extras.sql
v11_idempotency_keys.sql
v12_api_audit_log.sql
v13_api_rate_limits.sql
v14_rls_enable.sql
v15_handle_new_user_trigger.sql
v16_match_payment_uses_operators.sql
v18_handle_new_user_v2.sql
v20_simplify_trigger.sql
v21_verify_api_key.sql
v22_enqueue_webhook_delivery.sql
v23_match_payment_with_webhook.sql
v24_expire_with_webhook.sql
v25_kyc_storage_policies.sql
v26_match_payment_bim.sql
v27_match_payment_masrvi.sql
v29_fix_match_order_lifo.sql
v30_match_payment_sedad.sql
v31_match_payment_click_natif.sql
v32_remove_bcipay.sql
v33_restrict_intent_anon_access.sql
v34_tier2_collision_guard.sql
v35_match_payment_bcipay.sql
v36_match_payment_bankily.sql
v37_lockdown_match_payment_rpcs.sql    (KP-SEC-2026-001)
v38_lockdown_remaining_rpcs.sql        (KP-SEC-2026-002)
v39_followup_bechar.sql                (KP-SEC-2026-003)  -- NOTE: superseded par v41 si vous installez de zero (v39 contient un bug window-function-in-HAVING qui avorte la transaction)
v40_ingest_hardening.sql               (KP-SEC-2026-004)
v41_round3_hardening.sql               (KP-SEC-2026-005)  -- supersede v39 pour les fresh installs
```

Les migrations v37 a v41 fixent des vulnerabilites de securite publiees dans SECURITY_ADVISORIES.md. **Elles doivent toutes etre appliquees.** Un deploy a partir de v36 reste expose aux CVE KP-SEC-2026-001 a 005.

Si vous installez a partir de zero (database vide), appliquez schema.sql + migration_v2 a v38 + v40 + v41 (dans cet ordre, en sautant v39 qui est casse). Si vous avez deja applique v39 (en pensant qu'elle avait reussi), rejouez v41 : elle est idempotente et re-ecrit tout ce que v39 n'a pas pu commiter.

> **Astuce** : chaque fichier se termine par un `SELECT '<vNN> applied' AS info`
> qui vous confirme le passage. Si un `RAISE NOTICE` s'affiche, lisez-le :
> il indique une action manuelle a faire.

Verifier a la fin :

```sql
SELECT count(*) FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'merchants','merchant_members','merchant_operators','merchant_plans',
    'api_keys','payment_intents','orphan_sms','webhooks',
    'webhook_deliveries','idempotency_keys','api_audit_log','api_rate_limits'
  );
-- doit retourner 12
```

Creer le bucket de stockage KYC :
- Aller dans **Storage** > **New bucket** > nom : `kyc-documents` > **Private**.
- Les policies sont deja creees par la migration v25.

Verifier que la chaine de securite v37-v41 est correctement appliquee :

```sql
-- Verification post-migration : les fonctions SECURITY DEFINER doivent toutes etre service_role-only
WITH fns AS (
  SELECT p.oid, p.proname||'/'||p.pronargs AS sig
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname='public' AND p.proname IN (
    'match_payment_bankily','match_payment_masrvi','match_payment_bim',
    'match_payment_sedad','match_payment_click','match_payment_bcipay',
    'enqueue_webhook_delivery','reconcile_orphan','verify_api_key','verify_forwarder_token'
  )
)
SELECT sig,
  has_function_privilege('anon', oid, 'EXECUTE') AS anon_can_execute,
  has_function_privilege('authenticated', oid, 'EXECUTE') AS auth_can_execute
FROM fns ORDER BY sig;
-- Expected: toutes les colonnes anon_can_execute et auth_can_execute = false.
-- Si vous voyez true quelque part, votre schema est mal verrouille -- ne demarrez pas en prod.
```

---

## 5. Configurer les variables d'environnement

Copier le fichier d'exemple :

```bash
cp .env.example .env.local
```

Remplir chaque variable dans `.env.local` :

### Supabase

- `NEXT_PUBLIC_SUPABASE_URL` : le Project URL note a l'etape 3.
- `NEXT_PUBLIC_SUPABASE_ANON_KEY` : la cle `sb_publishable_...`.
- `SUPABASE_SERVICE_ROLE_KEY` : la cle `sb_secret_...` (ne pas exposer
  au client).

### URL publique de l'application

- `NEXT_PUBLIC_APP_URL` : `http://localhost:3000` en dev, l'URL de
  production sinon (par exemple `https://kitpay.mon-domaine.com`).
- `NEXT_PUBLIC_SITE_URL` : identique.

### Marchand par defaut (affichage sur la home)

- `NEXT_PUBLIC_MERCHANT_PHONE` : facultatif, un numero de fallback pour
  la home page (jamais utilise pour un vrai paiement).
- `NEXT_PUBLIC_MERCHANT_NAME` : facultatif, un nom de fallback.

### Admin

- `ADMIN_PASSWORD` : generer un mot de passe fort
  (`openssl rand -hex 24`), le mettre en lieu sur. Utilise par les
  routes `/api/admin/*`.

### Resend (recus par email, facultatif)

- Creer un compte sur [resend.com](https://resend.com), aller dans
  **Settings > API Keys > Create API Key**.
- `RESEND_API_KEY` : la cle `re_...`.
- `RESEND_FROM` : `KitPay <onboarding@resend.dev>` fonctionne en test.
  Pour envoyer aux vrais clients, verifier un domaine dans Resend
  (**Domains**) puis mettre `KitPay <no-reply@mon-domaine.com>`.

### Telegram (notifications internes, facultatif)

- Parler a [@BotFather](https://t.me/BotFather) sur Telegram, envoyer
  `/newbot`, suivre les instructions, recuperer le token.
- Creer un canal Telegram prive, ajouter le bot comme admin.
- Envoyer un premier message dans le canal, puis appeler
  `https://api.telegram.org/bot<TOKEN>/getUpdates` et recuperer
  `chat.id` (un nombre negatif commencant par `-100...`).
- `TELEGRAM_BOT_TOKEN` : le token du bot.
- `TELEGRAM_CHAT_ID` : le `chat.id` recupere.

### Secrets pour endpoints machine-to-machine

Generer trois chaines aleatoires longues :

```bash
openssl rand -hex 32   # WEBHOOK_SECRET
openssl rand -hex 32   # CRON_SECRET
```

- `WEBHOOK_SECRET` : protege `POST /api/sms-ingest`. Sera envoye par
  l'application Android de forwarding SMS dans le header
  `x-webhook-secret`.
- `CRON_SECRET` : protege `POST /api/cron/*`. Sera envoye par le
  scheduler externe (cron-job.org) dans le header `x-cron-secret` ou en
  query param `?secret=...`.

---

## 6. Lancer en local pour verifier

```bash
npm run dev
```

Ouvrir `http://localhost:3000`. La home page doit s'afficher.

Aller sur `http://localhost:3000/signup`, creer un compte avec votre
email pro. Vous allez recevoir un magic link.

**Important** : ouvrir le magic link dans le **meme navigateur** que
celui ou vous avez lance le signup. Sinon la session PKCE est cassee.

Une fois connecte, vous serez redirige vers `/onboarding/merchant`.
Remplir les 4 etapes (identite, contact, premier operateur,
recapitulatif). A la fin, vous atterrissez sur `/dashboard`.

Pour obtenir le role super_admin (utile pour valider vos propres KYC),
retourner dans Supabase SQL Editor et executer :

```sql
UPDATE auth.users
SET raw_app_meta_data = COALESCE(raw_app_meta_data, '{}'::jsonb) || '{"role":"super_admin"}'::jsonb
WHERE email = 'votre@email.pro';
```

Se deconnecter et se reconnecter pour que le role prenne effet.

---

## 7. Deployer sur Netlify ou Vercel

### Netlify

1. `git init`, commiter le repo, pusher sur GitHub.
2. Sur Netlify, **Add new site > Import an existing project > GitHub**.
3. Selectionner le repo.
4. Build settings : Next.js est detecte automatiquement (le fichier
   `netlify.toml` fait le reste).
5. Dans **Site settings > Environment variables**, ajouter toutes les
   variables de `.env.local` (sans les valeurs de dev, mettre les
   valeurs de prod).
6. Deploy.

### Vercel

1. `vercel` dans le repo, suivre les instructions.
2. Ajouter les variables d'environnement via
   `vercel env add <NAME> production`.
3. `vercel --prod`.

Une fois deploye, noter l'URL publique (par exemple
`https://kitpay-solutionia.netlify.app`). C'est cette URL qui va servir
pour le forwarder SMS et le cron externe.

Optionnel : brancher un domaine personnalise, mettre a jour
`NEXT_PUBLIC_APP_URL` et `NEXT_PUBLIC_SITE_URL` en consequence.

---

## 8. Configurer le forwarder SMS sur le telephone marchand

Voir le guide complet dans [docs/android-setup.md](./docs/android-setup.md).

Resume rapide (avec l'application SMS Forwarder de Bogdan Tudose) :

- Installer l'app.
- Pour chaque operateur, creer une regle avec :
  - Filtre expediteur : `Bankily`, `BMCI` (pour Masrvi), `BIM`,
    `Click`, `Sedad`, `BCIPAY`.
  - URL cible : `https://<votre-domaine>/api/sms-ingest`.
  - Methode : `POST`.
  - Headers : `Authorization: Bearer kpf_<token copie depuis le dashboard>` et
    `Content-Type: application/json`.
  - Le token se cree dans `Dashboard -> Forwarders -> Nouveau forwarder`.
  - Body : `{"from": "%from%", "sms_body": "%text%"}`.
- Autoriser la lecture des SMS et desactiver l'optimisation batterie
  pour l'application.
- Brancher le telephone en permanence sur secteur et WiFi.

---

## 9. Brancher le cron externe pour la livraison des webhooks

Aller sur [cron-job.org](https://cron-job.org), creer un compte gratuit,
puis **Create cronjob** :

- **Title** : `KitPay deliver webhooks`
- **URL** : `https://<votre-domaine>/api/cron/deliver-webhooks?secret=<VOTRE CRON_SECRET>`
- **Schedule** : Every 30 seconds (ou 1 minute si votre plan gratuit ne
  permet pas 30s).
- **Notifications** : envoyer un mail en cas d'echec pendant plus de
  10 minutes.
- **Save**.

Repeter pour les deux autres crons :

- `POST /api/cron/expire-intents?secret=<CRON_SECRET>` toutes les 5 minutes.
- `POST /api/cron/finalize-pending?secret=<CRON_SECRET>` toutes les
  10 minutes.

Alternative : si vous etes sur Netlify Pro, utiliser les
[Scheduled Functions](https://docs.netlify.com/functions/scheduled-functions/).
Si vous etes sur Vercel Pro, utiliser les
[Cron Jobs](https://vercel.com/docs/cron-jobs).

---

## 10. Test de bout en bout (10 MRU)

1. **Ajouter un operateur** : dans `/dashboard/operators`, cliquer sur
   "Ajouter", choisir un operateur (par exemple Bankily), saisir le
   numero de votre telephone marchand.

2. **Creer une API key test** : dans `/dashboard/api-keys`, cliquer sur
   "Creer une cle", mode `test`. Copier la cle affichee (`kp_test_...`)
   dans un endroit sur - elle ne sera plus jamais affichee.

3. **Creer un intent** :

```bash
curl -X POST https://<votre-domaine>/api/v1/intents \
  -H "Authorization: Bearer kp_test_..." \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 10,
    "method": "Bankily",
    "description": "Test end-to-end"
  }'
```

Reponse attendue :

```json
{
  "ref": "KP-A3F9X2",
  "amount": 10,
  "method": "Bankily",
  "status": "pending",
  "hosted_url": "https://<votre-domaine>/pay/KP-A3F9X2",
  "client_secret": "kpcs_...",
  "expires_at": "...",
  ...
}
```

4. **Ouvrir la hosted_url** dans un navigateur. Vous devez voir la page
   "Payer via Bankily" avec le numero de votre telephone marchand.

5. **Envoyer un vrai paiement Bankily** de 10 MRU depuis un autre
   telephone vers votre telephone marchand.

6. **Verifier** : dans les 5 a 10 secondes, la page hosted doit basculer
   sur "Paiement recu". Dans `/dashboard/intents`, l'intent doit etre
   passe en `paid` avec `matched_tier: 1` ou `2`.

Si oui, l'installation est terminee. Bravo.

---

## 11. Depannage

### Le SMS n'est pas detecte

1. Verifier dans l'application forwarder que le SMS a bien ete envoye
   (icone verte dans l'historique).
2. Verifier les logs Netlify/Vercel : chercher `sms-ingest`. Une
   reponse `401 unauthorized` = token Bearer invalide ou absent (verifier le header `Authorization: Bearer kpf_<token>` dans le forwarder). Une reponse
   `parse_failed` = format SMS non reconnu par le parser.
3. Verifier dans Supabase la table `orphan_sms` : si le SMS y est, la
   ligne aura le contenu brut, ce qui aide a debugger le parser.
4. Verifier le nom exact de l'expediteur SMS sur le telephone : parfois
   c'est `BIM Bank` au lieu de `BIM`, ou `MASRVI` au lieu de `BMCI`.
   Adapter le filtre dans le forwarder.

### Format d'expediteur different selon l'operateur

C'est un piege connu. Cette section resume ce qui est parsable :

- **Bankily** : l'expediteur peut etre `Bankily` ou `Click` (les SMS
  passent par GIMTEL). Le parseur declenche si le corps contient
  `(BANKILY)`.
- **Masrvi** : l'expediteur est `BMCI`, pas `Masrvi`. Le parseur
  declenche sur `f.includes("bmci")` OU la presence de
  `pour la facture` dans le corps.
- **Sedad** : l'expediteur reel est `BMI`, mais le forwarder doit
  envoyer `from=Sedad` manuellement (via le champ "Sender" du
  forwarder) sinon le parser ne se declenche pas.
- **BCIPAY** vs **BIM** : le meme format SMS, mais le parser distingue
  par l'expediteur (`BIM` sans `BCI` -> BIM, sinon -> BCIPAY).

Voir [docs/operators.md](./docs/operators.md) pour tous les details.

### Le webhook n'arrive pas chez le marchand

1. Verifier dans `/dashboard/webhooks/<id>` la liste des livraisons.
   Statut `pending` : le cron n'a pas encore tourne. Statut `failed` :
   voir `http_status` et `response_body`.
2. Verifier les logs du cron `/api/cron/deliver-webhooks` : chercher
   les erreurs `network_error` ou les codes HTTP retournes par votre
   endpoint marchand.
3. Verifier que le CRON_SECRET est bien passe (`?secret=...` ou header
   `x-cron-secret`). Une reponse `401 unauthorized` signifie que le
   secret ne correspond pas.
4. Verifier que votre endpoint marchand repond avec un code 2xx en
   moins de 10 secondes (timeout du worker).

### Fuseau horaire

Toutes les timestamps sont en UTC dans Postgres. Si les intents
expirent trop tot ou trop tard :

1. Verifier `NEXT_PUBLIC_APP_URL` et le fuseau du serveur.
2. `expires_at` est calcule cote serveur en UTC : `now() + expires_in`.
3. Le cron `/api/cron/expire-intents` compare aussi en UTC : pas de
   probleme de fuseau si `now()` est bien en UTC.

### Le telephone Android se met en veille et ne forwarde plus

C'est le piege le plus frequent en prod :

1. Desactiver l'optimisation batterie pour l'application forwarder :
   **Parametres > Batterie > Optimisation > Non optimise** pour SMS
   Forwarder.
2. Brancher le telephone en permanence sur secteur.
3. WiFi ou 4G en continu (pas de mode economie d'energie).
4. Optionnel : installer une application "keep alive" comme
   [Wakey](https://play.google.com/store/apps/details?id=com.doublep.wakey)
   ou activer "Ne pas mettre en veille" dans les options developpeur.
5. Configurer un monitoring externe (uptimerobot.com gratuit) qui
   verifie toutes les 5 minutes que `POST /api/sms-ingest` repond, et
   qui vous alerte par email en cas de panne.

### Bug PKCE sur le magic link admin

Si vous cliquez sur le magic link et vous obtenez `otp_expired` ou une
erreur d'authentification :

- Le magic link Supabase utilise le flow PKCE qui stocke un
  `code_verifier` cote client. Ouvrir le lien dans un autre navigateur
  ou en navigation privee casse le flow.
- Solution : cliquer sur le magic link dans le meme navigateur que
  celui ou vous avez lance le `/signup`.
- Solution alternative : dans Supabase > Authentication > Users,
  cliquer sur votre user > Send password reset, puis definir un mot de
  passe et se connecter avec email + password.

### Autres problemes

Consulter les [issues GitHub](https://github.com/<your-user>/kitpay-solutionia/issues)
ou en ouvrir une nouvelle en incluant :
- La version de KitPay SolutionIA (commit hash).
- Les logs pertinents (sans secrets).
- Les etapes exactes pour reproduire.
