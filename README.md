# nasty-demo

Démo du **compte unique** : https://demo.sty.ovh. L'app demande à Authentik « qui est cette personne ? »
(OIDC, option Pilote `sso: {mode: oidc, public: true}`) ; Authentik gère connexion, inscription et MFA
obligatoire sur `compte.demo.sty.ovh` (flux `compte-*` de nas-authentik). Les rôles et les invitations
restent dans l'app (`app/server.mjs`, sans dépendance, comptes et invitations dans un fichier sur le volume `demo-data`).

- Test : `cd app && node test.mjs` (faux relais SMTP, faux Authentik), lancé aussi au build de l'image.
- Inviter sans l'interface : `kubectl -n demo exec deploy/demo -- node server.mjs invite <e-mail> [rôle]`.
- Admin de l'app = membre du groupe Authentik `authentik Admins`.

La CI annonce chaque build à Pilote (pilote.yml) : plus de webhook sur ce repo.
