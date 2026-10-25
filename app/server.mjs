// Démo du compte unique : connexion par Authentik (OIDC, MFA imposé par Authentik), rôles et invitations
// gérés par l'app. Aucune dépendance : http, crypto, net et fetch de Node.
//   node server.mjs                       → serveur sur :3000
// Livré par « bump dans la MR » (ci-templates v1.1.0, BUMP: mr) : image et digest arrivent sur main dans le même commit.
//   node server.mjs invite <e-mail> [rôle] → envoie un mail d'invitation (sans passer par l'interface)
// Variables : OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, APP_URL, SMTP_HOST, SMTP_PORT, MAIL_FROM, ADMIN_GROUP,
// DATA_FILE (membres, invitations et clé de session ; sans elle, tout reste en mémoire).
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";

const env = process.env;
const ISSUER = (env.OIDC_ISSUER ?? "").replace(/\/?$/, "/");
const APP = (env.APP_URL ?? "https://demo.sty.ovh").replace(/\/$/, "");
const ADMIN_GROUP = env.ADMIN_GROUP ?? "authentik Admins";
const ROLES = ["membre", "éditeur", "admin"];
// ponytail: un fichier JSON réécrit à chaque changement (démo, 1 réplique) ; une vraie app prend une base.
const FILE = env.DATA_FILE;
const saved = FILE && existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : {};
const SECRET = Buffer.from(saved.secret ?? randomBytes(32).toString("base64"), "base64");
const members = new Map(saved.members); // sub → {email, name, role, since, via}
const invites = new Map(saved.invites); // e-mail → {role, by, at}
function save() {
  if (!FILE) return;
  writeFileSync(FILE + ".tmp", JSON.stringify({ secret: SECRET.toString("base64"), members: [...members], invites: [...invites] }));
  renameSync(FILE + ".tmp", FILE); // jamais de fichier à moitié écrit
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const b64u = (b) => Buffer.from(b).toString("base64url");
const EMAIL = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[a-z]{2,}$/i;

// ── Session : cookie signé (HMAC), 8 h ──────────────────────────────────────
const sign = (v) => b64u(createHmac("sha256", SECRET).update(v).digest());
function setCookie(res, name, value, maxAge) {
  const v = value === null ? "" : `${b64u(JSON.stringify(value))}.${sign(b64u(JSON.stringify(value)))}`;
  res.appendHeader("Set-Cookie", `${name}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${value === null ? 0 : maxAge}`);
}
function getCookie(req, name) {
  const raw = (req.headers.cookie ?? "").split(/;\s*/).find((c) => c.startsWith(name + "="))?.slice(name.length + 1);
  const [v, s] = (raw ?? "").split(".");
  if (!v || !s || s.length !== sign(v).length || !timingSafeEqual(Buffer.from(s), Buffer.from(sign(v)))) return null;
  const d = JSON.parse(Buffer.from(v, "base64url").toString());
  return d.exp > Date.now() ? d : null;
}

// ── OIDC (code + PKCE) ──────────────────────────────────────────────────────
let disco;
const discovery = async () => (disco ??= await (await fetch(ISSUER + ".well-known/openid-configuration")).json());

async function login(res, signup) {
  const d = await discovery();
  const state = b64u(randomBytes(16)), verifier = b64u(randomBytes(32));
  setCookie(res, "oidc", { state, verifier, exp: Date.now() + 15 * 60_000 }, 900);
  const q = new URLSearchParams({
    response_type: "code", client_id: env.OIDC_CLIENT_ID, redirect_uri: APP + "/callback", scope: "openid email profile", state,
    code_challenge: b64u(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256",
  });
  const authorize = new URL(d.authorization_endpoint);
  // Inscription : le flux compte-signup, puis retour sur l'autorisation (même hôte, chemin relatif).
  const to = signup ? `${authorize.origin}/if/flow/compte-signup/?next=${encodeURIComponent(authorize.pathname + "?" + q)}` : `${authorize}?${q}`;
  res.writeHead(302, { Location: to }).end();
}

async function callback(req, res, url) {
  const c = getCookie(req, "oidc");
  setCookie(res, "oidc", null);
  if (!c || url.searchParams.get("state") !== c.state) return page(res, 400, "<p>Connexion expirée : recommencez.</p>");
  const d = await discovery();
  const tok = await fetch(d.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + Buffer.from(`${env.OIDC_CLIENT_ID}:${env.OIDC_CLIENT_SECRET}`).toString("base64") },
    body: new URLSearchParams({ grant_type: "authorization_code", code: url.searchParams.get("code") ?? "", redirect_uri: APP + "/callback", code_verifier: c.verifier }),
  }).then((r) => r.json());
  if (!tok.access_token) return page(res, 401, `<p>Connexion refusée : ${esc(tok.error_description ?? tok.error)}</p>`);
  // Profil lu sur l'issuer (TLS) avec le jeton : pas de vérification de signature à faire ici.
  const u = await fetch(d.userinfo_endpoint, { headers: { Authorization: "Bearer " + tok.access_token } }).then((r) => r.json());
  if (!u.sub) return page(res, 401, "<p>Profil illisible.</p>");
  const email = String(u.email ?? "").toLowerCase();
  const m = members.get(u.sub) ?? { email, name: u.name, role: "membre", since: new Date().toISOString(), via: "inscription libre" };
  const inv = u.email_verified !== false && invites.get(email); // rôle d'invitation seulement sur e-mail vérifié
  if (inv) Object.assign(m, { role: inv.role, via: `invité par ${inv.by}` }), invites.delete(email);
  if ((u.groups ?? []).includes(ADMIN_GROUP)) m.role = "admin";
  Object.assign(m, { email, name: u.name });
  members.set(u.sub, m);
  save();
  setCookie(res, "s", { sub: u.sub, idt: tok.id_token, exp: Date.now() + 8 * 3600_000 }, 8 * 3600);
  res.writeHead(302, { Location: "/" }).end();
}

// ── Mail par le relais nas-smtp (sans auth, réseau du cluster) ──────────────
function smtp(to, subject, text) {
  return new Promise((resolve, reject) => {
    const s = net.connect(Number(env.SMTP_PORT ?? 587), env.SMTP_HOST ?? "smtp.smtp.svc.cluster.local");
    const from = env.MAIL_FROM ?? "noreply@sty.ovh";
    const steps = [
      `EHLO demo`, `MAIL FROM:<${from}>`, `RCPT TO:<${to}>`, "DATA",
      [`From: =?UTF-8?B?${Buffer.from("Démo Nasty").toString("base64")}?= <${from}>`,
        `To: <${to}>`, `Subject: =?UTF-8?B?${Buffer.from(subject).toString("base64")}?=`, `Date: ${new Date().toUTCString()}`,
        `Message-ID: <${randomBytes(12).toString("hex")}@sty.ovh>`, "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: base64", "", Buffer.from(text).toString("base64").replace(/.{76}/g, "$&\r\n"), "."].join("\r\n"),
      "QUIT",
    ];
    let buf = "";
    s.setTimeout(15_000, () => s.destroy(new Error("relais SMTP : délai dépassé")));
    s.on("error", reject);
    s.on("data", (d) => {
      buf += d;
      const lines = buf.split("\r\n");
      const last = lines.at(-2);
      if (!last || !/^\d{3} /.test(last)) return; // réponse incomplète (ou multiligne en cours)
      buf = "";
      if (!/^[23]/.test(last)) return s.destroy(new Error("relais SMTP : " + last));
      const next = steps.shift();
      if (next) s.write(next + "\r\n");
      else (s.end(), resolve());
    });
  });
}

const inviteText = (email, role, by) => `Bonjour,

${by} vous invite sur la démo Nasty, avec le rôle « ${role} ».

Pour rejoindre : ${APP}/?invitation=${encodeURIComponent(email)}

Créez votre compte avec cette adresse (${email}) ou connectez-vous si vous en avez déjà un.
Une double authentification vous sera demandée : empreinte, visage, clé physique ou code à 6 chiffres.

— Démo Nasty
`;

// ── Pages ───────────────────────────────────────────────────────────────────
const CSS = `:root{--bg:#f5f7f6;--card:#fff;--fg:#1b2420;--mut:#5d6b65;--line:#dde3df;--acc:#1d6b55;--soft:#e2efe9;--bad:#a3312c}
@media (prefers-color-scheme:dark){:root{--bg:#121715;--card:#1a211e;--fg:#e4ebe7;--mut:#9aaaa2;--line:#2c3632;--acc:#5cc4a2;--soft:#1d3029;--bad:#ef8a83}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:760px;margin:0 auto;padding:40px 16px;display:grid;gap:20px}h1{margin:0;font-size:1.8rem}h2{margin:0 0 8px;font-size:1.1rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px}.mut{color:var(--mut)}
.btn{display:inline-block;background:var(--acc);color:var(--bg);border:0;border-radius:8px;padding:10px 16px;font:600 15px system-ui;text-decoration:none;cursor:pointer}
.btn.alt{background:none;color:var(--acc);border:1px solid var(--acc)}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
table{width:100%;border-collapse:collapse;font-size:.93rem}td,th{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line)}th{color:var(--mut);font-weight:500}
input,select{font:inherit;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}input{flex:1;min-width:200px}
code{font-size:.85em;background:var(--soft);padding:1px 5px;border-radius:4px;word-break:break-all}.tag{background:var(--soft);color:var(--acc);border-radius:10px;padding:1px 8px;font-size:.85rem}
.ok{color:var(--acc)}.err{color:var(--bad)}`;

function page(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'", "X-Frame-Options": "DENY" });
  res.end(`<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Démo Nasty</title><style>${CSS}</style><main>${body}</main></html>`);
}

function home(req, res, url) {
  const s = getCookie(req, "s"), m = s && members.get(s.sub);
  if (!m) {
    const inv = url.searchParams.get("invitation");
    return page(res, 200, `<h1>Démo Nasty</h1>
<p class="mut">Une app comme une autre : elle demande à Authentik « qui est cette personne ? » et gère elle-même les rôles.</p>
${inv ? `<div class="card"><b>Vous êtes invité.</b> <span class="mut">Créez votre compte avec ${esc(inv)}, ou connectez-vous si vous en avez déjà un.</span></div>` : ""}
<div class="row"><a class="btn" href="/login">Se connecter</a><a class="btn alt" href="/signup">Créer un compte</a></div>`);
  }
  const msg = url.searchParams.get("ok") ? `<p class="ok">Invitation envoyée à ${esc(url.searchParams.get("ok"))}.</p>` : url.searchParams.get("err") ? `<p class="err">${esc(url.searchParams.get("err"))}</p>` : "";
  const admin = m.role === "admin";
  return page(res, 200, `<div class="row" style="justify-content:space-between"><h1>Bonjour ${esc(m.name || m.email)}</h1><a class="btn alt" href="/logout">Se déconnecter</a></div>
<div class="card"><h2>Ce que l'app reçoit d'Authentik</h2><table>
<tr><th>Identifiant (sub)</th><td><code>${esc(s.sub)}</code></td></tr><tr><th>E-mail</th><td>${esc(m.email)}</td></tr><tr><th>Nom</th><td>${esc(m.name)}</td></tr>
<tr><th>Rôle dans l'app</th><td><span class="tag">${esc(m.role)}</span> <span class="mut">(${esc(m.via)})</span></td></tr></table></div>
${admin ? `<div class="card"><h2>Inviter quelqu'un</h2>${msg}<form method="post" action="/invite" class="row">
<input type="email" name="email" id="email" required placeholder="paul@exemple.fr" aria-label="E-mail">
<select name="role" id="role" aria-label="Rôle">${ROLES.map((r) => `<option>${r}</option>`).join("")}</select><button class="btn">Envoyer</button></form>
<p class="mut" style="margin:10px 0 0">Le rôle est donné à la première connexion avec cette adresse, une fois vérifiée par Authentik.</p></div>
<div class="card"><h2>Membres (${members.size})</h2><table><tr><th>Nom</th><th>E-mail</th><th>Rôle</th></tr>
${[...members.values()].map((x) => `<tr><td>${esc(x.name)}</td><td>${esc(x.email)}</td><td>${esc(x.role)}</td></tr>`).join("")}</table>
${invites.size ? `<h2 style="margin-top:16px">Invitations en attente</h2><table>${[...invites].map(([e, i]) => `<tr><td>${esc(e)}</td><td>${esc(i.role)}</td><td class="mut">par ${esc(i.by)}</td></tr>`).join("")}</table>` : ""}</div>`
    : `<p class="mut">Seuls les admins de l'app peuvent inviter.</p>`}`);
}

async function invite(req, res) {
  const s = getCookie(req, "s"), m = s && members.get(s.sub);
  if (!m || m.role !== "admin" || req.headers.origin !== APP) return page(res, 403, "<p>Réservé aux admins de l'app.</p>");
  let body = "";
  for await (const c of req) if ((body += c).length > 2000) return page(res, 413, "<p>Trop long.</p>");
  const f = new URLSearchParams(body), email = (f.get("email") ?? "").trim().toLowerCase(), role = f.get("role") ?? "";
  if (!EMAIL.test(email) || !ROLES.includes(role)) return res.writeHead(303, { Location: "/?err=" + encodeURIComponent("E-mail ou rôle invalide.") }).end();
  try {
    await smtp(email, "Invitation à la démo Nasty", inviteText(email, role, m.name || m.email));
    invites.set(email, { role, by: m.name || m.email, at: Date.now() });
    save();
    res.writeHead(303, { Location: "/?ok=" + encodeURIComponent(email) }).end();
  } catch (e) {
    console.error(e.message);
    res.writeHead(303, { Location: "/?err=" + encodeURIComponent("Envoi impossible : " + e.message) }).end();
  }
}

async function logout(req, res) {
  const s = getCookie(req, "s");
  setCookie(res, "s", null);
  const d = await discovery().catch(() => ({}));
  const end = d.end_session_endpoint && s?.idt ? `${d.end_session_endpoint}?${new URLSearchParams({ id_token_hint: s.idt, post_logout_redirect_uri: APP + "/" })}` : "/";
  res.writeHead(302, { Location: end }).end();
}

if (process.argv[2] === "invite") {
  const [, , , to, role = "membre"] = process.argv;
  if (!EMAIL.test(to ?? "") || !ROLES.includes(role)) throw new Error("usage : node server.mjs invite <e-mail> [membre|éditeur|admin]");
  await smtp(to, "Invitation à la démo Nasty", inviteText(to, role, "L'équipe Nasty"));
  console.log("invitation envoyée à", to);
} else {
  http.createServer(async (req, res) => {
    const url = new URL(req.url, APP);
    try {
      if (req.method === "GET" && url.pathname === "/") return home(req, res, url);
      if (req.method === "GET" && url.pathname === "/login") return await login(res, false);
      if (req.method === "GET" && url.pathname === "/signup") return await login(res, true);
      if (req.method === "GET" && url.pathname === "/callback") return await callback(req, res, url);
      if (req.method === "GET" && url.pathname === "/logout") return await logout(req, res);
      if (req.method === "POST" && url.pathname === "/invite") return await invite(req, res);
      if (url.pathname === "/healthz") return res.end("ok");
      page(res, 404, "<p>Page introuvable.</p>");
    } catch (e) {
      console.error(e);
      if (!res.headersSent) page(res, 500, "<p>Erreur : réessayez.</p>");
    }
  }).listen(Number(env.PORT ?? 3000), () => console.log("démo sur", env.PORT ?? 3000));
}
