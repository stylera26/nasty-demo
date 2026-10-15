// Vérification de bout en bout avec un faux relais SMTP et un faux Authentik : node test.mjs
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));

// Faux relais : enregistre le message reçu.
let mail = "";
const smtpPort = await listen(net.createServer((s) => {
  s.write("220 relais\r\n");
  let data = false;
  s.on("data", (d) => {
    for (const l of String(d).split("\r\n").filter(Boolean)) {
      if (data) { mail += l + "\n"; if (l === ".") { data = false; s.write("250 ok\r\n"); } continue; }
      if (l.startsWith("EHLO")) s.write("250-relais\r\n250 8BITMIME\r\n");
      else if (l === "DATA") { data = true; s.write("354 go\r\n"); }
      else if (l === "QUIT") s.end("221 bye\r\n");
      else s.write("250 ok\r\n");
    }
  });
}));

// Faux Authentik : découverte, jeton, profil (membre du groupe admin).
let iss;
const oidcPort = await listen(http.createServer((req, res) => {
  const u = new URL(req.url, iss);
  const json = (o) => res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(o));
  if (u.pathname.endsWith("openid-configuration")) return json({ authorization_endpoint: iss + "authorize", token_endpoint: iss + "token", userinfo_endpoint: iss + "userinfo" });
  if (u.pathname.endsWith("token")) return json({ access_token: "at", id_token: "idt" });
  if (u.pathname.endsWith("userinfo")) return json({ sub: "u1", email: "Admin@Ex.fr", email_verified: true, name: "Admin", groups: ["authentik Admins"] });
  res.writeHead(404).end();
}));
iss = `http://127.0.0.1:${oidcPort}/application/o/demo/`;

const env = { ...process.env, OIDC_ISSUER: iss, OIDC_CLIENT_ID: "demo", OIDC_CLIENT_SECRET: "x", SMTP_HOST: "127.0.0.1", SMTP_PORT: String(smtpPort), DATA_FILE: join(mkdtempSync(join(tmpdir(), "demo-")), "data.json"), PORT: "3999", APP_URL: "http://127.0.0.1:3999" };
const run = (args) => new Promise((ok, ko) => spawn("node", ["server.mjs", ...args], { env, stdio: "inherit", cwd: import.meta.dirname }).on("exit", (c) => (c ? ko(new Error("code " + c)) : ok())));

// 1. Invitation en ligne de commande.
await run(["invite", "paul@ex.fr", "éditeur"]);
assert.match(mail, /To: <paul@ex\.fr>/);
assert.match(Buffer.from(mail.split("base64\n")[1].replace(/\s|\./g, ""), "base64").toString(), /rôle « éditeur »/);

// 2. Connexion : /login → état, /callback → session admin, page d'accueil, invitation par le formulaire.
const app = spawn("node", ["server.mjs"], { env, stdio: "inherit", cwd: import.meta.dirname });
await new Promise((r) => setTimeout(r, 400));
const A = "http://127.0.0.1:3999";
try {
  let r = await fetch(A + "/login", { redirect: "manual" });
  const loc = new URL(r.headers.get("location"));
  assert.equal(loc.origin + loc.pathname, iss + "authorize");
  assert.equal(loc.searchParams.get("code_challenge_method"), "S256");
  const oidc = r.headers.get("set-cookie").split(";")[0];
  r = await fetch(`${A}/callback?code=c&state=${loc.searchParams.get("state")}`, { redirect: "manual", headers: { cookie: oidc } });
  const s = r.headers.getSetCookie().find((c) => c.startsWith("s=") && !c.startsWith("s=;")).split(";")[0];
  r = await fetch(A + "/", { headers: { cookie: s } });
  const html = await r.text();
  assert.match(html, /Bonjour Admin/);
  assert.match(html, /admin@ex\.fr/);
  assert.match(html, /Inviter quelqu/);
  // Sans Origin : refusé (CSRF).
  r = await fetch(A + "/invite", { method: "POST", redirect: "manual", headers: { cookie: s, "content-type": "application/x-www-form-urlencoded" }, body: "email=a@b.fr&role=membre" });
  assert.equal(r.status, 403);
  mail = "";
  r = await fetch(A + "/invite", { method: "POST", redirect: "manual", headers: { cookie: s, origin: A, "content-type": "application/x-www-form-urlencoded" }, body: "email=Marie@Ex.fr&role=membre" });
  assert.equal(r.headers.get("location"), "/?ok=marie%40ex.fr");
  assert.match(mail, /To: <marie@ex\.fr>/);
  // Membres et invitations gardés sur disque (redémarrage sans perte).
  const d = JSON.parse(readFileSync(env.DATA_FILE, "utf8"));
  assert.equal(new Map(d.invites).get("marie@ex.fr").role, "membre");
  assert.equal(new Map(d.members).get("u1").role, "admin");
  // Mauvais état : refusé.
  r = await fetch(`${A}/callback?code=c&state=autre`, { headers: { cookie: oidc } });
  assert.equal(r.status, 400);
  console.log("ok");
} finally {
  app.kill();
  process.exit(process.exitCode ?? 0);
}
