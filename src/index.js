// ====== RÉGLAGES FEDAPAY (à remplir) ======
const FEDAPAY_SECRET_KEY = "";   // collez ici votre clé secrète FedaPay (sk_sandbox_... ou sk_live_...)
const FEDAPAY_MODE = "sandbox";  // "sandbox" = test, "live" = vrais paiements
const HUB_PUBLIC_URL = "";       // laissez vide : le hub utilise l'adresse /hub de ce Worker

// ====== OPTIONS (laissez vide pour désactiver) ======
const RESEND_API_KEY = "";      // envoi d'emails aux clients (compte gratuit sur resend.com)
const MAIL_FROM = "KinvosHub <onboarding@resend.dev>"; // remplacez par un expéditeur de VOTRE domaine vérifié
const ADMIN_EMAIL = "";         // email qui reçoit l'alerte de chaque vente
const TELEGRAM_BOT_TOKEN = "";  // alertes de vente sur Telegram
const TELEGRAM_CHAT_ID = "";
// ==========================================

// Serveur central de licences — Les Logiciels Easy (KINVOS GROUP)
// Cloudflare Workers + D1

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, x-admin-key",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function uid() {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase();
}

function genLicenseKey(code) {
  const seg = () => crypto.randomUUID().replace(/-/g, "").slice(0, 4).toUpperCase();
  return `${code}-${seg()}-${seg()}-${seg()}`;
}

function addDuration(dateIso, type, durationDays) {
  const d = new Date(dateIso);
  if (type === "mensuel") d.setMonth(d.getMonth() + 1);
  else if (type === "annuel") d.setFullYear(d.getFullYear() + 1);
  else if (type === "jours") d.setTime(d.getTime() + (Number(durationDays) || 0) * 86400000);
  else return null; // vie
  return d.toISOString();
}

function requireAdmin(request, env) {
  const key = request.headers.get("x-admin-key");
  return key && env.ADMIN_API_KEY && key === env.ADMIN_API_KEY;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      // ---------- Route publique : vérification de licence ----------
      if (path === "/api/verify" && method === "POST") {
        return await handleVerify(request, env);
      }

      // ---------- Routes publiques du hub d'achat ----------
      if (method === "GET" && (path === "/hub" || path === "/hub/")) return htmlPage(HUB_HTML);
      if (method === "GET" && path === "/hub/admin") return htmlPage(HUB_ADMIN_HTML);
      if (path.startsWith("/api/hub/")) await ensureHubTables(env);
      if (path === "/api/hub/catalog" && method === "GET") return await hubCatalog(env);
      if (path === "/api/hub/promo" && method === "POST") return await hubPromoPreview(request, env);
      if (path === "/api/hub/recover" && method === "POST") return await hubRecover(request, env);
      if (path === "/api/hub/orders" && method === "POST") {
        return await hubCreateOrder(request, env);
      }
      const hubOrder = path.match(/^\/api\/hub\/orders\/([0-9a-f-]{36})$/);
      if (hubOrder && method === "GET") {
        return await hubGetOrder(env, hubOrder[1]);
      }
      if (path === "/api/hub/webhook" && method === "POST") {
        return await hubWebhook(request, env);
      }

      // ---------- Admin du hub : propriétaire ou agents ----------
      if (path.startsWith("/api/admin/hub-")) {
        await ensureHubTables(env);
        const who = await hubWho(request, env);
        if (!who) return json({ error: "Non autorisé" }, 401);
        return await handleHubAdmin(request, env, path, method, who);
      }

      // ---------- Routes admin : protégées par x-admin-key ----------
      if (path.startsWith("/api/admin/")) {
        if (!requireAdmin(request, env)) {
          return json({ error: "Non autorisé" }, 401);
        }
        return await handleAdmin(request, env, path, method);
      }

      if (path === "/" || path === "") {
        return json({ status: "ok", service: "kinvos-license-server" });
      }

      return json({ error: "Route introuvable" }, 404);
    } catch (err) {
      return json({ error: "Erreur serveur", details: String(err) }, 500);
    }
  },
};

// ============ Vérification (route publique) ============
async function handleVerify(request, env) {
  const body = await request.json().catch(() => ({}));
  const { license_key, device_fingerprint } = body;

  if (!license_key || !device_fingerprint) {
    return json({ valid: false, reason: "PARAMETRES_MANQUANTS" });
  }

  const lic = await env.DB.prepare("SELECT * FROM licenses WHERE license_key = ?")
    .bind(license_key).first();

  if (!lic) return json({ valid: false, reason: "CLE_INCONNUE" });
  if (lic.status === "disabled") return json({ valid: false, reason: "LICENCE_DESACTIVEE" });
  if (lic.expiration && new Date(lic.expiration) < new Date()) {
    return json({ valid: false, reason: "LICENCE_EXPIREE", expiration: lic.expiration });
  }

  const existingDevice = await env.DB.prepare(
    "SELECT * FROM devices WHERE license_id = ? AND device_fingerprint = ?"
  ).bind(lic.id, device_fingerprint).first();

  if (!existingDevice) {
    const countRow = await env.DB.prepare(
      "SELECT COUNT(*) as n FROM devices WHERE license_id = ?"
    ).bind(lic.id).first();

    if (countRow.n >= lic.max_devices) {
      return json({ valid: false, reason: "LICENCE_DEJA_UTILISEE", max_devices: lic.max_devices });
    }

    const now = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO devices (id, license_id, device_fingerprint, activated_at, last_seen_at) VALUES (?,?,?,?,?)"
    ).bind(uid(), lic.id, device_fingerprint, now, now).run();
  } else {
    await env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), existingDevice.id).run();
  }

  return json({ valid: true, type: lic.type, expiration: lic.expiration });
}

// ============ Routes admin ============
async function handleAdmin(request, env, path, method) {
  const parts = path.replace("/api/admin/", "").split("/").filter(Boolean);
  const resource = parts[0]; // software | licenses | clients
  const id = parts[1];
  const action = parts[2]; // renew | toggle

  // ---------- Logiciels ----------
  if (resource === "software") {
    if (method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT * FROM software ORDER BY created_at DESC"
      ).all();
      return json(results);
    }
    if (method === "POST") {
      const { name, code } = await request.json();
      if (!name || !code) return json({ error: "name et code requis" }, 400);
      const newId = uid();
      await env.DB.prepare(
        "INSERT INTO software (id, name, code, created_at) VALUES (?,?,?,?)"
      ).bind(newId, name, code.toUpperCase(), new Date().toISOString()).run();
      return json({ id: newId, name, code: code.toUpperCase() }, 201);
    }
    if (method === "DELETE" && id) {
      await env.DB.prepare("DELETE FROM devices WHERE license_id IN (SELECT id FROM licenses WHERE software_id = ?)").bind(id).run();
      await env.DB.prepare("DELETE FROM licenses WHERE software_id = ?").bind(id).run();
      await env.DB.prepare("DELETE FROM software WHERE id = ?").bind(id).run();
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
  }

  // ---------- Licences ----------
  if (resource === "licenses") {
    if (method === "GET") {
      const softwareId = new URL(request.url).searchParams.get("software_id");
      const stmt = softwareId
        ? env.DB.prepare("SELECT * FROM licenses WHERE software_id = ? ORDER BY created_at DESC").bind(softwareId)
        : env.DB.prepare("SELECT * FROM licenses ORDER BY created_at DESC");
      const { results } = await stmt.all();
      return json(results);
    }

    if (method === "POST" && !id) {
      const { software_id, client_name, client_email, type, max_devices, price, duration_days } = await request.json();
      const sw = await env.DB.prepare("SELECT * FROM software WHERE id = ?").bind(software_id).first();
      if (!sw) return json({ error: "Logiciel introuvable" }, 404);

      let clientId = null;
      if (client_email) {
        const existing = await env.DB.prepare("SELECT * FROM clients WHERE email = ?").bind(client_email).first();
        if (existing) {
          clientId = existing.id;
        } else {
          clientId = uid();
          await env.DB.prepare(
            "INSERT INTO clients (id, name, email, created_at) VALUES (?,?,?,?)"
          ).bind(clientId, client_name || null, client_email, new Date().toISOString()).run();
        }
      }

      const now = new Date().toISOString();
      const newId = uid();
      const key = genLicenseKey(sw.code);
      const expiration = addDuration(now, type, duration_days);

      await env.DB.prepare(`INSERT INTO licenses
        (id, software_id, client_id, license_key, type, price, max_devices, status, expiration, created_at, duration_days)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
        .bind(newId, software_id, clientId, key, type, price || 0, max_devices || 1, "active", expiration, now, duration_days || null)
        .run();

      return json({ id: newId, key, expiration }, 201);
    }

    if (method === "POST" && id && action === "renew") {
      const lic = await env.DB.prepare("SELECT * FROM licenses WHERE id = ?").bind(id).first();
      if (!lic) return json({ error: "Licence introuvable" }, 404);
      const base = lic.expiration && new Date(lic.expiration) > new Date() ? lic.expiration : new Date().toISOString();
      const expiration = addDuration(base, lic.type, lic.duration_days);
      await env.DB.prepare("UPDATE licenses SET status = 'active', expiration = ? WHERE id = ?").bind(expiration, id).run();
      return json({ expiration });
    }

    if (method === "POST" && id && action === "toggle") {
      const lic = await env.DB.prepare("SELECT * FROM licenses WHERE id = ?").bind(id).first();
      if (!lic) return json({ error: "Licence introuvable" }, 404);
      const next = lic.status === "disabled" ? "active" : "disabled";
      await env.DB.prepare("UPDATE licenses SET status = ? WHERE id = ?").bind(next, id).run();
      return json({ status: next });
    }

    if (method === "DELETE" && id) {
      await env.DB.prepare("DELETE FROM devices WHERE license_id = ?").bind(id).run();
      await env.DB.prepare("DELETE FROM licenses WHERE id = ?").bind(id).run();
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
  }

  // ---------- Clients ----------
  if (resource === "clients" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM clients ORDER BY created_at DESC").all();
    return json(results);
  }

  return json({ error: "Route admin introuvable" }, 404);
}


// ============ Hub d'achat : commandes et paiement ============
// Prix fixés ICI, côté serveur : on ne fait jamais confiance au prix envoyé par le navigateur.
const HUB_PLANS = {
  "1an":  { label: "1 an",     price: 11000, type: "annuel", days: null },
  "3ans": { label: "3 ans",    price: 22000, type: "jours",  days: 1095 },
  "5ans": { label: "5 ans",    price: 33000, type: "jours",  days: 1825 },
  "vie":  { label: "Illimité", price: 62000, type: "vie",    days: null },
};
const HUB_MAX_DEVICES = 1;      // appareils autorisés par licence achetée sur le hub
const FCFA_PER_EUR = 655.957;   // le champ "prix" des licences est en euros

async function hubCreateOrder(request, env) {
  const b = await request.json().catch(() => ({}));
  const plan = HUB_PLANS[b.plan];
  const code = String(b.software_code || "").toUpperCase();
  const name = String(b.client_name || "").trim().slice(0, 120);
  const email = String(b.client_email || "").trim().toLowerCase().slice(0, 200);
  const phone = String(b.client_phone || "").trim().slice(0, 40);

  if (!plan) return json({ error: "Durée invalide" }, 400);
  const cfg = await getHubConfig(env);
  if (!cfg.open) return json({ error: "Les achats sont temporairement fermés" }, 403);
  if (!cfg.products.some((p) => p.code === code && p.on)) return json({ error: "Logiciel indisponible" }, 404);
  const prod = cfg.products.find((p) => p.code === code);
  const base = prod.prices && prod.prices[b.plan] > 0 ? Math.round(prod.prices[b.plan]) : cfg.plans[b.plan].price;
  let price, discount = 0, promo = null;
  try { const r = await applyPromo(env, b.promo, base); price = r.price; discount = r.discount; promo = r.code; }
  catch (e) { return json({ error: e.message }, 400); }  if (name.length < 2 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || phone.replace(/\D/g, "").length < 8) {
    return json({ error: "Nom, email et téléphone valides requis" }, 400);
  }

  const sw = await env.DB.prepare("SELECT id, name, code FROM software WHERE code = ?").bind(code).first();
  if (!sw) return json({ error: "Logiciel indisponible" }, 404);

  const id = crypto.randomUUID(); // identifiant long : impossible à deviner
  await env.DB.prepare(
    `INSERT INTO hub_orders
     (id, software_code, plan, amount_fcfa, client_name, client_email, client_phone, status, created_at, promo_code, discount_fcfa)
     VALUES (?,?,?,?,?,?,?,'pending',?,?,?)`
  ).bind(id, sw.code, b.plan, price, name, email, phone, new Date().toISOString(), promo, discount).run();

  if (price <= 0) { // 100 % de réduction : pas de paiement, licence tout de suite
    const free = await env.DB.prepare("SELECT * FROM hub_orders WHERE id = ?").bind(id).first();
    await fulfillOrder(env, free);
    return json({ order_id: id, amount: 0, status: "paid", payment: null }, 201);
  }

  let payment;
  try {
    payment = await createGatewayPayment(env, {
      order_id: id, origin: new URL(request.url).origin, amount: price, name, email, phone, software: sw.name, plan: plan.label,
    });
  } catch (err) {
    await env.DB.prepare("UPDATE hub_orders SET status = 'failed' WHERE id = ?").bind(id).run();
    return json({ error: "Paiement momentanément indisponible, réessayez." }, 502);
  }
  return json({ order_id: id, amount: price, status: "pending", payment }, 201);
}

async function loadHubOrder(env, id) {
  return await env.DB.prepare(
    `SELECT o.*, s.name AS software_name FROM hub_orders o
     LEFT JOIN software s ON s.code = o.software_code WHERE o.id = ?`
  ).bind(id).first();
}

async function hubGetOrder(env, id) {
  let o = await loadHubOrder(env, id);
  if (!o) return json({ error: "Commande introuvable" }, 404);

  // Commande en attente : on demande directement à FedaPay si le paiement est approuvé.
  if (o.status === "pending" && o.payment_ref) {
    try {
      if (await confirmGatewayPayment(env, o)) {
        await fulfillOrder(env, o);
        o = await loadHubOrder(env, id);
      }
    } catch (e) { /* on réessaiera au prochain appel */ }
  }

  const out = {
    status: o.status,
    software: o.software_name,
    plan: HUB_PLANS[o.plan] ? HUB_PLANS[o.plan].label : o.plan,
    amount: o.amount_fcfa,
  };
  if (o.status === "paid") {
    out.license_key = o.license_key;
    out.expiration = o.expiration;
  }
  return json(out);
}

// Notification FedaPay (secours : le hub vérifie aussi lui-même en interrogeant le serveur).
// On ne croit jamais le contenu reçu : on redemande l'état de la transaction à FedaPay.
async function hubWebhook(request, env) {
  const payload = await request.json().catch(() => ({}));
  const txId = (payload.entity && payload.entity.id) || (payload.object && payload.object.id) || (payload.data && payload.data.id);
  if (!txId) return json({ received: true, confirmed: false });
  const order = await env.DB.prepare("SELECT * FROM hub_orders WHERE payment_ref = ?").bind(String(txId)).first();
  if (!order) return json({ received: true, confirmed: false });
  const ok = await confirmGatewayPayment(env, order);
  if (ok) await fulfillOrder(env, order);
  return json({ received: true, confirmed: !!ok });
}

// ---- Passerelle FedaPay ----
// Secrets/variables du Worker : FEDAPAY_SECRET_KEY (secret), FEDAPAY_ENV ("sandbox" ou "live"), HUB_URL (adresse de la page du hub)
function fedapayBase(env) {
  return fpMode(env) === "live" ? "https://api.fedapay.com/v1" : "https://sandbox-api.fedapay.com/v1";
}

async function fedapay(env, method, path, body) {
  const res = await fetch(fedapayBase(env) + path, {
    method,
    headers: { Authorization: "Bearer " + fpKey(env), "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// FedaPay peut envelopper l'objet ({"v1/transaction": {...}}) : on le déballe.
function fedapayTx(data) {
  return (data && (data["v1/transaction"] || data.transaction)) || data;
}

async function createGatewayPayment(env, order) {
  if (!fpKey(env)) return { mode: "manual" }; // pas de clé : mode test manuel

  const parts = order.name.split(/\s+/);
  const firstname = parts[0];
  const lastname = parts.slice(1).join(" ") || firstname;
  const body = {
    description: order.software + " - " + order.plan,
    amount: order.amount,
    currency: { iso: "XOF" },
    custom_metadata: { order_id: order.order_id },
  };
  const back = env.HUB_URL || HUB_PUBLIC_URL || (order.origin + "/hub");
  body.callback_url = back + (back.includes("?") ? "&" : "?") + "order=" + order.order_id;

  let r = await fedapay(env, "POST", "/transactions", {
    ...body, customer: { firstname, lastname, email: order.email },
  });
  if (!r.ok) r = await fedapay(env, "POST", "/transactions", body); // nouvel essai sans fiche client
  const tx = fedapayTx(r.data);
  if (!r.ok || !tx || !tx.id) throw new Error("FedaPay : création refusée (" + r.status + ")");

  const t = await fedapay(env, "POST", "/transactions/" + tx.id + "/token");
  const tok = (t.data && t.data["v1/token"]) || t.data;
  if (!t.ok || !tok || !tok.url) throw new Error("FedaPay : lien de paiement non généré");

  await env.DB.prepare("UPDATE hub_orders SET payment_ref = ? WHERE id = ?")
    .bind(String(tx.id), order.order_id).run();
  return { mode: "fedapay", url: tok.url };
}

// true uniquement si FedaPay confirme : transaction approuvée ET montant identique.
async function confirmGatewayPayment(env, order) {
  if (!fpKey(env) || !order.payment_ref) return false;
  const r = await fedapay(env, "GET", "/transactions/" + order.payment_ref);
  if (!r.ok) return false;
  const tx = fedapayTx(r.data);
  return !!tx && tx.status === "approved" && Number(tx.amount) === Number(order.amount_fcfa);
}

// Crée la licence une seule fois par commande, puis la rattache à la commande.
async function fulfillOrder(env, order) {
  if (order.status === "paid") return;
  const claim = await env.DB.prepare(
    "UPDATE hub_orders SET status = 'processing' WHERE id = ? AND status = 'pending'"
  ).bind(order.id).run();
  if (!claim.meta || claim.meta.changes !== 1) return; // déjà en cours ou traitée

  try {
    const plan = HUB_PLANS[order.plan];
    const sw = await env.DB.prepare("SELECT * FROM software WHERE code = ?").bind(order.software_code).first();
    if (!plan || !sw) throw new Error("Commande invalide");

    let clientId;
    const existing = await env.DB.prepare("SELECT * FROM clients WHERE email = ?").bind(order.client_email).first();
    if (existing) {
      clientId = existing.id;
    } else {
      clientId = uid();
      await env.DB.prepare("INSERT INTO clients (id, name, email, created_at) VALUES (?,?,?,?)")
        .bind(clientId, order.client_name, order.client_email, new Date().toISOString()).run();
    }

    const now = new Date().toISOString();
    const licId = uid();
    const key = genLicenseKey(sw.code);
    const expiration = addDuration(now, plan.type, plan.days);
    const priceEur = Math.round((order.amount_fcfa / FCFA_PER_EUR) * 100) / 100;
    const maxDev = (await getHubConfig(env)).max_devices;

    await env.DB.prepare(`INSERT INTO licenses
      (id, software_id, client_id, license_key, type, price, max_devices, status, expiration, created_at, duration_days)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(licId, sw.id, clientId, key, plan.type, priceEur, maxDev, "active", expiration, now, plan.days)
      .run();

    await env.DB.prepare(
      "UPDATE hub_orders SET status = 'paid', paid_at = ?, license_id = ?, license_key = ?, expiration = ? WHERE id = ?"
    ).bind(now, licId, key, expiration, order.id).run();
    try { if (order.promo_code) await env.DB.prepare("UPDATE hub_promos SET uses = uses + 1 WHERE code = ?").bind(order.promo_code).run(); } catch (e) {}
    try { await afterSale(env, order, key, expiration); } catch (e) {}
  } catch (err) {
    await env.DB.prepare("UPDATE hub_orders SET status = 'pending' WHERE id = ?").bind(order.id).run();
    throw err;
  }
}


function fpKey(env) { return env.FEDAPAY_SECRET_KEY || FEDAPAY_SECRET_KEY; }
function fpMode(env) { return (env.FEDAPAY_ENV || FEDAPAY_MODE) === "live" ? "live" : "sandbox"; }
function htmlPage(html) {
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

// Logiciels proposés par défaut sur le hub (modifiables ensuite dans l'espace admin).
// EasySkill et EasyPharma sont désactivés tant qu'ils n'existent pas dans le serveur de licences.
const HUB_DEFAULT_PRODUCTS = [
  { code: "A",  t: "École Primaire",      nom: "Academia",            e: "📚", on: true },
  { code: "AS", t: "École Secondaire",    nom: "Academia Secondaire", e: "🎓", on: true },
  { code: "SK", t: "Centre de Formation", nom: "EasySkill",           e: "👨‍🏫", on: false },
  { code: "EH", t: "Hôtel",               nom: "EasyHotel",           e: "🏨", on: true },
  { code: "EF", t: "Restaurant",          nom: "EasyFood",            e: "🍽️", on: true },
  { code: "ES", t: "Stock",               nom: "EasyStock",           e: "📦", on: true },
  { code: "EC", t: "Clinique",            nom: "EasyClinic",          e: "🏥", on: true },
  { code: "EP", t: "Pharmacie",           nom: "EasyPharma",          e: "💊", on: false },
  { code: "EL", t: "Blanchisserie",       nom: "EasyLaundry",         e: "🧺", on: true },
];

let hubReady = false;
async function ensureHubTables(env) {
  if (hubReady) return;
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS hub_orders (
    id TEXT PRIMARY KEY, software_code TEXT NOT NULL, plan TEXT NOT NULL, amount_fcfa INTEGER NOT NULL,
    client_name TEXT, client_email TEXT, client_phone TEXT, status TEXT NOT NULL DEFAULT 'pending',
    payment_ref TEXT, license_id TEXT, license_key TEXT, expiration TEXT, created_at TEXT NOT NULL, paid_at TEXT)`).run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS hub_settings (key TEXT PRIMARY KEY, value TEXT)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS hub_promos (code TEXT PRIMARY KEY, kind TEXT, value INTEGER, max_uses INTEGER DEFAULT 0, uses INTEGER DEFAULT 0, expires_at TEXT, active INTEGER DEFAULT 1, created_at TEXT)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS hub_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, who TEXT, action TEXT, detail TEXT)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS hub_staff (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT, role TEXT, created_at TEXT)").run();
  for (const col of ["promo_code TEXT", "discount_fcfa INTEGER DEFAULT 0"]) {
    try { await env.DB.prepare("ALTER TABLE hub_orders ADD COLUMN " + col).run(); } catch (e) { /* déjà présente */ }
  }
  hubReady = true;
}

async function getHubConfig(env) {
  const row = await env.DB.prepare("SELECT value FROM hub_settings WHERE key = 'config'").first();
  let saved = {};
  try { saved = row ? JSON.parse(row.value) : {}; } catch (e) {}
  const plans = {};
  for (const k of Object.keys(HUB_PLANS)) {
    const p = saved.plans && saved.plans[k];
    plans[k] = { label: HUB_PLANS[k].label, price: p && p.price > 0 ? Math.round(p.price) : HUB_PLANS[k].price };
  }
  return {
    open: saved.open !== false,
    max_devices: saved.max_devices > 0 ? Math.round(saved.max_devices) : HUB_MAX_DEVICES,
    plans,
    texts: Object.assign({ whatsapp: "", email: "", terms: "" }, saved.texts || {}),
    products: Array.isArray(saved.products) && saved.products.length ? saved.products : HUB_DEFAULT_PRODUCTS,
  };
}

async function publicHubConfig(env) {
  const cfg = await getHubConfig(env);
  cfg.fedapay = { configured: !!fpKey(env), mode: fpMode(env) };
  cfg.services = { email: !!RESEND_API_KEY, telegram: !!(TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) };
  return cfg;
}

async function saveHubConfig(env, b) {
  const products = (Array.isArray(b.products) ? b.products : []).slice(0, 60).map((p) => ({
    code: String(p.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8),
    nom: String(p.nom || "").slice(0, 60),
    t: String(p.t || p.nom || "").slice(0, 60),
    e: String(p.e || "📦").slice(0, 8),
    on: !!p.on,
    prices: Object.fromEntries(Object.entries(p.prices || {}).filter(([k, v]) => HUB_PLANS[k] && Number(v) > 0).map(([k, v]) => [k, Math.round(Number(v))])),
  })).filter((p) => p.code && p.nom);
  const cfg = { open: b.open !== false, max_devices: Number(b.max_devices) || 1, plans: b.plans || {}, products,
    texts: { whatsapp: String((b.texts || {}).whatsapp || "").slice(0, 20), email: String((b.texts || {}).email || "").slice(0, 120), terms: String((b.texts || {}).terms || "").slice(0, 6000) } };
  await env.DB.prepare(
    "INSERT INTO hub_settings (key, value) VALUES ('config', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).bind(JSON.stringify(cfg)).run();
}

async function hubCatalog(env) {
  const cfg = await getHubConfig(env);
  return json({
    open: cfg.open,
    texts: cfg.texts,
    products: cfg.products.filter((p) => p.on).map((p) => ({ code: p.code, nom: p.nom, t: p.t, e: p.e, prices: p.prices || {} })),
    plans: Object.keys(cfg.plans).map((k) => ({ id: k, label: cfg.plans[k].label, price: cfg.plans[k].price })),
  });
}

// ---------- Codes promo ----------
async function applyPromo(env, raw, price) {
  const code = String(raw || "").trim().toUpperCase();
  if (!code) return { price, discount: 0, code: null };
  const p = await env.DB.prepare("SELECT * FROM hub_promos WHERE code = ?").bind(code).first();
  const ok = p && p.active && (!p.max_uses || p.uses < p.max_uses) && (!p.expires_at || new Date(p.expires_at + "T23:59:59Z") > new Date());
  if (!ok) throw new Error("Code promo invalide ou expiré");
  const d = p.kind === "percent" ? Math.round((price * Math.min(p.value, 100)) / 100) : Math.min(p.value, price);
  return { price: price - d, discount: d, code };
}

async function hubPromoPreview(request, env) {
  const b = await request.json().catch(() => ({}));
  const cfg = await getHubConfig(env);
  const prod = cfg.products.find((p) => p.code === String(b.software_code || "").toUpperCase() && p.on);
  if (!prod || !cfg.plans[b.plan]) return json({ error: "Choix invalide" }, 400);
  const base = prod.prices && prod.prices[b.plan] > 0 ? Math.round(prod.prices[b.plan]) : cfg.plans[b.plan].price;
  try { const r = await applyPromo(env, b.promo, base); return json({ price: r.price, discount: r.discount }); }
  catch (e) { return json({ error: e.message }, 400); }
}

// ---------- Emails et alertes ----------
const escH = (t) => String(t == null ? "" : t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY || !to) return false;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + RESEND_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html }),
    });
    return r.ok;
  } catch (e) { return false; }
}

async function sendCodeMail(env, order, key, expiration) {
  const sw = await env.DB.prepare("SELECT name FROM software WHERE code = ?").bind(order.software_code).first();
  const name = sw ? sw.name : order.software_code;
  const plan = HUB_PLANS[order.plan] ? HUB_PLANS[order.plan].label : order.plan;
  const html = "<p>Bonjour " + escH(order.client_name) + ",</p><p>Voici votre code d'accès pour <b>" + escH(name) + "</b> (" + escH(plan) + ") :</p>" +
    '<p style="font-size:22px;font-family:monospace"><b>' + escH(key) + "</b></p><p>Valable " +
    (expiration ? "jusqu'au " + new Date(expiration).toLocaleDateString("fr-FR") : "sans limite de durée") +
    ".</p><p>Saisissez ce code dans votre logiciel pour l'activer.</p>";
  return await sendEmail(order.client_email, "Votre code d'accès " + name, html);
}

async function afterSale(env, order, key, expiration) {
  await sendCodeMail(env, order, key, expiration);
  const txt = "Nouvelle vente KinvosHub : " + order.software_code + " (" + order.plan + ") — " + order.amount_fcfa + " FCFA — " + order.client_name;
  if (ADMIN_EMAIL) await sendEmail(ADMIN_EMAIL, "Nouvelle vente KinvosHub", "<p>" + escH(txt) + "</p>");
  if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
    try {
      await fetch("https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: txt }),
      });
    } catch (e) {}
  }
}

const recoverAt = new Map();
async function hubRecover(request, env) {
  const b = await request.json().catch(() => ({}));
  const email = String(b.email || "").trim().toLowerCase();
  if (!RESEND_API_KEY) return json({ error: "Service email non activé : contactez l'assistance." }, 503);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "Email invalide" }, 400);
  const now = Date.now();
  if (now - (recoverAt.get(email) || 0) < 60000) return json({ error: "Patientez une minute avant de réessayer." }, 429);
  recoverAt.set(email, now);
  const { results } = await env.DB.prepare(
    "SELECT * FROM hub_orders WHERE client_email = ? AND status = 'paid' ORDER BY created_at DESC LIMIT 10"
  ).bind(email).all();
  for (const o of results) await sendCodeMail(env, o, o.license_key, o.expiration);
  return json({ ok: true });
}

// ---------- Accès : propriétaire (clé admin) ou agents ----------
async function sha256(t) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function hubWho(request, env) {
  const key = request.headers.get("x-admin-key");
  if (!key) return null;
  if (env.ADMIN_API_KEY && key === env.ADMIN_API_KEY) return { name: "Propriétaire", role: "owner" };
  const st = await env.DB.prepare("SELECT name, role FROM hub_staff WHERE key_hash = ?").bind(await sha256(key)).first();
  return st ? { name: st.name, role: st.role } : null;
}
async function audit(env, who, action, detail) {
  try {
    await env.DB.prepare("INSERT INTO hub_audit (at, who, action, detail) VALUES (?,?,?,?)")
      .bind(new Date().toISOString(), who.name, action, String(detail || "").slice(0, 300)).run();
  } catch (e) {}
}

async function handleHubAdmin(request, env, path, method, who) {
  const parts = path.replace("/api/admin/", "").split("/").filter(Boolean);
  const resource = parts[0], id = parts[1], action = parts[2];
  const owner = who.role === "owner";
  const deny = () => json({ error: "Réservé au propriétaire" }, 403);
  const body = async () => await request.json().catch(() => ({}));

  if (resource === "hub-config") {
    if (method === "POST") {
      if (!owner) return deny();
      await saveHubConfig(env, await body());
      await audit(env, who, "Catalogue / réglages enregistrés", "");
    }
    const cfg = await publicHubConfig(env);
    cfg.me = who;
    return json(cfg);
  }

  if (resource === "hub-orders") {
    if (method === "GET" && !id) {
      const { results } = await env.DB.prepare(
        `SELECT o.*, s.name AS software_name, l.status AS license_status FROM hub_orders o
         LEFT JOIN software s ON s.code = o.software_code
         LEFT JOIN licenses l ON l.id = o.license_id
         ORDER BY o.created_at DESC LIMIT 2000`
      ).all();
      return json(results);
    }
    if (method === "POST" && id === "verify-all") {
      const { results } = await env.DB.prepare(
        "SELECT * FROM hub_orders WHERE status = 'pending' AND payment_ref IS NOT NULL ORDER BY created_at DESC LIMIT 30"
      ).all();
      let confirmed = 0;
      for (const o of results) {
        try { if (await confirmGatewayPayment(env, o)) { await fulfillOrder(env, o); confirmed++; } } catch (e) {}
      }
      await audit(env, who, "Vérification des paiements en attente", confirmed + " confirmé(s)");
      return json({ checked: results.length, confirmed });
    }
    const order = id ? await env.DB.prepare("SELECT * FROM hub_orders WHERE id = ?").bind(id).first() : null;
    if (!order) return json({ error: "Commande introuvable" }, 404);
    if (method === "POST") {
      if (action === "verify") {
        let ok = false;
        if (order.status === "pending") { ok = await confirmGatewayPayment(env, order); if (ok) await fulfillOrder(env, order); }
        const fresh = await env.DB.prepare("SELECT status FROM hub_orders WHERE id = ?").bind(id).first();
        await audit(env, who, "Vérification FedaPay", id.slice(0, 8) + " → " + fresh.status);
        return json({ status: fresh.status });
      }
      if (action === "resend") {
        if (order.status !== "paid") return json({ error: "Commande non payée" }, 400);
        const sent = await sendCodeMail(env, order, order.license_key, order.expiration);
        await audit(env, who, "Code renvoyé", order.client_email + (sent ? "" : " (email non configuré)"));
        return json({ sent, key: order.license_key });
      }
      if (!owner) return deny();
      if (action === "confirm") {
        await fulfillOrder(env, order);
        const fresh = await env.DB.prepare("SELECT * FROM hub_orders WHERE id = ?").bind(id).first();
        await audit(env, who, "Paiement confirmé manuellement", id.slice(0, 8));
        return json({ status: fresh.status, license_key: fresh.license_key, expiration: fresh.expiration });
      }
      if (action === "cancel") {
        await env.DB.prepare("UPDATE hub_orders SET status = 'cancelled' WHERE id = ? AND status IN ('pending','failed')").bind(id).run();
        await audit(env, who, "Commande annulée", id.slice(0, 8));
        return json({ status: "cancelled" });
      }
      if (action === "refund") {
        if (order.status !== "paid") return json({ error: "Commande non payée" }, 400);
        await env.DB.prepare("UPDATE hub_orders SET status = 'refunded' WHERE id = ?").bind(id).run();
        if (order.license_id) await env.DB.prepare("UPDATE licenses SET status = 'disabled' WHERE id = ?").bind(order.license_id).run();
        await audit(env, who, "Commande marquée remboursée", id.slice(0, 8));
        return json({ status: "refunded" });
      }
    }
  }

  if (resource === "hub-promos") {
    if (!owner) return deny();
    if (method === "GET") {
      const { results } = await env.DB.prepare("SELECT * FROM hub_promos ORDER BY created_at DESC").all();
      return json(results);
    }
    if (method === "POST" && !id) {
      const b = await body();
      const code = String(b.code || "").toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 30);
      const kind = b.kind === "amount" ? "amount" : "percent";
      const value = Math.round(Number(b.value));
      if (!code || !(value > 0) || (kind === "percent" && value > 100)) return json({ error: "Code et valeur valides requis" }, 400);
      await env.DB.prepare(
        "INSERT INTO hub_promos (code, kind, value, max_uses, expires_at, active, created_at) VALUES (?,?,?,?,?,1,?)"
      ).bind(code, kind, value, Math.max(0, Math.round(Number(b.max_uses) || 0)), b.expires_at || null, new Date().toISOString()).run();
      await audit(env, who, "Code promo créé", code);
      return json({ code }, 201);
    }
    if (method === "POST" && id && action === "toggle") {
      await env.DB.prepare("UPDATE hub_promos SET active = 1 - active WHERE code = ?").bind(id).run();
      await audit(env, who, "Code promo activé/désactivé", id);
      return json({ ok: true });
    }
    if (method === "DELETE" && id) {
      await env.DB.prepare("DELETE FROM hub_promos WHERE code = ?").bind(id).run();
      await audit(env, who, "Code promo supprimé", id);
      return json({ ok: true });
    }
  }

  if (resource === "hub-staff") {
    if (!owner) return deny();
    if (method === "GET") {
      const { results } = await env.DB.prepare("SELECT id, name, role, created_at FROM hub_staff ORDER BY created_at DESC").all();
      return json(results);
    }
    if (method === "POST") {
      const b = await body();
      const name = String(b.name || "").trim().slice(0, 60);
      if (name.length < 2) return json({ error: "Nom requis" }, 400);
      const key = "hs_" + crypto.randomUUID().replace(/-/g, "");
      await env.DB.prepare("INSERT INTO hub_staff (id, name, key_hash, role, created_at) VALUES (?,?,?,?,?)")
        .bind(crypto.randomUUID(), name, await sha256(key), "agent", new Date().toISOString()).run();
      await audit(env, who, "Accès agent créé", name);
      return json({ key }, 201);
    }
    if (method === "DELETE" && id) {
      await env.DB.prepare("DELETE FROM hub_staff WHERE id = ?").bind(id).run();
      await audit(env, who, "Accès agent supprimé", id.slice(0, 8));
      return json({ ok: true });
    }
  }

  if (resource === "hub-audit") {
    if (!owner) return deny();
    const { results } = await env.DB.prepare("SELECT * FROM hub_audit ORDER BY id DESC LIMIT 200").all();
    return json(results);
  }
  return json({ error: "Route introuvable" }, 404);
}

// Pages servies par le Worker : /hub (clients) et /hub/admin (administrateur)
const HUB_HTML = "<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n<meta name=\"theme-color\" content=\"#FFFFFF\">\n<title>KinvosHub — Logiciels de gestion</title>\n<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2?family=Nunito:ital,wght@0,400;0,500;0,600;0,700;0,800;1,700&display=swap\">\n<style>\n:root{--pri:#087F5B;--navy:#064E3B;--yel:#FF8A00;--ink:#064E3B;--line:#DDEFE5;--muted:#5B7268;--ok:#15803D;--bad:#B42318;color-scheme:light;box-sizing:border-box}\n*,*::before,*::after{box-sizing:inherit}\nhtml,body{margin:0}\nbody{background:#fff;color:var(--ink);font:15px/1.45 \"Nunito\",system-ui,sans-serif;min-height:100vh;overflow-x:hidden}\nsvg{display:block}\nbutton{font-family:inherit;color:inherit}\n.page{max-width:560px;margin:0 auto;position:relative;padding-top:env(safe-area-inset-top,0px);background:radial-gradient(circle at 105% 14%,#C9F0DC 0,#E4F7EE 22%,rgba(255,255,255,0) 46%)}\n.hd{display:flex;align-items:center;justify-content:space-between;padding:14px 16px 0}\n.hd>button{border:0;background:none;padding:6px;cursor:pointer}\n.logo{display:flex;align-items:center;gap:8px}\n.logo svg{width:44px;height:32px}\n.wm{position:relative;font-size:27px;font-weight:800;letter-spacing:-.5px;color:var(--navy)}\n.wm b{color:var(--yel)}\n.wm::after{content:\"\";position:absolute;left:28%;right:-2%;bottom:-7px;height:5px;border-radius:50%;border-top:3px solid var(--yel)}\n.hero{display:grid;grid-template-columns:1.15fr .85fr;gap:4px;align-items:center;padding:30px 16px 6px}\nh1{margin:0;font-size:clamp(25px,7.2vw,38px);line-height:1.08;font-weight:800;color:var(--navy)}\nh1 em{display:block;position:relative;font-style:italic;color:var(--pri);font-weight:700;margin-top:4px;padding-bottom:12px}\nh1 em::after{content:\"\";position:absolute;left:8%;right:4%;bottom:2px;height:6px;border-radius:50%;border-top:3px solid var(--yel)}\n.tg{margin:8px 0 0;font-weight:500;font-size:clamp(13px,3.6vw,17px)}\n.tg i{color:var(--navy);font-style:normal;margin:0 3px}\n.ill svg{width:118%;margin-left:-6%;height:auto}\n.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:18px 14px 6px}\n.p{display:flex;align-items:center;gap:8px;text-align:left;background:#fff;border:1px solid var(--line);border-radius:20px;padding:10px 10px 10px 8px;cursor:pointer;box-shadow:0 6px 18px rgba(8,127,91,.1);min-height:84px}\n.ci{font-size:36px;width:54px;flex:none;text-align:center;padding-right:6px;border-right:1.5px solid var(--line);line-height:1.2}\n.pt{flex:1;font-weight:700;font-size:14px;line-height:1.25;color:var(--navy);padding-left:2px}\n.pt small{display:block;font-weight:600;font-size:13.5px}\n.pt em{display:block;font-style:normal;font-weight:500;font-size:11.5px;color:var(--muted);margin-top:2px}\n.ar{width:30px;height:30px;border-radius:50%;background:var(--pri);display:grid;place-items:center;flex:none}\n.trust{display:grid;grid-template-columns:1fr 1fr 1fr;padding:18px 8px 4px}\n.trust div{text-align:center;font-weight:600;font-size:13.5px;line-height:1.25;padding:0 6px;color:var(--navy)}\n.trust div+div{border-left:1.5px solid var(--pri)}\n.trust svg{width:34px;height:34px;margin:0 auto 6px;fill:var(--pri)}\n.cta2{display:flex;align-items:center;justify-content:center;gap:12px;width:calc(100% - 32px);margin:18px 16px 0;border:0;border-radius:99px;background:linear-gradient(90deg,#087F5B,#046C4E);color:#fff;font-weight:600;font-size:17px;padding:17px 10px;cursor:pointer;box-shadow:0 8px 20px rgba(8,127,91,.35);position:relative;z-index:1}\n.wave{margin-top:-24px;height:90px}\n.wave svg{width:100%;height:100%}\n.pg{padding:22px 16px 60px}\n.pg h2{margin:0 0 14px;font-size:22px;font-weight:800;color:var(--navy)}\nbutton:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #86E0B4;outline-offset:2px}\n.dr{position:fixed;inset:0;background:rgba(6,78,59,.35);display:none;z-index:30}\n.dr.on{display:block}\n.dr nav{width:78%;max-width:300px;height:100%;background:#fff;padding:calc(20px + env(safe-area-inset-top,0px)) 14px;display:flex;flex-direction:column;gap:6px}\n.dr nav button{border:0;background:none;text-align:left;font-weight:600;font-size:16px;color:var(--navy);padding:13px 12px;border-radius:12px;cursor:pointer}\n.dr nav button:hover{background:#E6F6EE}\n.bg{position:fixed;inset:0;background:rgba(6,78,59,.4);display:none;align-items:flex-end;justify-content:center;z-index:40}\n.bg.on{display:flex}\n.sheet{background:#fff;width:100%;max-width:560px;border-radius:24px 24px 0 0;padding:20px 16px calc(20px + env(safe-area-inset-bottom,0px));max-height:94vh;overflow:auto}\n.sh{display:flex;gap:12px;align-items:center;padding-bottom:14px;border-bottom:1px solid var(--line)}\n.sh .ci{border:0;font-size:40px}\n.sh h2{margin:0;font-size:20px;line-height:1.2;color:var(--navy)}\n.sh small{color:var(--muted)}\nh3{font-size:15px;font-weight:700;margin:18px 0 8px;color:var(--navy)}\n.dur{display:grid;grid-template-columns:1fr 1fr;gap:8px}\n.dur button{background:#fff;border:1.5px solid var(--line);border-radius:14px;padding:11px;text-align:left;cursor:pointer}\n.dur b{display:block}.dur small{color:var(--muted)}\n.dur button[aria-pressed=\"true\"]{border-color:var(--pri);background:#E6F6EE;box-shadow:inset 0 0 0 1px var(--pri)}\nlabel{display:block;font-weight:600;font-size:14px;margin:12px 0 5px}\ninput,select{width:100%;font:inherit;padding:12px;border-radius:12px;border:1px solid #C3DDD0;background:#fff;color:#123326}\n.cta{width:100%;margin-top:18px;background:var(--pri);color:#fff;border:0;border-radius:99px;padding:15px;font-weight:600;font-size:16.5px;cursor:pointer;box-shadow:0 6px 16px rgba(8,127,91,.3)}\n.ghost{background:none;border:0;color:var(--muted);width:100%;padding:12px;cursor:pointer}\n.code{font:700 19px/1.2 ui-monospace,Menlo,monospace;letter-spacing:.04em;text-align:center;background:#E6F6EE;border:2px dashed var(--pri);color:var(--pri);border-radius:14px;padding:16px 8px;margin:14px 0;word-break:break-all}\n.row{background:#fff;border:1px solid var(--line);border-radius:16px;padding:14px;margin-bottom:10px;box-shadow:0 4px 12px rgba(8,127,91,.08)}\n.row .code{font-size:16px;padding:10px;margin:8px 0}\n.tag{display:inline-block;font-size:12.5px;font-weight:600;padding:1px 9px;border-radius:99px;border:1px solid currentColor;margin-left:6px}\n.ok{color:var(--ok)}.bad{color:var(--bad)}\n.msg{margin-top:10px;font-weight:600}\n.empty{color:var(--muted);text-align:center;padding:30px 10px}\n.note{font-size:13px;color:var(--muted);margin-top:14px}\n.p{border-radius:16px;background:linear-gradient(135deg,#fff 40%,#F0FAF5);border-left:5px solid var(--yel);box-shadow:0 6px 16px rgba(8,127,91,.12)}\n.ci{width:56px;height:56px;display:grid;place-items:center;padding:0;border:0;border-radius:14px;background:#E3F6EC;font-size:30px}\n.pt small{color:var(--pri)}\n.ar{border-radius:10px;background:var(--yel)}\n.cta2{border-radius:18px}.cta{border-radius:16px}\n.trust div+div{border-left:1.5px dashed var(--pri)}\n.grid .p:last-child:nth-child(odd){grid-column:1/-1}\n</style>\n</head>\n<body>\n<svg width=\"0\" height=\"0\" style=\"position:absolute\" aria-hidden=\"true\"><defs>\n<symbol id=\"k\" viewBox=\"0 0 80 56\"><path d=\"M13 3H31L23 53H5Z\" fill=\"#087F5B\"/><path d=\"M31 30L56 3H79L48 36Z\" fill=\"#087F5B\"/><path d=\"M44 32L79 53H56L38 40Z\" fill=\"#087F5B\"/><path d=\"M2 51C24 48 40 38 52 20L58 25C46 44 28 55 5 55Z\" fill=\"#FF8A00\"/></symbol>\n<symbol id=\"ar\" viewBox=\"0 0 24 24\"><path d=\"M5 12h14M13 6l6 6-6 6\" fill=\"none\" stroke=\"#fff\" stroke-width=\"2.6\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></symbol>\n</defs></svg>\n\n<div class=\"page\">\n<header class=\"hd\">\n<button id=\"mn\" aria-label=\"Ouvrir le menu\"><svg width=\"30\" height=\"26\" viewBox=\"0 0 30 26\" stroke=\"#087F5B\" stroke-width=\"3.5\" stroke-linecap=\"round\"><path d=\"M2 3h26M2 13h26M2 23h26\"/></svg></button>\n<div class=\"logo\"><svg><use href=\"#k\"/></svg><span class=\"wm\">Kinvos<b>Hub</b></span></div>\n<button id=\"us\" aria-label=\"Mes achats\"><svg width=\"36\" height=\"36\" viewBox=\"0 0 40 40\"><circle cx=\"20\" cy=\"20\" r=\"20\" fill=\"#087F5B\"/><circle cx=\"20\" cy=\"15\" r=\"6\" fill=\"#fff\"/><path d=\"M8 33c1-7 6-10 12-10s11 3 12 10z\" fill=\"#fff\"/></svg></button>\n</header>\n\n<section id=\"v0\">\n<div class=\"hero\">\n<div><h1>Vos logiciels de gestion<em>en un seul endroit</em></h1><p class=\"tg\">Achetez <i>•</i> Accédez <i>•</i> Gérez</p></div>\n<div class=\"ill\"><svg viewBox=\"0 0 260 170\" aria-hidden=\"true\">\n<rect x=\"22\" y=\"10\" width=\"170\" height=\"108\" rx=\"9\" fill=\"#E1F2E9\" stroke=\"#B3D1C2\" stroke-width=\"4\"/>\n<rect x=\"31\" y=\"19\" width=\"152\" height=\"90\" rx=\"4\" fill=\"#fff\"/>\n<use href=\"#k\" x=\"76\" y=\"32\" width=\"56\" height=\"39\"/>\n<text x=\"107\" y=\"92\" text-anchor=\"middle\" font-family=\"Nunito,sans-serif\" font-weight=\"800\" font-size=\"16\" fill=\"#064E3B\">Kinvos<tspan fill=\"#FF8A00\">Hub</tspan></text>\n<path d=\"M4 118H210L202 130Q200 135 194 135H20Q14 135 12 130Z\" fill=\"#C2DCCF\"/>\n<rect x=\"176\" y=\"46\" width=\"64\" height=\"116\" rx=\"11\" fill=\"#8FB5A3\"/>\n<rect x=\"180\" y=\"50\" width=\"56\" height=\"108\" rx=\"8\" fill=\"#fff\"/>\n<use href=\"#k\" x=\"191\" y=\"76\" width=\"34\" height=\"24\"/>\n<text x=\"208\" y=\"116\" text-anchor=\"middle\" font-family=\"Nunito,sans-serif\" font-weight=\"800\" font-size=\"9\" fill=\"#064E3B\">Kinvos<tspan fill=\"#FF8A00\">Hub</tspan></text>\n<path d=\"M180 140Q200 128 236 134V150Q236 158 228 158H188Q180 158 180 150Z\" fill=\"#087F5B\"/>\n</svg></div>\n</div>\n\n<div class=\"grid\" id=\"grid\"></div>\n\n<div class=\"trust\">\n<div><svg viewBox=\"0 0 24 24\"><path d=\"M13 2L4 14h7l-1 8 10-13h-7z\"/></svg>Activation<br>immédiate</div>\n<div><svg viewBox=\"0 0 24 24\"><path d=\"M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z\"/><path d=\"M8.5 12l2.5 2.5 4.5-5\" fill=\"none\" stroke=\"#fff\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>Paiement<br>sécurisé</div>\n<div><svg viewBox=\"0 0 24 24\"><path d=\"M4 15v-3a8 8 0 0116 0v3\" fill=\"none\" stroke=\"#087F5B\" stroke-width=\"2.2\"/><rect x=\"2.5\" y=\"13\" width=\"4.5\" height=\"7\" rx=\"2\"/><rect x=\"17\" y=\"13\" width=\"4.5\" height=\"7\" rx=\"2\"/><path d=\"M19.5 20c0 1.6-2 2-5 2\" fill=\"none\" stroke=\"#087F5B\" stroke-width=\"2\"/></svg>Assistance<br>réactive</div>\n</div>\n\n<button class=\"cta2\" id=\"go\"><svg width=\"26\" height=\"26\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#fff\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M2 3h3l2.5 12h11l2-8H6.5\"/><circle cx=\"9\" cy=\"20\" r=\"1.5\"/><circle cx=\"17\" cy=\"20\" r=\"1.5\"/></svg>Choisissez votre logiciel<svg width=\"22\" height=\"22\"><use href=\"#ar\" width=\"22\" height=\"22\"/></svg></button>\n<div class=\"wave\"><svg viewBox=\"0 0 400 90\" preserveAspectRatio=\"none\"><path d=\"M0 50Q90 30 190 62T400 18V90H0Z\" fill=\"#FF8A00\"/><path d=\"M0 62Q100 44 200 74T400 36V90H0Z\" fill=\"#087F5B\"/></svg></div>\n</section>\n\n<section id=\"v1\" class=\"pg\" hidden><h2>Mes achats</h2><div id=\"list\"></div><div class=\"row\" style=\"margin-top:14px\"><b>Code perdu ?</b><small style=\"display:block;color:var(--muted);margin:2px 0 8px\">Saisissez l’email utilisé lors de l’achat : nous vous renvoyons vos codes.</small><input id=\"rmail\" type=\"email\" placeholder=\"Votre email d’achat\"><button class=\"cta\" id=\"rbtn\" style=\"margin-top:10px\">Recevoir mes codes par email</button><div class=\"msg\" id=\"rmsg\"></div></div></section>\n</div>\n\n<div class=\"dr\" id=\"dr\"><nav>\n<button data-v=\"0\">Accueil</button><button data-v=\"1\">Mes achats</button>\n</nav></div>\n<div class=\"bg\" id=\"bg\"><div class=\"sheet\" role=\"dialog\" aria-modal=\"true\" id=\"sh\"></div></div>\n\n<script>\nconst $=s=>document.querySelector(s);\nconst esc=s=>String(s==null?\"\":s).replace(/[&<>\"]/g,c=>({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\"}[c]));\nconst f=n=>Number(n).toLocaleString(\"fr-FR\")+\" FCFA\";\nconst dfr=t=>new Date(t).toLocaleDateString(\"fr-FR\",{day:\"numeric\",month:\"long\",year:\"numeric\"});\nlet CAT={products:[],plans:[],open:true},mine=[];\ntry{mine=JSON.parse(localStorage.getItem(\"hub_orders\")||\"[]\")}catch(e){}\nconst saveMine=()=>{try{localStorage.setItem(\"hub_orders\",JSON.stringify(mine))}catch(e){}};\nasync function api(p,o){const r=await fetch(p,o);const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||\"Erreur\");return d}\nfunction show(i){[0,1].forEach(n=>$(\"#v\"+n).hidden=n!==i);$(\"#dr\").classList.remove(\"on\");if(i===1)mes();window.scrollTo(0,0)}\n$(\"#mn\").onclick=()=>$(\"#dr\").classList.add(\"on\");\n$(\"#dr\").onclick=e=>{const b=e.target.closest(\"button\");if(b)show(+b.dataset.v);else if(e.target.id===\"dr\")$(\"#dr\").classList.remove(\"on\")};\n$(\"#us\").onclick=()=>show(1);\n$(\"#go\").onclick=()=>$(\"#grid\").scrollIntoView({behavior:\"smooth\",block:\"start\"});\nconst fermer=()=>$(\"#bg\").classList.remove(\"on\");\n$(\"#bg\").onclick=e=>{if(e.target.id===\"bg\")fermer()};\nasync function init(){\ntry{CAT=await api(\"/api/hub/catalog\")}catch(e){$(\"#grid\").innerHTML='<div class=\"empty\" style=\"grid-column:1/-1\">Boutique momentanément indisponible.</div>';return}\nif(!CAT.open){$(\"#grid\").innerHTML='<div class=\"empty\" style=\"grid-column:1/-1\">Les achats sont temporairement fermés.</div>';return}\n$(\"#grid\").innerHTML=CAT.products.map(p=>`<button class=\"p\" data-c=\"${esc(p.code)}\"><span class=\"ci\">${esc(p.e)}</span><span class=\"pt\"><small>Gestion</small>${esc(p.t)}<em>${esc(p.nom)}</em></span><span class=\"ar\"><svg width=\"18\" height=\"18\"><use href=\"#ar\" width=\"18\" height=\"18\"/></svg></span></button>`).join(\"\");\nconst w=(CAT.texts&&CAT.texts.whatsapp||\"\").replace(/\\D/g,\"\");if(w){const a=document.querySelector(\".trust div:last-child\");a.style.cursor=\"pointer\";a.onclick=()=>window.open(\"https://wa.me/\"+w)}\nconst q=new URLSearchParams(location.search).get(\"order\");\nif(q&&/^[0-9a-f-]{36}$/.test(q))suivre(q);\n}\n$(\"#grid\").onclick=e=>{const b=e.target.closest(\".p\");if(b)ouvrir(CAT.products.find(p=>p.code===b.dataset.c))};\nfunction ouvrir(p){\nlet di=0,cut=0;const sh=$(\"#sh\");const pr=d=>((p.prices&&p.prices[d.id])||d.price);const due=()=>Math.max(0,pr(CAT.plans[di])-cut);\nfunction draw(){\nsh.innerHTML=`<div class=\"sh\"><span class=\"ci\">${esc(p.e)}</span><div><h2>Gestion ${esc(p.t)}</h2><small>${esc(p.nom)}</small></div></div>\n<h3>Durée d’accès</h3><div class=\"dur\">${CAT.plans.map((d,i)=>`<button data-i=\"${i}\" aria-pressed=\"${i===di}\"><b>${esc(d.label)}</b><small>${f(pr(d))}</small></button>`).join(\"\")}</div>\n<label for=\"nom\">Nom complet</label><input id=\"nom\" autocomplete=\"name\">\n<label for=\"mail\">Email</label><input id=\"mail\" type=\"email\" autocomplete=\"email\">\n<label for=\"tel\">Téléphone</label><input id=\"tel\" type=\"tel\" autocomplete=\"tel\">\n<label for=\"promo\">Code promo (facultatif)</label><div style=\"display:flex;gap:8px\"><input id=\"promo\" autocapitalize=\"characters\"><button class=\"ghost\" id=\"pa\" style=\"width:auto;padding:0 14px\">Appliquer</button></div><div class=\"msg\" id=\"pm\"></div>${CAT.texts&&CAT.texts.terms?`<label style=\"display:flex;gap:8px;align-items:flex-start;font-weight:500\"><input type=\"checkbox\" id=\"cg\" style=\"width:auto;margin-top:4px\"><span>J’accepte les conditions d’utilisation <a href=\"#\" id=\"lt\">(lire)</a></span></label><div id=\"tt\" class=\"note\" hidden style=\"white-space:pre-wrap\"></div>`:\"\"}\n<div class=\"msg bad\" id=\"err\" role=\"alert\"></div>\n<button class=\"cta\" id=\"pay\">Payer ${f(due())}</button>\n<button class=\"ghost\" id=\"cl\">Fermer</button>\n<div class=\"note\">Paiement sécurisé par FedaPay (Mobile Money ou carte). Votre code s’affiche dès que le paiement est confirmé.</div>`;\nsh.querySelectorAll(\".dur button\").forEach(b=>b.onclick=()=>{di=+b.dataset.i;cut=0;const ids=[\"#nom\",\"#mail\",\"#tel\",\"#promo\"],v=ids.map(s=>$(s).value);draw();ids.forEach((s,k)=>$(s).value=v[k]);if($(\"#promo\").value)$(\"#pa\").click()});\n$(\"#pa\").onclick=async()=>{const c=$(\"#promo\").value.trim(),m=$(\"#pm\");if(!c){cut=0;m.textContent=\"\";$(\"#pay\").textContent=\"Payer \"+f(due());return}try{const r=await api(\"/api/hub/promo\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({software_code:p.code,plan:CAT.plans[di].id,promo:c})});cut=r.discount;m.className=\"msg ok\";m.textContent=\"Réduction de \"+f(r.discount)+\" appliquée.\";$(\"#pay\").textContent=\"Payer \"+f(due())}catch(e){cut=0;m.className=\"msg bad\";m.textContent=e.message;$(\"#pay\").textContent=\"Payer \"+f(due())}};\nif($(\"#lt\"))$(\"#lt\").onclick=e=>{e.preventDefault();$(\"#tt\").textContent=CAT.texts.terms;$(\"#tt\").hidden=false};\n$(\"#cl\").onclick=fermer;\n$(\"#pay\").onclick=async()=>{\nconst nom=$(\"#nom\").value.trim(),mail=$(\"#mail\").value.trim(),tel=$(\"#tel\").value.trim();\nif(nom.length<2||!/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(mail)||tel.replace(/\\D/g,\"\").length<8){$(\"#err\").textContent=\"Entrez votre nom, un email et un téléphone valides.\";return}\nif($(\"#cg\")&&!$(\"#cg\").checked){$(\"#err\").textContent=\"Veuillez accepter les conditions d’utilisation.\";return}\nconst b=$(\"#pay\");b.disabled=true;b.textContent=\"Redirection vers le paiement…\";\ntry{\nconst pl=CAT.plans[di];\nconst r=await api(\"/api/hub/orders\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({software_code:p.code,plan:pl.id,client_name:nom,client_email:mail,client_phone:tel,promo:$(\"#promo\").value.trim()})});\nmine.unshift({id:r.order_id,nom:p.nom,e:p.e,plan:pl.label,amount:r.amount});saveMine();\nif(r.status===\"paid\"){suivre(r.order_id);return}\nif(r.payment&&r.payment.url){location.href=r.payment.url;return}\n$(\"#err\").textContent=\"Le paiement en ligne n’est pas encore activé. Commande n° \"+r.order_id.slice(0,8)+\" enregistrée.\"\n}catch(e){$(\"#err\").textContent=e.message}\nb.disabled=false;b.textContent=\"Payer \"+f(due());\n};\n}\ndraw();$(\"#bg\").classList.add(\"on\");\n}\nfunction recu(o){\n$(\"#sh\").innerHTML=`<h2 class=\"ok\" style=\"margin:0 0 6px\">Paiement confirmé</h2><div>${esc(o.software)} — ${esc(o.plan)}</div><div class=\"code\">${esc(o.license_key)}</div><button class=\"cta\" id=\"cp\">Copier le code</button><div class=\"note\">Accès valable ${o.expiration?\"jusqu’au \"+dfr(o.expiration):\"sans limite de durée\"}. Saisissez ce code dans votre logiciel. Vous le retrouvez aussi dans « Mes achats ».</div><button class=\"ghost\" id=\"ok\">Fermer</button>`;\n$(\"#bg\").classList.add(\"on\");\n$(\"#cp\").onclick=async()=>{try{await navigator.clipboard.writeText(o.license_key);$(\"#cp\").textContent=\"Code copié\"}catch(e){$(\"#cp\").textContent=\"Copiez le code affiché\"}};\n$(\"#ok\").onclick=()=>{fermer();show(1)};\n}\nasync function suivre(id){\nhistory.replaceState(null,\"\",location.pathname);\nconst sh=$(\"#sh\");$(\"#bg\").classList.add(\"on\");\nsh.innerHTML='<h2 style=\"margin:0 0 8px\">Vérification du paiement…</h2><div class=\"note\">Patientez quelques secondes, ne fermez pas la page.</div>';\nfor(let i=0;i<60;i++){\ntry{const o=await api(\"/api/hub/orders/\"+id);if(o.status===\"paid\"){recu(o);return}if(o.status===\"failed\"||o.status===\"cancelled\")break}catch(e){}\nawait new Promise(r=>setTimeout(r,3000));\n}\nsh.innerHTML='<h2 style=\"margin:0 0 8px\">Paiement non confirmé</h2><div class=\"note\">Si vous avez payé, votre code apparaîtra dans « Mes achats » dès que le paiement sera confirmé.</div><button class=\"ghost\" id=\"ok\">Fermer</button>';\n$(\"#ok\").onclick=fermer;\n}\nasync function mes(){\nconst v=$(\"#list\");\nif(!mine.length){v.innerHTML='<div class=\"empty\">Aucun achat sur cet appareil.<br>Choisissez un logiciel pour obtenir votre code.</div>';return}\nv.innerHTML='<div class=\"empty\">Chargement…</div>';\nconst rows=await Promise.all(mine.map(async m=>{try{return{m,o:await api(\"/api/hub/orders/\"+m.id)}}catch(e){return{m,o:null}}}));\nv.innerHTML=rows.map(({m,o})=>{const paid=o&&o.status===\"paid\";const lab=paid?\"Payé\":(o&&o.status===\"pending\"?\"En attente\":\"Non payé\");return `<div class=\"row\"><b>${esc(m.e)} ${esc(m.nom)}</b><span class=\"tag ${paid?\"ok\":\"bad\"}\">${lab}</span>${paid?`<div class=\"code\">${esc(o.license_key)}</div>`:\"\"}<small style=\"color:var(--muted)\">${esc(m.plan)} · ${f(m.amount)}${paid?\" · \"+(o.expiration?\"jusqu’au \"+dfr(o.expiration):\"accès illimité\"):\"\"}</small></div>`}).join(\"\");\n}\ntry{const mf={name:\"KinvosHub\",short_name:\"KinvosHub\",start_url:\"/hub\",display:\"standalone\",background_color:\"#FFFFFF\",theme_color:\"#FFFFFF\"};\nconst l=document.createElement(\"link\");l.rel=\"manifest\";l.href=URL.createObjectURL(new Blob([JSON.stringify(mf)],{type:\"application/manifest+json\"}));document.head.appendChild(l)}catch(e){}\n$(\"#rbtn\").onclick=async()=>{const m=$(\"#rmsg\");try{await api(\"/api/hub/recover\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({email:$(\"#rmail\").value.trim()})});m.className=\"msg ok\";m.textContent=\"Si des achats existent pour cet email, vos codes viennent d’être envoyés.\"}catch(e){m.className=\"msg bad\";m.textContent=e.message}};\ninit();\n</script>\n</body>\n</html>\n";
const HUB_ADMIN_HTML = "<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n<meta name=\"robots\" content=\"noindex\">\n<title>KinvosHub — Administration</title>\n<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap\">\n<style>\n:root{--pri:#087F5B;--navy:#064E3B;--yel:#FF8A00;--line:#DDEFE5;--bg:#F4FAF7;--muted:#5B7268;--ok:#15803D;--bad:#B42318;color-scheme:light;box-sizing:border-box}\n*,*::before,*::after{box-sizing:inherit}\nbody{margin:0;background:var(--bg);color:#123326;font:15px/1.45 \"Nunito\",system-ui,sans-serif}\nbutton,input,select{font:inherit;color:inherit}\n.top{background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;padding-top:env(safe-area-inset-top,0px)}\n.top div{max-width:900px;margin:0 auto;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;font-weight:800;font-size:18px;color:var(--navy)}\n.top b{color:var(--yel)}\n.wrap{max-width:900px;margin:0 auto;padding:14px 16px 80px}\nnav{display:flex;gap:4px;overflow-x:auto;background:#E3F1EA;border-radius:12px;padding:4px;margin-bottom:16px}\nnav button{flex:1;white-space:nowrap;border:0;background:none;padding:9px 12px;border-radius:9px;font-weight:700;color:var(--muted);cursor:pointer}\nnav button.on{background:#fff;color:var(--pri);box-shadow:0 1px 3px rgba(6,78,59,.2)}\n.cards{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}\n@media(min-width:700px){.cards{grid-template-columns:repeat(4,1fr)}}\n.st{background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px}\n.st small{color:var(--muted);font-weight:600;display:block}.st b{font-size:20px;color:var(--navy)}\nh2{font-size:17px;margin:18px 0 8px;color:var(--navy)}\n.box{background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px;margin-bottom:10px}\n.row{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)}\n.row:last-child{border:0}\n.it{background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px;margin-bottom:8px;cursor:pointer}\n.it .l{display:flex;justify-content:space-between;gap:8px}\n.it small,.muted{color:var(--muted)}\n.tag{font-size:12.5px;font-weight:700;padding:1px 9px;border-radius:99px;border:1px solid currentColor;white-space:nowrap}\n.paid{color:var(--ok)}.pending,.processing{color:#B45309}.failed,.cancelled,.refunded{color:var(--bad)}\n.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}\n.bar>*{flex:1;min-width:120px}\ninput,select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #C3DDD0;background:#fff}\n.btn{border:0;border-radius:12px;padding:12px 16px;font-weight:800;background:var(--pri);color:#fff;cursor:pointer}\n.btn.o{background:var(--yel)}.btn.g{background:#fff;color:var(--pri);border:1.5px solid var(--pri)}.btn.r{background:#fff;color:var(--bad);border:1.5px solid var(--bad)}\n.btn.s{padding:7px 12px;font-size:13px}\n.pr{display:grid;grid-template-columns:1fr 1fr;gap:8px}\n.pe{display:grid;grid-template-columns:auto 56px 1fr 1fr auto;gap:6px;align-items:center;padding:8px 0;border-bottom:1px solid var(--line)}\n.pe .c{font-weight:800;width:34px}\n.bg{position:fixed;inset:0;background:rgba(6,78,59,.4);display:none;align-items:flex-end;justify-content:center;z-index:20}\n.bg.on{display:flex}\n.sheet{background:#fff;width:100%;max-width:560px;border-radius:22px 22px 0 0;padding:18px 16px calc(18px + env(safe-area-inset-bottom,0px));max-height:92vh;overflow:auto}\n.kv{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px dashed var(--line)}\n.kv span:first-child{color:var(--muted)}.kv span:last-child{text-align:right;word-break:break-all}\n.code{font:700 16px ui-monospace,Menlo,monospace;text-align:center;background:#E6F6EE;border:2px dashed var(--pri);color:var(--pri);border-radius:12px;padding:12px 6px;margin:10px 0;word-break:break-all}\nlabel{display:block;font-weight:700;font-size:14px;margin:10px 0 4px}\n.tg{display:flex;align-items:center;gap:8px}.tg input{width:auto}\n#login{max-width:380px;margin:12vh auto;padding:0 16px;text-align:center}\n#login h1{color:var(--navy);margin:0 0 6px}\n.msg{margin-top:10px;font-weight:700}\n.empty{text-align:center;color:var(--muted);padding:26px}\n</style>\n</head>\n<body>\n<div id=\"login\">\n<h1>Kinvos<span style=\"color:var(--yel)\">Hub</span></h1>\n<p class=\"muted\">Espace administrateur</p>\n<input id=\"key\" type=\"password\" placeholder=\"Clé administrateur\" autocomplete=\"current-password\">\n<button class=\"btn\" id=\"go\" style=\"width:100%;margin-top:12px\">Se connecter</button>\n<div class=\"msg\" style=\"color:var(--bad)\" id=\"lerr\"></div>\n</div>\n\n<div id=\"app\" hidden>\n<div class=\"top\"><div><span>Kinvos<b>Hub</b> · Administration</span><button class=\"btn g s\" id=\"out\">Quitter</button></div></div>\n<div class=\"wrap\">\n<nav id=\"tabs\"><button data-t=\"0\">Tableau de bord</button><button data-t=\"1\">Commandes</button><button data-t=\"2\">Catalogue</button><button data-t=\"3\">Clients</button><button data-t=\"4\">Réglages</button><button data-t=\"5\">Promos</button><button data-t=\"6\">Équipe</button></nav>\n\n<section id=\"s0\"></section>\n\n<section id=\"s1\" hidden>\n<div class=\"bar\"><input id=\"q\" placeholder=\"Rechercher (nom, email, téléphone, code)\"><select id=\"fs\"><option value=\"\">Tous les statuts</option><option value=\"paid\">Payées</option><option value=\"pending\">En attente</option><option value=\"failed\">Échecs</option><option value=\"cancelled\">Annulées</option><option value=\"refunded\">Remboursées</option></select><select id=\"fl\"><option value=\"\">Tous les logiciels</option></select><input type=\"date\" id=\"fd\" title=\"Depuis le\"></div>\n<button class=\"btn g s\" id=\"csv\" style=\"margin-bottom:10px\">Exporter en CSV</button>\n<div id=\"ol\"></div>\n</section>\n\n<section id=\"s2\" hidden>\n<h2>Tarifs (FCFA)</h2>\n<div class=\"box\"><div class=\"pr\" id=\"plans\"></div></div>\n<h2>Logiciels vendus sur le hub</h2>\n<div class=\"box\" id=\"prods\"></div>\n<h2>Ajouter un logiciel</h2>\n<div class=\"box\">\n<div class=\"pr\"><div><label>Préfixe (code du serveur)</label><input id=\"nc\" placeholder=\"Ex : EP\"></div><div><label>Nom du logiciel</label><input id=\"nn\" placeholder=\"Ex : EasyPharma\"></div><div><label>Titre sur la carte</label><input id=\"nt\" placeholder=\"Ex : Pharmacie\"></div><div><label>Emoji</label><input id=\"ne\" placeholder=\"💊\"></div></div>\n<button class=\"btn g\" id=\"na\" style=\"margin-top:12px\">Ajouter à la liste</button>\n<p class=\"muted\" style=\"font-size:13px\">Le préfixe doit exister dans votre appli de licences, sinon l’achat sera refusé.</p>\n</div>\n<button class=\"btn\" id=\"sv2\" style=\"width:100%\">Enregistrer le catalogue</button>\n</section>\n\n<section id=\"s3\" hidden><div class=\"bar\"><input id=\"cq\" placeholder=\"Rechercher un client\"></div><div id=\"cl\"></div></section>\n\n<section id=\"s4\" hidden>\n<div class=\"box\">\n<label class=\"tg\"><input type=\"checkbox\" id=\"open\"> Boutique ouverte aux achats</label>\n<label>Appareils autorisés par licence vendue</label><input id=\"md\" type=\"number\" min=\"1\" max=\"100\">\n</div>\n<h2>Textes du hub</h2><div class=\"box\"><label>WhatsApp d’assistance (avec indicatif)</label><input id=\"twa\" placeholder=\"22997000000\"><label>Email d’assistance</label><input id=\"tem\"><label>Conditions d’utilisation (facultatif)</label><textarea id=\"ttc\" rows=\"5\" style=\"width:100%;padding:10px;border-radius:10px;border:1px solid #C3DDD0\"></textarea></div>\n<h2>Services</h2>\n<div class=\"box\" id=\"fp\"></div>\n<h2>Liens utiles</h2>\n<div class=\"box\" id=\"lk\"></div>\n<button class=\"btn\" id=\"sv4\" style=\"width:100%\">Enregistrer les réglages</button>\n</section>\n<section id=\"s5\" hidden>\n<h2 style=\"margin-top:0\">Nouveau code promo</h2>\n<div class=\"box\"><div class=\"pr\"><div><label>Code</label><input id=\"pcode\" placeholder=\"BIENVENUE\"></div><div><label>Type</label><select id=\"pkind\"><option value=\"percent\">Pourcentage (%)</option><option value=\"amount\">Montant (FCFA)</option></select></div><div><label>Valeur</label><input id=\"pval\" type=\"number\" min=\"1\"></div><div><label>Utilisations max (0 = illimité)</label><input id=\"pmax\" type=\"number\" min=\"0\" value=\"0\"></div><div><label>Expire le (facultatif)</label><input id=\"pexp\" type=\"date\"></div></div><button class=\"btn\" id=\"pnew\" style=\"margin-top:12px\">Créer le code</button></div>\n<h2>Codes existants</h2><div id=\"plist\"></div></section>\n<section id=\"s6\" hidden>\n<h2 style=\"margin-top:0\">Agents (accès limité)</h2>\n<div class=\"box\"><p class=\"muted\" style=\"margin-top:0;font-size:13px\">Un agent voit les commandes et les clients, vérifie les paiements et renvoie les codes. Il ne peut ni changer les prix, ni créer ou modifier une licence.</p><div class=\"bar\"><input id=\"sname\" placeholder=\"Nom de l’agent\"><button class=\"btn\" id=\"snew\">Créer l’accès</button></div><div id=\"skey\"></div><div id=\"slist\"></div></div>\n<h2>Journal des actions</h2><div class=\"box\" id=\"alog\"></div></section>\n<div class=\"msg\" id=\"msg\" role=\"status\"></div>\n</div>\n</div>\n<div class=\"bg\" id=\"bg\"><div class=\"sheet\" id=\"sh\"></div></div>\n\n<script>\nconst $=s=>document.querySelector(s);\nconst esc=s=>String(s==null?\"\":s).replace(/[&<>\"]/g,c=>({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\"}[c]));\nconst f=n=>Number(n||0).toLocaleString(\"fr-FR\")+\" FCFA\";\nconst dt=t=>t?new Date(t).toLocaleString(\"fr-FR\",{day:\"2-digit\",month:\"short\",year:\"numeric\",hour:\"2-digit\",minute:\"2-digit\"}):\"—\";\nconst ST={paid:\"Payée\",pending:\"En attente\",processing:\"En cours\",failed:\"Échec\",cancelled:\"Annulée\",refunded:\"Remboursée\"};\nlet KEY=sessionStorage.getItem(\"hubkey\")||\"\",ORD=[],CFG=null,ME={},PER=localStorage.getItem(\"per\")||\"30\";\nasync function api(p,o){o=o||{};const r=await fetch(\"/api/admin/\"+p,{method:o.method||\"GET\",body:o.body,headers:{\"x-admin-key\":KEY,\"Content-Type\":\"application/json\"}});const d=await r.json().catch(()=>({}));if(r.status===401){out();throw new Error(\"Clé refusée\")}if(!r.ok)throw new Error(d.error||\"Erreur\");return d}\nfunction out(){sessionStorage.removeItem(\"hubkey\");KEY=\"\";$(\"#app\").hidden=true;$(\"#login\").hidden=false}\nasync function load(){[CFG,ORD]=await Promise.all([api(\"hub-config\"),api(\"hub-orders\")]);ME=CFG.me;$(\"#login\").hidden=true;$(\"#app\").hidden=false;document.querySelectorAll(\"#tabs button\").forEach(b=>b.hidden=ME.role!==\"owner\"&&[\"2\",\"4\",\"5\",\"6\"].includes(b.dataset.t));draw()}\n$(\"#go\").onclick=async()=>{KEY=$(\"#key\").value.trim();try{await load();sessionStorage.setItem(\"hubkey\",KEY)}catch(e){$(\"#lerr\").textContent=e.message}};\n$(\"#out\").onclick=out;\nif(KEY)load().catch(()=>{});\nfunction tab(i){document.querySelectorAll(\"section\").forEach((s,n)=>s.hidden=n!==i);document.querySelectorAll(\"#tabs button\").forEach(b=>b.classList.toggle(\"on\",+b.dataset.t===i));$(\"#msg\").textContent=\"\"}\n$(\"#tabs\").onclick=e=>{const b=e.target.closest(\"button\");if(b)tab(+b.dataset.t)};\nconst note=(t,bad)=>{const m=$(\"#msg\");m.textContent=t;m.style.color=bad?\"var(--bad)\":\"var(--ok)\"};\n\nfunction draw(){stats();orders();catalog();clients();reglages();if(ME.role===\"owner\"){promos().catch(()=>{});team().catch(()=>{})}tab(+(document.querySelector(\"#tabs .on\")||{dataset:{t:0}}).dataset.t)}\n\nfunction stats(){\nconst now=new Date(),all=ORD.filter(o=>o.status===\"paid\");\nconst t0=new Date(now.getFullYear(),now.getMonth(),now.getDate());\nconst st=PER===\"today\"?t0:PER===\"month\"?new Date(now.getFullYear(),now.getMonth(),1):PER===\"year\"?new Date(now.getFullYear(),0,1):PER===\"all\"?new Date(0):new Date(t0-(+PER-1)*864e5);\nconst paid=all.filter(o=>new Date(o.paid_at)>=st),sum=x=>x.reduce((s,o)=>s+o.amount_fcfa,0);\nconst pend=ORD.filter(o=>o.status===\"pending\").length;\nconst by={};paid.forEach(o=>{const k=o.software_name||o.software_code;by[k]=by[k]||{n:0,t:0};by[k].n++;by[k].t+=o.amount_fcfa});\nconst days=[];for(let i=29;i>=0;i--)days.push({d:new Date(t0-i*864e5),t:0});\nall.forEach(o=>{const x=days.find(k=>k.d.toDateString()===new Date(o.paid_at).toDateString());if(x)x.t+=o.amount_fcfa});\nconst mx=Math.max(1,...days.map(x=>x.t));\nconst svg=`<svg viewBox=\"0 0 300 92\" style=\"width:100%\">${days.map((x,i)=>`<rect x=\"${i*10+1}\" y=\"${80-x.t/mx*72}\" width=\"8\" height=\"${x.t/mx*72}\" rx=\"2\" fill=\"#087F5B\"><title>${x.d.toLocaleDateString(\"fr-FR\")} : ${f(x.t)}</title></rect>`).join(\"\")}<text x=\"0\" y=\"90\" font-size=\"7\" fill=\"#5B7268\">il y a 30 jours</text><text x=\"300\" y=\"90\" font-size=\"7\" text-anchor=\"end\" fill=\"#5B7268\">aujourd’hui</text></svg>`;\nconst opt=(v,l)=>`<option value=\"${v}\"${PER===v?\" selected\":\"\"}>${l}</option>`;\n$(\"#s0\").innerHTML=`<div class=\"bar\"><select id=\"per\">${opt(\"today\",\"Aujourd’hui\")}${opt(\"7\",\"7 derniers jours\")}${opt(\"30\",\"30 derniers jours\")}${opt(\"month\",\"Ce mois\")}${opt(\"year\",\"Cette année\")}${opt(\"all\",\"Depuis le début\")}</select><button class=\"btn g s\" id=\"vall\">Vérifier les paiements en attente (${pend})</button></div>\n<div class=\"cards\"><div class=\"st\"><small>Chiffre d’affaires</small><b>${f(sum(paid))}</b></div><div class=\"st\"><small>Ventes</small><b>${paid.length}</b></div><div class=\"st\"><small>Panier moyen</small><b>${f(paid.length?Math.round(sum(paid)/paid.length):0)}</b></div><div class=\"st\"><small>En attente</small><b>${pend}</b></div></div>\n<h2>Ventes sur 30 jours</h2><div class=\"box\">${svg}</div>\n<h2>Ventes par logiciel</h2><div class=\"box\">${Object.keys(by).length?Object.entries(by).sort((a,b)=>b[1].t-a[1].t).map(([k,v])=>`<div class=\"row\"><span>${esc(k)}</span><span><b>${v.n}</b> · ${f(v.t)}</span></div>`).join(\"\"):'<div class=\"empty\">Aucune vente sur la période.</div>'}</div>\n<h2>Dernières ventes</h2>${all.slice(0,8).map(o=>`<div class=\"it\" onclick=\"detail('${o.id}')\"><div class=\"l\"><b>${esc(o.client_name)}</b><b>${f(o.amount_fcfa)}</b></div><small>${esc(o.software_name||o.software_code)} · ${dt(o.paid_at)}</small></div>`).join(\"\")||'<div class=\"empty\">—</div>'}`;\n$(\"#per\").onchange=e=>{PER=e.target.value;localStorage.setItem(\"per\",PER);stats()};\n$(\"#vall\").onclick=async()=>{try{const r=await api(\"hub-orders/verify-all\",{method:\"POST\",body:\"{}\"});ORD=await api(\"hub-orders\");draw();note(r.confirmed+\" paiement(s) confirmé(s) sur \"+r.checked+\" vérifié(s).\")}catch(e){note(e.message,1)}};\n}\n\nfunction orders(){\nconst sel=$(\"#fl\"),cur=sel.value;sel.innerHTML='<option value=\"\">Tous les logiciels</option>'+[...new Set(ORD.map(o=>o.software_code))].map(c=>`<option value=\"${esc(c)}\">${esc(c)}</option>`).join(\"\");sel.value=cur;\nconst q=$(\"#q\").value.trim().toLowerCase(),s=$(\"#fs\").value,l=sel.value,fd=$(\"#fd\").value;\nconst list=ORD.filter(o=>(!s||o.status===s)&&(!l||o.software_code===l)&&(!fd||o.created_at>=fd)&&(!q||[o.client_name,o.client_email,o.client_phone,o.license_key,o.id].join(\" \").toLowerCase().includes(q)));\n$(\"#ol\").innerHTML=list.map(o=>`<div class=\"it\" onclick=\"detail('${o.id}')\"><div class=\"l\"><b>${esc(o.client_name)}</b><span class=\"tag ${o.status}\">${ST[o.status]||o.status}</span></div><div class=\"l\"><small>${esc(o.software_name||o.software_code)} · ${esc((CFG.plans[o.plan]||{}).label||o.plan)}</small><b>${f(o.amount_fcfa)}</b></div><small>${dt(o.created_at)}</small></div>`).join(\"\")||'<div class=\"empty\">Aucune commande.</div>';\n}\n[\"q\",\"fs\",\"fl\",\"fd\"].forEach(i=>$(\"#\"+i).oninput=orders);\n\nfunction detail(id){\nconst o=ORD.find(x=>x.id===id);if(!o)return;const own=ME.role===\"owner\";\nconst kv=(x,y)=>`<div class=\"kv\"><span>${x}</span><span>${y}</span></div>`;\nconst B=(i,c,t)=>`<button class=\"btn ${c}\" style=\"width:100%;margin-top:8px\" id=\"${i}\">${t}</button>`;\nconst dis=o.license_status===\"disabled\";\n$(\"#sh\").innerHTML=`<h2 style=\"margin-top:0\">${esc(o.client_name)} <span class=\"tag ${o.status}\">${ST[o.status]||o.status}</span></h2>\n${kv(\"Logiciel\",esc(o.software_name||o.software_code))}${kv(\"Durée\",esc((CFG.plans[o.plan]||{}).label||o.plan))}${kv(\"Montant\",f(o.amount_fcfa))}${o.promo_code?kv(\"Code promo\",esc(o.promo_code)+\" (−\"+f(o.discount_fcfa)+\")\"):\"\"}${kv(\"Email\",esc(o.client_email))}${kv(\"Téléphone\",esc(o.client_phone))}${kv(\"Créée le\",dt(o.created_at))}${kv(\"Payée le\",dt(o.paid_at))}${kv(\"Expiration\",o.expiration?dt(o.expiration):(o.status===\"paid\"?\"Illimitée\":\"—\"))}${o.license_status?kv(\"Licence\",dis?\"Désactivée\":\"Active\"):\"\"}${kv(\"Réf. FedaPay\",esc(o.payment_ref||\"—\"))}${kv(\"N° de commande\",esc(o.id.slice(0,8)))}\n${o.license_key?`<div class=\"code\">${esc(o.license_key)}</div>${B(\"cp\",\"g\",\"Copier la clé\")}`:\"\"}\n${o.status===\"pending\"?B(\"vf\",\"g\",\"Vérifier auprès de FedaPay\"):\"\"}\n${o.status===\"paid\"?B(\"rs\",\"g\",\"Renvoyer le code par email\"):\"\"}\n${own&&(o.status===\"pending\"||o.status===\"failed\")?B(\"cf\",\"o\",\"Confirmer manuellement\")+B(\"ca\",\"r\",\"Annuler la commande\")+'<p class=\"muted\" style=\"font-size:13px\">Ne confirmez que si vous avez vraiment reçu l’argent.</p>':\"\"}\n${own&&o.status===\"paid\"&&o.license_id?B(\"tg\",\"g\",dis?\"Réactiver la licence\":\"Désactiver la licence\")+B(\"rn\",\"g\",\"Renouveler la licence\")+B(\"rf\",\"r\",\"Marquer comme remboursé\")+'<p class=\"muted\" style=\"font-size:13px\">Le remboursement de l’argent se fait dans FedaPay : ici, la commande est marquée remboursée et la licence désactivée.</p>':\"\"}\n${B(\"cl2\",\"g\",\"Fermer\")}`;\n$(\"#bg\").classList.add(\"on\");\nconst X=id=>$(\"#\"+id);X(\"cl2\").onclick=()=>$(\"#bg\").classList.remove(\"on\");\nif(X(\"cp\"))X(\"cp\").onclick=()=>navigator.clipboard.writeText(o.license_key).then(()=>X(\"cp\").textContent=\"Clé copiée\");\nconst go=async(p,ask,msg)=>{if(ask&&!confirm(ask))return;try{const r=await api(p,{method:\"POST\",body:\"{}\"});ORD=await api(\"hub-orders\");draw();$(\"#bg\").classList.remove(\"on\");note(typeof msg===\"function\"?msg(r):msg)}catch(e){note(e.message,1)}};\nconst h=\"hub-orders/\"+o.id+\"/\";\nif(X(\"vf\"))X(\"vf\").onclick=()=>go(h+\"verify\",0,r=>\"Statut après vérification : \"+(ST[r.status]||r.status));\nif(X(\"rs\"))X(\"rs\").onclick=()=>go(h+\"resend\",0,r=>r.sent?\"Email envoyé au client.\":\"Email non envoyé (service email non configuré). Clé : \"+r.key);\nif(X(\"cf\"))X(\"cf\").onclick=()=>go(h+\"confirm\",\"Créer la licence pour cette commande ?\",\"Licence créée.\");\nif(X(\"ca\"))X(\"ca\").onclick=()=>go(h+\"cancel\",\"Annuler cette commande ?\",\"Commande annulée.\");\nif(X(\"tg\"))X(\"tg\").onclick=()=>go(\"licenses/\"+o.license_id+\"/toggle\",0,\"Licence mise à jour.\");\nif(X(\"rn\"))X(\"rn\").onclick=()=>go(\"licenses/\"+o.license_id+\"/renew\",\"Prolonger cette licence d’une durée ?\",\"Licence renouvelée.\");\nif(X(\"rf\"))X(\"rf\").onclick=()=>go(h+\"refund\",\"Marquer remboursée et désactiver la licence ?\",\"Commande marquée remboursée.\");\n}\n$(\"#bg\").onclick=e=>{if(e.target.id===\"bg\")$(\"#bg\").classList.remove(\"on\")};\n\n$(\"#csv\").onclick=()=>{const h=[\"Date\",\"Statut\",\"Client\",\"Email\",\"Téléphone\",\"Logiciel\",\"Durée\",\"Montant FCFA\",\"Clé\",\"Expiration\"];const q=v=>'\"'+String(v==null?\"\":v).replace(/\"/g,'\"\"')+'\"';const rows=ORD.map(o=>[o.created_at,o.status,o.client_name,o.client_email,o.client_phone,o.software_code,o.plan,o.amount_fcfa,o.license_key,o.expiration].map(q).join(\",\"));const a=document.createElement(\"a\");a.href=URL.createObjectURL(new Blob([\"\\ufeff\"+[h.map(q).join(\",\")].concat(rows).join(\"\\n\")],{type:\"text/csv\"}));a.download=\"commandes-hub.csv\";a.click()};\n\nfunction catalog(){\n$(\"#plans\").innerHTML=Object.entries(CFG.plans).map(([k,p])=>`<div><label>${esc(p.label)}</label><input type=\"number\" min=\"100\" step=\"500\" data-p=\"${k}\" value=\"${p.price}\"></div>`).join(\"\");\n$(\"#plans\").oninput=e=>{const k=e.target.dataset.p;if(k)CFG.plans[k].price=Math.round(+e.target.value)||0};\n$(\"#prods\").innerHTML=CFG.products.map((p,i)=>`<div class=\"pe\"><input type=\"checkbox\" data-i=\"${i}\" data-f=\"on\" ${p.on?\"checked\":\"\"} title=\"Visible sur le hub\"><input data-i=\"${i}\" data-f=\"e\" value=\"${esc(p.e)}\"><input data-i=\"${i}\" data-f=\"t\" value=\"${esc(p.t)}\"><input data-i=\"${i}\" data-f=\"nom\" value=\"${esc(p.nom)}\"><span class=\"c\">${esc(p.code)}</span></div><div class=\"pr\" style=\"grid-template-columns:repeat(4,1fr);padding:2px 0 8px\">${Object.keys(CFG.plans).map(k=>`<div><small class=\"muted\">${esc(CFG.plans[k].label)}</small><input type=\"number\" placeholder=\"${CFG.plans[k].price}\" data-i=\"${i}\" data-k=\"${k}\" value=\"${(p.prices&&p.prices[k])||\"\"}\"></div>`).join(\"\")}</div>`).join(\"\")+`<p class=\"muted\" style=\"font-size:13px;margin-bottom:0\">Case cochée : visible. Colonnes : emoji, titre, nom, préfixe. Les 4 petites cases sont des prix propres au logiciel ; vides, le tarif général s’applique.</p>`;\n$(\"#prods\").oninput=$(\"#prods\").onchange=e=>{const t=e.target,i=t.dataset.i;if(i==null)return;if(t.dataset.k){const p=CFG.products[i];p.prices=p.prices||{};p.prices[t.dataset.k]=Math.round(+t.value)||0}else CFG.products[i][t.dataset.f]=t.type===\"checkbox\"?t.checked:t.value};\n}\n$(\"#na\").onclick=()=>{const c=$(\"#nc\").value.trim().toUpperCase(),n=$(\"#nn\").value.trim();if(!c||!n)return note(\"Préfixe et nom requis.\",1);if(CFG.products.some(p=>p.code===c))return note(\"Ce préfixe existe déjà.\",1);CFG.products.push({code:c,nom:n,t:$(\"#nt\").value.trim()||n,e:$(\"#ne\").value.trim()||\"📦\",on:true});[\"nc\",\"nn\",\"nt\",\"ne\"].forEach(i=>$(\"#\"+i).value=\"\");catalog();note(\"Ajouté : pensez à enregistrer.\")};\n\nfunction clients(){\nconst q=$(\"#cq\").value.trim().toLowerCase(),m={};\nORD.forEach(o=>{const k=(o.client_email||\"\").toLowerCase();const c=m[k]=m[k]||{n:o.client_name,e:o.client_email,p:o.client_phone,a:0,t:0,d:o.created_at};if(o.status===\"paid\"){c.a++;c.t+=o.amount_fcfa}});\nconst l=Object.values(m).filter(c=>!q||[c.n,c.e,c.p].join(\" \").toLowerCase().includes(q)).sort((a,b)=>b.t-a.t);\n$(\"#cl\").innerHTML=l.map(c=>`<div class=\"it\" style=\"cursor:default\"><div class=\"l\"><b>${esc(c.n)}</b><b>${f(c.t)}</b></div><small>${esc(c.e)} · ${esc(c.p)}</small><br><small>${c.a} achat(s) payé(s)</small></div>`).join(\"\")||'<div class=\"empty\">Aucun client.</div>';\n}\n$(\"#cq\").oninput=clients;\n\nfunction reglages(){\n$(\"#open\").checked=!!CFG.open;$(\"#md\").value=CFG.max_devices;\nconst T=CFG.texts||{},sv=CFG.services||{};$(\"#twa\").value=T.whatsapp||\"\";$(\"#tem\").value=T.email||\"\";$(\"#ttc\").value=T.terms||\"\";\nconst ok=(b,y,n)=>`<span class=\"${b?\"paid\":\"failed\"}\">${b?y:n}</span>`;\n$(\"#fp\").innerHTML=`<div class=\"kv\"><span>FedaPay : clé secrète</span>${ok(CFG.fedapay.configured,\"Renseignée\",\"Absente (test manuel)\")}</div><div class=\"kv\"><span>Mode FedaPay</span><span><b>${CFG.fedapay.mode===\"live\"?\"Réel (live)\":\"Test (sandbox)\"}</b></span></div><div class=\"kv\"><span>Emails (Resend)</span>${ok(sv.email,\"Activés\",\"Non configurés\")}</div><div class=\"kv\"><span>Alertes Telegram</span>${ok(sv.telegram,\"Activées\",\"Non configurées\")}</div><p class=\"muted\" style=\"font-size:13px;margin-bottom:0\">Les clés se règlent dans le code du Worker, tout en haut du fichier.</p>`;\nconst o=location.origin;\n$(\"#lk\").innerHTML=`<div class=\"kv\"><span>Page du hub</span><span>${o}/hub</span></div><div class=\"kv\"><span>Webhook FedaPay</span><span>${o}/api/hub/webhook</span></div>`;\n$(\"#sv4\").hidden=ME.role!==\"owner\";\n}\nconst save=async()=>{CFG.open=$(\"#open\").checked;CFG.max_devices=Math.max(1,Math.round(+$(\"#md\").value)||1);CFG.texts={whatsapp:$(\"#twa\").value.trim(),email:$(\"#tem\").value.trim(),terms:$(\"#ttc\").value.trim()};try{CFG=await api(\"hub-config\",{method:\"POST\",body:JSON.stringify(CFG)});draw();note(\"Enregistré.\")}catch(e){note(e.message,1)}};\n$(\"#sv2\").onclick=$(\"#sv4\").onclick=save;\nasync function promos(){\nconst l=await api(\"hub-promos\");\n$(\"#plist\").innerHTML=l.map(p=>`<div class=\"it\" style=\"cursor:default\"><div class=\"l\"><b>${esc(p.code)}</b><span class=\"tag ${p.active?\"paid\":\"cancelled\"}\">${p.active?\"Actif\":\"Désactivé\"}</span></div><small>${p.kind===\"percent\"?p.value+\" %\":f(p.value)} · utilisé ${p.uses}${p.max_uses?\"/\"+p.max_uses:\"\"} fois${p.expires_at?\" · expire le \"+new Date(p.expires_at).toLocaleDateString(\"fr-FR\"):\"\"}</small><div style=\"margin-top:8px;display:flex;gap:8px\"><button class=\"btn g s\" data-pt=\"${esc(p.code)}\">${p.active?\"Désactiver\":\"Activer\"}</button><button class=\"btn r s\" data-pd=\"${esc(p.code)}\">Supprimer</button></div></div>`).join(\"\")||'<div class=\"empty\">Aucun code promo.</div>';\n}\n$(\"#plist\").onclick=async e=>{const t=e.target.dataset;try{if(t.pt)await api(\"hub-promos/\"+t.pt+\"/toggle\",{method:\"POST\",body:\"{}\"});else if(t.pd){if(!confirm(\"Supprimer ce code ?\"))return;await api(\"hub-promos/\"+t.pd,{method:\"DELETE\"})}else return;promos()}catch(x){note(x.message,1)}};\n$(\"#pnew\").onclick=async()=>{try{await api(\"hub-promos\",{method:\"POST\",body:JSON.stringify({code:$(\"#pcode\").value,kind:$(\"#pkind\").value,value:+$(\"#pval\").value,max_uses:+$(\"#pmax\").value||0,expires_at:$(\"#pexp\").value||null})});[\"pcode\",\"pval\"].forEach(i=>$(\"#\"+i).value=\"\");promos();note(\"Code créé.\")}catch(x){note(x.message,1)}};\nasync function team(){\nconst [s,l]=await Promise.all([api(\"hub-staff\"),api(\"hub-audit\")]);\n$(\"#slist\").innerHTML=s.map(x=>`<div class=\"row\"><span><b>${esc(x.name)}</b> <small class=\"muted\">${esc(x.role)}</small></span><button class=\"btn r s\" data-sd=\"${esc(x.id)}\">Supprimer</button></div>`).join(\"\");\n$(\"#alog\").innerHTML=l.map(x=>`<div class=\"row\"><span><b>${esc(x.action)}</b><br><small class=\"muted\">${esc(x.who)} · ${esc(x.detail||\"\")}</small></span><small class=\"muted\">${dt(x.at)}</small></div>`).join(\"\")||'<div class=\"empty\">Rien pour le moment.</div>';\n}\n$(\"#slist\").onclick=async e=>{const id=e.target.dataset.sd;if(!id||!confirm(\"Supprimer cet accès ?\"))return;try{await api(\"hub-staff/\"+id,{method:\"DELETE\"});team()}catch(x){note(x.message,1)}};\n$(\"#snew\").onclick=async()=>{try{const r=await api(\"hub-staff\",{method:\"POST\",body:JSON.stringify({name:$(\"#sname\").value})});$(\"#sname\").value=\"\";$(\"#skey\").innerHTML=`<p>Clé de l’agent (affichée une seule fois) :</p><div class=\"code\">${esc(r.key)}</div>`;team()}catch(x){note(x.message,1)}};\n</script>\n</body>\n</html>\n";
