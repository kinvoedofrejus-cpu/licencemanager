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
