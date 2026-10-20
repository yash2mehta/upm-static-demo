// Login gate for the whole site.
//
// Runs on Netlify's edge in front of every request. Until a visitor has a valid
// signed session cookie, the only thing they can load is the login page (plus the
// logo images it uses). Nothing from the static site is served to them.
//
// Sign-in methods:
//   1. Username + password, checked against the LOGIN_USERS environment variable.
//   2. Google, restricted to GOOGLE_ALLOWED_DOMAIN and the GOOGLE_ALLOWED_EMAILS list.
//
// Environment variables (Netlify > Site configuration > Environment variables):
//   SESSION_SECRET         long random string used to sign session cookies (required)
//   LOGIN_USERS            "alice:password1,bob:password2" (optional; omit to disable)
//   GOOGLE_CLIENT_ID       OAuth client ID from Google Cloud (optional; omit to disable)
//   GOOGLE_CLIENT_SECRET   OAuth client secret from Google Cloud
//   GOOGLE_ALLOWED_DOMAIN  Google Workspace domain, e.g. "stratagile.com"
//   GOOGLE_ALLOWED_EMAILS  "a@stratagile.com,b@stratagile.com", or "*" for everyone in the domain

declare const Netlify: { env: { get(key: string): string | undefined } };
type Context = { next(): Promise<Response> };

const SESSION_COOKIE = "upm_session";
const STATE_COOKIE = "upm_oauth_state";
const SESSION_HOURS = 12;

// Files the login page itself needs, served without a session.
const PUBLIC_PATHS = new Set(["/upm-crest.png", "/upm-logo.png", "/robots.txt"]);

const env = (key: string) => (Netlify.env.get(key) ?? "").trim();

export default async (request: Request, context: Context) => {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/auth/login" && request.method === "POST") return passwordLogin(request);
  if (path === "/auth/google") return googleStart(url);
  if (path === "/auth/google/callback") return googleCallback(request, url);
  if (path === "/auth/logout") return logout();
  if (PUBLIC_PATHS.has(path)) return context.next();

  if (await readSession(request)) return context.next();

  // Not signed in. Page navigations get the login form; everything else
  // (scripts, styles, data files) gets a bare 401.
  const wantsHtml = (request.headers.get("accept") ?? "").includes("text/html");
  if (!wantsHtml) return new Response("Unauthorized", { status: 401, headers: noStore() });
  return loginPage({ next: path + url.search, status: 401 });
};

export const config = { path: "/*" };

// ---------- username + password ----------

async function passwordLogin(request: Request) {
  const form = await request.formData();
  const username = String(form.get("username") ?? "").trim();
  const password = String(form.get("password") ?? "");
  const next = safeNext(String(form.get("next") ?? "/"));

  const users = parseUsers(env("LOGIN_USERS"));
  const expected = users.get(username.toLowerCase());
  // Always run the comparison so timing doesn't reveal which usernames exist.
  const ok = await safeEqual(password, expected ?? crypto.randomUUID());

  if (!username || !password || expected === undefined || !ok) {
    return loginPage({ next, status: 401, error: "Incorrect username or password." });
  }
  return startSession(username, next);
}

function parseUsers(raw: string) {
  const users = new Map<string, string>();
  for (const entry of raw.split(",")) {
    const i = entry.indexOf(":");
    if (i > 0) users.set(entry.slice(0, i).trim().toLowerCase(), entry.slice(i + 1).trim());
  }
  return users;
}

// ---------- Google sign-in ----------

function googleStart(url: URL) {
  const clientId = env("GOOGLE_CLIENT_ID");
  if (!clientId) return loginPage({ status: 500, error: "Google sign-in is not configured." });

  const state = randomToken();
  const next = safeNext(url.searchParams.get("next") ?? "/");
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: `${url.origin}/auth/google/callback`,
    response_type: "code",
    scope: "openid email profile",
    state,
    prompt: "select_account",
  });
  // "hd" makes Google's account picker show only accounts from this domain.
  // It is a UI hint only; the callback re-checks the domain on the token.
  const domain = env("GOOGLE_ALLOWED_DOMAIN");
  if (domain) params.set("hd", domain);

  const headers = noStore();
  headers.set("Location", `https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  headers.append(
    "Set-Cookie",
    cookie(STATE_COOKIE, `${state}|${encodeURIComponent(next)}`, { maxAge: 600, path: "/auth" }),
  );
  return new Response(null, { status: 302, headers });
}

async function googleCallback(request: Request, url: URL) {
  const [savedState, savedNext] = (getCookie(request, STATE_COOKIE) ?? "").split("|");
  const next = safeNext(decodeURIComponent(savedNext ?? "/"));
  const fail = (error: string, status = 403) => {
    const res = loginPage({ next, status, error });
    res.headers.append("Set-Cookie", cookie(STATE_COOKIE, "", { maxAge: 0, path: "/auth" }));
    return res;
  };

  if (url.searchParams.get("error")) return fail("Google sign-in was cancelled.", 401);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state || !savedState || state !== savedState) {
    return fail("Your sign-in session expired. Please try again.", 400);
  }

  const clientId = env("GOOGLE_CLIENT_ID");
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: env("GOOGLE_CLIENT_SECRET"),
      redirect_uri: `${url.origin}/auth/google/callback`,
      grant_type: "authorization_code",
    }),
  });
  if (!tokenRes.ok) return fail("Google sign-in failed. Please try again.", 502);
  const { id_token } = await tokenRes.json();

  // The ID token came straight from Google's token endpoint over TLS, so its
  // claims can be trusted without verifying the signature (OpenID Connect 3.1.3.7).
  let claims: Record<string, unknown>;
  try {
    claims = JSON.parse(new TextDecoder().decode(base64urlDecode(String(id_token).split(".")[1])));
  } catch {
    return fail("Google sign-in failed. Please try again.", 502);
  }

  const email = String(claims.email ?? "").toLowerCase();
  const validToken =
    ["https://accounts.google.com", "accounts.google.com"].includes(String(claims.iss)) &&
    claims.aud === clientId &&
    Number(claims.exp) * 1000 > Date.now() &&
    claims.email_verified === true;
  if (!validToken || !isAllowedGoogleUser(email, String(claims.hd ?? ""))) {
    return fail(`${email || "This account"} is not allowed to access this site.`);
  }

  const res = await startSession(email, next);
  res.headers.append("Set-Cookie", cookie(STATE_COOKIE, "", { maxAge: 0, path: "/auth" }));
  return res;
}

function isAllowedGoogleUser(email: string, hostedDomain: string) {
  const domain = env("GOOGLE_ALLOWED_DOMAIN").toLowerCase();
  if (!domain || hostedDomain.toLowerCase() !== domain || !email.endsWith(`@${domain}`)) return false;

  const allowed = env("GOOGLE_ALLOWED_EMAILS").toLowerCase();
  if (allowed === "*") return true; // everyone in the Workspace domain
  return allowed.split(",").map((e) => e.trim()).includes(email);
}

// ---------- sessions ----------

async function startSession(user: string, next: string) {
  const payload = base64urlEncode(
    new TextEncoder().encode(JSON.stringify({ sub: user, exp: Date.now() + SESSION_HOURS * 3600_000 })),
  );
  const headers = noStore();
  headers.set("Location", next);
  headers.append(
    "Set-Cookie",
    cookie(SESSION_COOKIE, `${payload}.${await sign(payload)}`, { maxAge: SESSION_HOURS * 3600 }),
  );
  return new Response(null, { status: 303, headers });
}

async function readSession(request: Request) {
  const value = getCookie(request, SESSION_COOKIE);
  if (!value) return null;
  const [payload, signature] = value.split(".");
  if (!payload || !signature) return null;
  try {
    const key = await hmacKey();
    const valid = await crypto.subtle.verify(
      "HMAC", key, base64urlDecode(signature), new TextEncoder().encode(payload),
    );
    if (!valid) return null;
    const session = JSON.parse(new TextDecoder().decode(base64urlDecode(payload)));
    return session.exp > Date.now() ? session : null;
  } catch {
    return null;
  }
}

function logout() {
  const headers = noStore();
  headers.set("Location", "/");
  headers.append("Set-Cookie", cookie(SESSION_COOKIE, "", { maxAge: 0 }));
  return new Response(null, { status: 303, headers });
}

async function hmacKey() {
  const secret = env("SESSION_SECRET");
  if (secret.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters");
  return crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"],
  );
}

async function sign(data: string) {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(), new TextEncoder().encode(data));
  return base64urlEncode(new Uint8Array(sig));
}

// ---------- helpers ----------

async function safeEqual(a: string, b: string) {
  const digest = async (s: string) =>
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// Only allow redirects back to a path on this site.
function safeNext(next: string) {
  return next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") && !next.startsWith("/auth/")
    ? next
    : "/";
}

function cookie(name: string, value: string, opts: { maxAge: number; path?: string }) {
  return `${name}=${value}; Path=${opts.path ?? "/"}; Max-Age=${opts.maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function getCookie(request: Request, name: string) {
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return undefined;
}

function noStore() {
  return new Headers({ "Cache-Control": "no-store" });
}

function randomToken() {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(24)));
}

function base64urlEncode(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(s: string) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

// ---------- login page ----------

function loginPage({ next = "/", status = 200, error = "" }: { next?: string; status?: number; error?: string }) {
  const nextValue = escapeHtml(safeNext(next));
  const passwordEnabled = env("LOGIN_USERS") !== "";
  const googleEnabled = env("GOOGLE_CLIENT_ID") !== "";

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign in · UPM Student Account &amp; Billing System</title>
<style>
  :root { --brand: #c43047; --brand-dark: #a3243a; --ink: #0f1317; --muted: #6f757c; --line: #e3e6e8; --bg: #f4f5f6; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px 16px;
         background: var(--bg); color: var(--ink);
         font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .card { width: 100%; max-width: 400px; background: #fff; border: 1px solid var(--line);
          border-radius: 14px; padding: 36px 32px; box-shadow: 0 8px 30px rgba(15,19,23,.06); }
  .crest { display: block; height: 72px; margin: 0 auto 16px; }
  h1 { font-size: 20px; margin: 0; text-align: center; }
  .sub { color: var(--muted); text-align: center; margin: 4px 0 28px; font-size: 14px; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 0 0 6px; }
  input[type=text], input[type=password] { width: 100%; padding: 11px 12px; font: inherit; color: inherit;
         border: 1px solid #cfd4d8; border-radius: 8px; margin-bottom: 16px; background: #fff; }
  input:focus { outline: 2px solid var(--brand); outline-offset: 1px; border-color: transparent; }
  .btn { display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%;
         padding: 11px 16px; font: inherit; font-weight: 600; border-radius: 8px; cursor: pointer;
         text-decoration: none; }
  .btn-primary { background: var(--brand); color: #fff; border: 0; }
  .btn-primary:hover { background: var(--brand-dark); }
  .btn-google { background: #fff; color: var(--ink); border: 1px solid #cfd4d8; }
  .btn-google:hover { background: #f8f9fa; }
  .btn:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; }
  .divider { display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 13px; margin: 22px 0; }
  .divider::before, .divider::after { content: ""; flex: 1; height: 1px; background: var(--line); }
  .error { background: #fdeff1; color: #8f1d30; border: 1px solid #f3c6cf; border-radius: 8px;
           padding: 10px 12px; font-size: 14px; margin-bottom: 20px; }
  .note { color: var(--muted); font-size: 12px; text-align: center; margin: 14px 0 0; }
</style>
</head>
<body>
<main class="card">
  <img class="crest" src="/upm-crest.png" alt="Universiti Putra Malaysia">
  <h1>Student Account &amp; Billing System</h1>
  <p class="sub">Sign in to continue</p>
  ${error ? `<div class="error" role="alert">${escapeHtml(error)}</div>` : ""}
  ${passwordEnabled ? `
  <form method="post" action="/auth/login">
    <input type="hidden" name="next" value="${nextValue}">
    <label for="username">Username</label>
    <input id="username" name="username" type="text" autocomplete="username" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button class="btn btn-primary" type="submit">Sign in</button>
  </form>` : ""}
  ${passwordEnabled && googleEnabled ? `<div class="divider">or</div>` : ""}
  ${googleEnabled ? `
  <a class="btn btn-google" href="/auth/google?next=${encodeURIComponent(safeNext(next))}">
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>
    Sign in with Google
  </a>` : ""}
  ${!passwordEnabled && !googleEnabled ? `<div class="error">No sign-in method is configured.</div>` : ""}
</main>
</body>
</html>`;

  const headers = noStore();
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(html, { status, headers });
}
