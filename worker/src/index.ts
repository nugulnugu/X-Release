export interface Env {
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  OAUTH_REDIRECT_URL: string;
  JWT_SECRET: string;

  ALLOWLIST_JSON: string;
  INVITES_JSON: string;
  PROTECTED_PAGE_URL: string;
  HOME_PAGE_URL: string;

  // CORS 허용 오리진(콤마로 여러 개 가능)
  ALLOWED_ORIGIN: string;
}

/* ---------- small utils ---------- */
function json(data: any, init: ResponseInit = {}) {
  return new Response(JSON.stringify(data), {
    headers: { "content-type": "application/json" },
    ...init,
  });
}

/* ---------- JWT (demo-safe) ---------- */
async function signJWT(payload: object, secret: string) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(`${header}.${body}`));
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
  return `${header}.${body}.${sig}`;
}

async function verifyJWT(token: string, secret: string) {
  try {
    const [h, b, s] = token.split(".");
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(`${h}.${b}`));
    const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
    if (sig !== s) return null;
    return JSON.parse(atob(b));
  } catch {
    return null;
  }
}

/* ---------- allowlist/invites ---------- */
function parseLists(env: Env) {
  const allow = new Set<string>(JSON.parse(env.ALLOWLIST_JSON || "[]"));
  const invites = JSON.parse(env.INVITES_JSON || "{}") as Record<string, string[]>;
  return { allow, invites };
}

/* ---------- cookies ---------- */
// 크로스 사이트 쿠키 전송을 위해 SameSite=None; Secure; HttpOnly 필수
function cookieSerialize(name: string, value: string, opt: { maxAge?: number } = {}) {
  const attrs = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ];
  if (opt.maxAge) attrs.push(`Max-Age=${opt.maxAge}`);
  return attrs.join("; ");
}

/* ---------- CORS helpers (safe clone) ---------- */
function applyCORS(res: Response, origin: string) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Credentials", "true");
  h.set("Vary", "Origin");
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: h,
  });
}
function splitOrigins(val?: string) {
  return (val || "").split(",").map((s) => s.trim()).filter(Boolean);
}
function getAllowedOrigin(reqOrigin: string | null, env: Env) {
  if (!reqOrigin) return null;
  const list = splitOrigins(env.ALLOWED_ORIGIN);
  return list.length && list.includes(reqOrigin) ? reqOrigin : null;
}

/* ---------- PKCE helpers ---------- */
function base64url(buf: ArrayBuffer | Uint8Array) {
  const arr = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  const b64 = btoa(String.fromCharCode(...arr));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randStr(len = 32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return base64url(arr);
}
async function sha256Base64url(input: string) {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64url(hash);
}
function tmpCookie(name: string, val: string, maxAgeSec = 600) {
  return [
    `${name}=${val}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    `Max-Age=${maxAgeSec}`,
  ].join("; ");
}

/* ---------- worker ---------- */
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(req.url);
      const reqOrigin = req.headers.get("Origin");
      const allowOrigin = getAllowedOrigin(reqOrigin, env);

      const respond = (res: Response) => (allowOrigin ? applyCORS(res, allowOrigin) : res);
      const jsonRespond = (data: any, init: ResponseInit = {}) =>
        respond(json(data, init));

      /* --- debug: check CORS vars at runtime --- */
      if (url.pathname === "/__debug/cors") {
        return jsonRespond({
          origin: reqOrigin,
          allowed_env: env.ALLOWED_ORIGIN || null,
          method: req.method,
        });
      }

      /* --- CORS preflight --- */
      if (req.method === "OPTIONS") {
        if (allowOrigin) {
          const acrh = req.headers.get("Access-Control-Request-Headers") || "content-type";
          return new Response(null, {
            headers: {
              "Access-Control-Allow-Origin": allowOrigin,
              "Access-Control-Allow-Credentials": "true",
              "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
              "Access-Control-Allow-Headers": acrh,
              "Vary": "Origin",
            },
          });
        }
        // 허용 오리진이 아니면 헤더 없이 204 → 브라우저가 CORS 에러를 띄움
        return new Response(null, { status: 204 });
      }

      /* --- 1) 세션 확인 --- */
      if (url.pathname === "/api/check-session") {
        const token = (req.headers.get("Cookie") || "")
          .split(";")
          .map((s) => s.trim())
          .find((s) => s.startsWith("xgate="))
          ?.split("=")[1];
        if (!token) return jsonRespond({ ok: false }, { status: 401 });
        const payload = await verifyJWT(token, env.JWT_SECRET);
        if (!payload) return jsonRespond({ ok: false }, { status: 401 });
        return jsonRespond({ ok: true, payload });
      }

      /* --- 2) 로그아웃 --- */
      if (url.pathname === "/api/logout") {
        return respond(
          new Response("OK", {
            headers: { "Set-Cookie": cookieSerialize("xgate", "", { maxAge: 0 }) },
          })
        );
      }

      /* --- 3) 게이트 --- */
      if (url.pathname === "/api/check-gate" && req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        const userId = String((body as any).userId || "");
        const code = (body as any).code ? String((body as any).code) : undefined;

        const { allow, invites } = parseLists(env);
        const invited = code && Array.isArray(invites[code]) && invites[code].includes(userId);

        if (allow.has(userId) || invited) {
          const token = await signJWT({ userId }, env.JWT_SECRET);
          return respond(
            new Response(JSON.stringify({ ok: true }), {
              headers: {
                "content-type": "application/json",
                "Set-Cookie": cookieSerialize("xgate", token, { maxAge: 60 * 60 * 24 * 7 }), // 7일
              },
            })
          );
        }
        return jsonRespond({ ok: false }, { status: 403 });
      }

      /* --- 4) 로그인 시작 (OAuth 2.0 + PKCE) --- */
      if (url.pathname === "/auth/login") {
        const invite = url.searchParams.get("invite") || "";
        const state = randStr(24);
        const code_verifier = randStr(64);
        const code_challenge = await sha256Base64url(code_verifier);

        const setCookies = [
          tmpCookie("x_state", state),
          tmpCookie("x_cv", code_verifier),
          tmpCookie("x_inv", invite),
        ];

        const params = new URLSearchParams({
          response_type: "code",
          client_id: env.X_CLIENT_ID,
          redirect_uri: env.OAUTH_REDIRECT_URL,
          scope: "users.read",
          state,
          code_challenge,
          code_challenge_method: "S256",
        });

        return new Response(null, {
          status: 302,
          headers: {
            "Set-Cookie": setCookies.join(", "),
            "Location": `https://x.com/i/oauth2/authorize?${params.toString()}`,
          },
        });
      }

      /* --- 5) OAuth 콜백 --- */
      if (url.pathname === "/auth/callback") {
        const code = url.searchParams.get("code") || "";
        const state = url.searchParams.get("state") || "";

        // 임시쿠키 복원
        const cookie = req.headers.get("Cookie") || "";
        const get = (k: string) =>
          cookie
            .split(";")
            .map((s) => s.trim())
            .find((s) => s.startsWith(k + "="))
            ?.split("=")[1] || "";
        const savedState = get("x_state");
        const code_verifier = get("x_cv");
        const invite = get("x_inv") || undefined;

        if (!code || !state || state !== savedState || !code_verifier) {
          return Response.redirect(env.HOME_PAGE_URL, 302);
        }

        // 토큰 교환
        const body = new URLSearchParams({
          grant_type: "authorization_code",
          client_id: env.X_CLIENT_ID,
          redirect_uri: env.OAUTH_REDIRECT_URL,
          code,
          code_verifier,
        });
        if (env.X_CLIENT_SECRET) body.set("client_secret", env.X_CLIENT_SECRET);

        const tokRes = await fetch("https://api.x.com/2/oauth2/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body,
        });
        if (!tokRes.ok) return Response.redirect(env.HOME_PAGE_URL, 302);
        const tok = (await tokRes.json()) as any;
        const access = tok.access_token as string | undefined;
        if (!access) return Response.redirect(env.HOME_PAGE_URL, 302);

        // 사용자 id 조회
        const meRes = await fetch("https://api.x.com/2/users/me", {
          headers: { Authorization: `Bearer ${access}` },
        });
        if (!meRes.ok) return Response.redirect(env.HOME_PAGE_URL, 302);
        const me = (await meRes.json()) as any;
        const userId = me?.data?.id as string | undefined;
        if (!userId) return Response.redirect(env.HOME_PAGE_URL, 302);

        // 게이트 판정
        const { allow, invites } = parseLists(env);
        const invited = invite && Array.isArray(invites[invite]) && invites[invite].includes(userId);

        // 임시쿠키 제거
        const clearTmp = [
          "x_state=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=None",
          "x_cv=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=None",
          "x_inv=; Path=/;_
