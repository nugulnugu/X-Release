export interface Env {
  // 시크릿/설정(대시보드 또는 wrangler secret으로 바인딩 권장)
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  OAUTH_REDIRECT_URL: string; // 예: https://x-gate.your-subdomain.workers.dev/auth/callback
  JWT_SECRET: string;

  ALLOWLIST_JSON: string;
  INVITES_JSON: string;
  PROTECTED_PAGE_URL: string;
  HOME_PAGE_URL: string;

  // 새로 추가: CORS 허용 오리진(정확한 스킴+호스트). 여러 개면 콤마로 구분.
  ALLOWED_ORIGIN?: string; // 예: "https://nugulnugu.github.io"
}

function json(data: any, init: ResponseInit = {}) {
  return new Response(JSON.stringify(data), {
    headers: { "content-type": "application/json" },
    ...init,
  });
}

// --- 간단 JWT 유틸(데모용; 실제론 라이브러리 사용 권장)
async function signJWT(payload: object, secret: string) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
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
      "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(`${h}.${b}`));
    const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
    if (sig !== s) return null;
    return JSON.parse(atob(b));
  } catch {
    return null;
  }
}

function parseLists(env: Env) {
  const allow = new Set<string>(JSON.parse(env.ALLOWLIST_JSON || "[]"));
  const invites = JSON.parse(env.INVITES_JSON || "{}") as Record<string, string[]>;
  return { allow, invites };
}

// ⚠️ 크로스 사이트에서 쿠키 전송을 허용하려면 SameSite=None; Secure 가 필수입니다.
function cookieSerialize(name: string, value: string, opt: { maxAge?: number } = {}) {
  const attrs = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None; Secure; HttpOnly" // ← Lax이면 cross-site fetch에 쿠키가 안 실립니다.
  ];
  if (opt.maxAge) attrs.push(`Max-Age=${opt.maxAge}`);
  return attrs.join("; ");
}

// ----- CORS 유틸 -----
function splitOrigins(val?: string) {
  return (val || "").split(",").map(s => s.trim()).filter(Boolean);
}
function isAllowedOrigin(origin: string | null, env: Env) {
  if (!origin) return false;
  const list = splitOrigins(env.ALLOWED_ORIGIN);
  return list.length ? list.includes(origin) : false;
}

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


export default {
  async fetch(req: Request, env: Env) {
    const url = new URL(req.url);
    const reqOrigin = req.headers.get("Origin");
    const origin = getAllowedOrigin(reqOrigin, env);
    const allowed = isAllowedOrigin(origin, env) ? origin! : null;

    // 공통 래퍼: 허용 오리진이면 CORS 헤더를 붙여 반환
    const respond = (res: Response) => (allowed ? applyCORS(res, allowed) : res);
    const jsonRespond = (data: any, init: ResponseInit = {}) => respond(json(data, init));

    // --- OPTIONS 프리플라이트 처리 ---
    if (req.method === "OPTIONS") {
      // 허용 오리진일 때만 CORS 응답을 붙임
      if (allowed) {
        const acrh = req.headers.get("Access-Control-Request-Headers") || "content-type";
        const headers = new Headers({
          "Access-Control-Allow-Origin": allowed,
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
          "Access-Control-Allow-Headers": acrh,
          "Vary": "Origin"
        });
        return new Response(null, { headers });
      }
      // 허용 오리진이 아니면 빈 204 응답
      return new Response(null, { status: 204 });
    }

    // 1) 세션 확인
    if (url.pathname === "/api/check-session") {
      const token = (req.headers.get("Cookie") || "")
        .split(";").map(s => s.trim()).find(s => s.startsWith("xgate="))?.split("=")[1];
      if (!token) return jsonRespond({ ok:false }, { status: 401 });
      const payload = await verifyJWT(token, env.JWT_SECRET);
      if (!payload) return jsonRespond({ ok:false }, { status: 401 });
      return jsonRespond({ ok:true, payload });
    }

    // 2) 로그아웃
    if (url.pathname === "/api/logout") {
      return respond(new Response("OK", {
        headers: { "Set-Cookie": cookieSerialize("xgate", "", { maxAge: 0 }) }
      }));
    }

    // 3) 게이트(백엔드 판정)
    if (url.pathname === "/api/check-gate" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      const userId = String((body as any).userId || "");
      const code   = (body as any).code ? String((body as any).code) : undefined;

      const { allow, invites } = parseLists(env);
      const invited = code && Array.isArray(invites[code]) && invites[code].includes(userId);

      if (allow.has(userId) || invited) {
        const token = await signJWT({ userId }, env.JWT_SECRET);
        return respond(new Response(JSON.stringify({ ok:true }), {
          headers: {
            "content-type": "application/json",
            "Set-Cookie": cookieSerialize("xgate", token, { maxAge: 60*60*24*7 }) // 7일
          }
        }));
      }
      return jsonRespond({ ok:false }, { status: 403 });
    }

    // 4) 로그인 시작 (OAuth PKCE 시작 지점)
    if (url.pathname === "/auth/login") {
      // TODO: state/pkce 생성 후 X로 리다이렉트
      return Response.redirect(env.HOME_PAGE_URL, 302);
    }

    // 5) OAuth 콜백
    if (url.pathname === "/auth/callback") {
      // TODO:
      // - code 교환 → 사용자 프로필 → "숫자 userId" 추출
      const userId = ""; // ← 트위터 숫자 ID로 교체

      const code = url.searchParams.get("invite") || undefined;
      const { allow, invites } = parseLists(env);
      const invited = code && Array.isArray(invites[code]) && invites[code].includes(userId);

      if (userId && (allow.has(userId) || invited)) {
        const token = await signJWT({ userId }, env.JWT_SECRET);
        // 콜백은 브라우저 네비게이션(리다이렉트)이므로 CORS 불필요
        return new Response(null, {
          status: 302,
          headers: {
            "Set-Cookie": cookieSerialize("xgate", token, { maxAge: 60*60*24*7 }),
            "Location": env.PROTECTED_PAGE_URL
          }
        });
      }
      return Response.redirect(env.HOME_PAGE_URL, 302);
    }

    return respond(new Response("OK"));
  }
};
