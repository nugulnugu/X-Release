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

function cookieSerialize(name: string, value: string, opt: { maxAge?: number } = {}) {
  const attrs = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ];
  if (opt.maxAge) attrs.push(`Max-Age=${opt.maxAge}`);
  return attrs.join("; ");
}

export default {
  async fetch(req: Request, env: Env) {
    const url = new URL(req.url);

    // 1) 세션 확인
    if (url.pathname === "/api/check-session") {
      const token = (req.headers.get("Cookie") || "")
        .split(";").map(s=>s.trim()).find(s=>s.startsWith("xgate="))?.split("=")[1];
      if (!token) return json({ ok:false }, { status: 401 });
      const payload = await verifyJWT(token, env.JWT_SECRET);
      if (!payload) return json({ ok:false }, { status: 401 });
      return json({ ok:true, payload });
    }

    // 2) 로그아웃
    if (url.pathname === "/api/logout") {
      return new Response("OK", {
        headers: { "Set-Cookie": cookieSerialize("xgate", "", { maxAge: 0 }) }
      });
    }

    // 3) 게이트(백엔드판정 API; 프론트에서 직접 호출해도 되고 콜백에서만 써도 됨)
    if (url.pathname === "/api/check-gate" && req.method === "POST") {
      const body = await req.json().catch(()=>({}));
      const userId = String(body.userId || "");
      const code   = body.code ? String(body.code) : undefined;

      const { allow, invites } = parseLists(env);
      const invited = code && Array.isArray(invites[code]) && invites[code].includes(userId);
      if (allow.has(userId) || invited) {
        const token = await signJWT({ userId }, env.JWT_SECRET);
        return new Response(JSON.stringify({ ok:true }), {
          headers: { 
            "content-type":"application/json",
            "Set-Cookie": cookieSerialize("xgate", token, { maxAge: 60*60*24*7 }) // 7일
          }
        });
      }
      return json({ ok:false }, { status: 403 });
    }

    // 4) 로그인 시작 (여기서 X OAuth 2.0 Authorization Code with PKCE 시작)
    if (url.pathname === "/auth/login") {
      // TODO: state/pkce 생성 후 X로 리다이렉트
      // 데모: 아직 OAuth 미연결 상태라 홈으로 안내
      return Response.redirect(env.HOME_PAGE_URL, 302);
    }

    // 5) OAuth 콜백
    if (url.pathname === "/auth/callback") {
      // TODO:
      // - code 교환 → 사용자 프로필 얻기 → "숫자 userId" 추출
      // - 아래 userId에 실제 값 넣기
      const userId = ""; // ← 트위터 숫자 ID를 여기 세팅

      const code = url.searchParams.get("invite") || undefined; // 필요 시 쿼리로 초대코드 전송
      const { allow, invites } = parseLists(env);
      const invited = code && Array.isArray(invites[code]) && invites[code].includes(userId);

      if (userId && (allow.has(userId) || invited)) {
        const token = await signJWT({ userId }, env.JWT_SECRET);
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

    return new Response("OK");
  }
};

function withCORS(res: Response, origin: string) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", origin); // 정확한 오리진(별표 X)
  h.set("Access-Control-Allow-Credentials", "true");
  h.set("Vary", "Origin");
  return new Response(res.body, { ...res, headers: h });
}
