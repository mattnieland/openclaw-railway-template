import net from "node:net";

function validForwardedHost(value, fallback) {
  if (typeof value !== "string" || value.includes(",")) return fallback;

  try {
    const url = new URL(`https://${value.trim()}`);
    if (
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      url.username ||
      url.password
    ) {
      return fallback;
    }
    return url.host;
  } catch {
    return fallback;
  }
}

// Paths where the caller's own bearer token must reach the gateway untouched.
// /hooks/ carries webhook secrets; /a2a/ and /.well-known/ belong to the A2A
// channel plugin, which authenticates peers by their own per-peer tokens.
const CALLER_AUTH_PREFIXES = ["/hooks/", "/a2a/", "/.well-known/"];

export function shouldInjectGatewayAuth(url) {
  if (typeof url !== "string") return true;
  const pathname = url.split(/[?#]/, 1)[0];
  return !CALLER_AUTH_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

export function rebuildForwardedHeaders(proxyReq, req, railwayPublicDomain) {
  for (const name of proxyReq.getHeaderNames()) {
    const lower = name.toLowerCase();
    if (
      lower === "forwarded" ||
      lower === "x-real-ip" ||
      lower.startsWith("x-forwarded-")
    ) {
      proxyReq.removeHeader(name);
    }
  }

  if (!railwayPublicDomain) return;

  const realIp = req.headers["x-real-ip"];
  const clientIp =
    typeof realIp === "string" && net.isIP(realIp.trim())
      ? realIp.trim()
      : "127.0.0.1";
  const forwardedHost = validForwardedHost(
    req.headers["x-forwarded-host"],
    railwayPublicDomain,
  );

  proxyReq.setHeader("X-Forwarded-For", clientIp);
  proxyReq.setHeader("X-Forwarded-Proto", "https");
  proxyReq.setHeader("X-Forwarded-Host", forwardedHost);
}
