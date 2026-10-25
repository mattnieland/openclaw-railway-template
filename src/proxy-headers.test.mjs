import assert from "node:assert/strict";
import test from "node:test";

import {
  rebuildForwardedHeaders,
  shouldInjectGatewayAuth,
} from "./proxy-headers.js";

function proxyRequest(headers) {
  const values = new Map(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]),
  );
  return {
    getHeaderNames: () => [...values.keys()],
    removeHeader: (name) => values.delete(name.toLowerCase()),
    setHeader: (name, value) => values.set(name.toLowerCase(), value),
    headers: values,
  };
}

test("rebuilds Railway forwarding headers from the trusted client IP", () => {
  const proxyReq = proxyRequest({
    forwarded: "for=192.0.2.1",
    "x-forwarded-for": "192.0.2.1",
    "x-forwarded-proto": "http",
    "x-forwarded-host": "claw.example.com",
    "x-forwarded-client-cert": "spoofed",
    "x-real-ip": "192.0.2.1",
  });

  rebuildForwardedHeaders(
    proxyReq,
    {
      headers: {
        host: "internal.railway",
        "x-forwarded-host": "claw.example.com",
        "x-real-ip": "203.0.113.10",
      },
      socket: { remoteAddress: "100.64.0.1" },
    },
    "claw.up.railway.app",
  );

  assert.deepEqual(Object.fromEntries(proxyReq.headers), {
    "x-forwarded-for": "203.0.113.10",
    "x-forwarded-proto": "https",
    "x-forwarded-host": "claw.example.com",
  });
});

test("fails closed when Railway client attribution is missing or malformed", () => {
  for (const realIp of [undefined, "not-an-ip"]) {
    const proxyReq = proxyRequest({});
    rebuildForwardedHeaders(
      proxyReq,
      {
        headers: {
          "x-forwarded-host": "invalid.example.com, spoofed.example.com",
          ...(realIp === undefined ? {} : { "x-real-ip": realIp }),
        },
        socket: { remoteAddress: "100.64.0.1" },
      },
      "claw.up.railway.app",
    );

    assert.deepEqual(Object.fromEntries(proxyReq.headers), {
      "x-forwarded-for": "127.0.0.1",
      "x-forwarded-proto": "https",
      "x-forwarded-host": "claw.up.railway.app",
    });
  }
});

test("keeps loopback client attribution fail-closed for OpenClaw", () => {
  const proxyReq = proxyRequest({});
  rebuildForwardedHeaders(
    proxyReq,
    {
      headers: { "x-real-ip": "::1" },
      socket: { remoteAddress: "100.64.0.1" },
    },
    "claw.up.railway.app",
  );

  assert.equal(proxyReq.headers.get("x-forwarded-for"), "::1");
});

test("strips untrusted forwarding headers outside Railway", () => {
  const proxyReq = proxyRequest({
    "x-forwarded-for": "192.0.2.1",
    "x-real-ip": "192.0.2.1",
  });

  rebuildForwardedHeaders(
    proxyReq,
    {
      headers: { "x-real-ip": "192.0.2.1" },
      socket: { remoteAddress: "127.0.0.1" },
    },
    undefined,
  );

  assert.deepEqual(Object.fromEntries(proxyReq.headers), {});
});

test("injects the gateway token for ordinary gateway paths", () => {
  assert.equal(shouldInjectGatewayAuth("/"), true);
  assert.equal(shouldInjectGatewayAuth("/openclaw?token=x"), true);
  assert.equal(shouldInjectGatewayAuth("/v1/chat/completions"), true);
  assert.equal(shouldInjectGatewayAuth(undefined), true);
});

test("leaves the caller's Authorization alone for webhook and A2A paths", () => {
  assert.equal(shouldInjectGatewayAuth("/hooks/github"), false);
  assert.equal(shouldInjectGatewayAuth("/a2a/v1"), false);
  assert.equal(shouldInjectGatewayAuth("/a2a/v1?x=1"), false);
  assert.equal(shouldInjectGatewayAuth("/.well-known/agent-card.json"), false);
  assert.equal(shouldInjectGatewayAuth("/.well-known/agent.json"), false);
});

test("does not match look-alike prefixes", () => {
  assert.equal(shouldInjectGatewayAuth("/a2a"), true);
  assert.equal(shouldInjectGatewayAuth("/a2abc/v1"), true);
  assert.equal(shouldInjectGatewayAuth("/hooks"), true);
});
