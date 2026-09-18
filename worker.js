export default {
  async fetch(request, env) {
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const url = new URL(request.url);
    const q = url.searchParams;

    const userId = q.get("userId") || q.get("user") || "";
    const tx = q.get("transactionId") || q.get("tx") || "";
    const amount = q.get("currencyAmount") || q.get("amount") || "";
    const sig = q.get("signature") || q.get("sig") || "";

    if (!userId || !tx || !amount || !sig) {
      return new Response("Missing required fields", { status: 400 });
    }

    const message = `${userId}:${tx}:${amount}`;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.OFFERWALL_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(message)
    );

    const expected = [...new Uint8Array(signature)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    if (!timingSafeEqual(expected, sig)) {
      return new Response("invalid signature", { status: 403 });
    }

    const forward = new URL(env.APP_WEBHOOK_URL);

    const fields = [
      "userId",
      "transactionId",
      "currencyAmount",
      "currencyName",
      "offerId",
      "offerName",
      "goalId",
      "payoutUsd",
      "status",
      "test",
      "timestamp"
    ];

    for (const field of fields) {
      const value = q.get(field);
      if (value !== null) {
        forward.searchParams.set(field, value);
      }
    }

    const response = await fetch(forward.toString(), {
      method: "GET",
      headers: {
        "X-Webhook-Secret": env.APP_WEBHOOK_SECRET
      }
    });

    if (!response.ok) {
      return new Response("upstream error", { status: 502 });
    }

    return new Response("ok", { status: 200 });
  }
};

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}
