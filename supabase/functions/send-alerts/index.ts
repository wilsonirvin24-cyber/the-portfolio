// The Portfolio: sends queued text alerts ("you're on the clock") through Twilio.
//
// Deploy as a Supabase Edge Function named "send-alerts", then add a Database Webhook that calls it
// on every INSERT into public.alerts_outbox. Secrets to set for the function (never put these in the website):
//   TWILIO_ACCOUNT_SID   from the Twilio console
//   TWILIO_AUTH_TOKEN    from the Twilio console
//   TWILIO_FROM          your Twilio number in +1XXXXXXXXXX form (or a Messaging Service SID starting with MG)
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided to Edge Functions automatically.

const env = (k: string): string => Deno.env.get(k) ?? "";

// US numbers typed any way ("312-555-0142") become +13125550142. Anything else must already start with +.
export function e164(raw: string | null): string | null {
  if (!raw) return null;
  const d = raw.replace(/\D/g, "");
  if (raw.trim().startsWith("+")) return d.length >= 8 && d.length <= 15 ? "+" + d : null;
  if (d.length === 10) return "+1" + d;
  if (d.length === 11 && d[0] === "1") return "+" + d;
  return null;
}

async function rpc(fn: string, args: Record<string, unknown>) {
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const r = await fetch(`${env("SUPABASE_URL")}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!r.ok) throw new Error(`${fn} failed: ${r.status} ${await r.text()}`);
  return r.status === 204 ? null : r.json();
}

async function sendText(to: string, body: string): Promise<string | null> {
  const sid = env("TWILIO_ACCOUNT_SID"), from = env("TWILIO_FROM");
  const form = new URLSearchParams({ To: to, Body: body });
  form.set(from.startsWith("MG") ? "MessagingServiceSid" : "From", from);
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(`${sid}:${env("TWILIO_AUTH_TOKEN")}`), "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  });
  if (r.ok) return null;
  const err = await r.json().catch(() => ({}));
  return `Twilio ${r.status}: ${err.message ?? "send failed"}`;
}

export async function run(): Promise<{ sent: number; failed: number }> {
  let sent = 0, failed = 0;
  const rows: { alert_id: number; to_phone: string | null; message: string }[] = (await rpc("pf_alerts_claim", { p_limit: 20 })) ?? [];
  for (const row of rows) {
    const to = e164(row.to_phone);
    const error = to ? await sendText(to, row.message).catch((e) => String(e)) : "No usable phone number on the account.";
    await rpc("pf_alerts_done", { p_id: row.alert_id, p_error: error });
    error ? failed++ : sent++;
  }
  return { sent, failed };
}

Deno.serve(async () => {
  try {
    return Response.json(await run());
  } catch (e) {
    return Response.json({ error: String(e) }, { status: 500 });
  }
});
