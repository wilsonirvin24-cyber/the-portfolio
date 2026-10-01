#!/usr/bin/env python3
"""Build index.html for the public scoreboard from the app page published in Claude.

Usage: build_page.py <app_page.html> <out_file>
The app page reads its data through window.claude; here a small read-only stand-in serves data.json instead.
"""
import sys
src, out = sys.argv[1], sys.argv[2]
page = open(src).read()
if "<body" in page:                      # a page read back from Claude carries the published skeleton
    page = page[page.index(">", page.index("<body")) + 1:]
    page = page.replace("</body>", "").replace("</html>", "")
HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>The Portfolio</title>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="The Portfolio">
<meta name="theme-color" content="#0f2a1e">
<link rel="apple-touch-icon" href="icon-180.png">
<link rel="icon" type="image/png" href="icon-180.png">
<link rel="manifest" href="manifest.webmanifest">
<style>:root{padding:env(safe-area-inset-top,0px) 0 env(safe-area-inset-bottom,0px)}body{margin:0}img{max-width:100%}[hidden]{display:none!important}
.pubnote{max-width:1080px;margin:0 auto;padding:0 16px 28px;font-size:12.5px;color:var(--muted)}</style>
<script>
/* Read-only stand-in for the Claude page runtime: serves the daily snapshot in data.json. */
(function(){
  let data = null;
  const load = () => data || (data = fetch("data.json?t=" + Date.now()).then(r => r.json()));
  const snap = (docs, p) => ({ id: p.split("/").pop(), exists: p in docs, data: () => docs[p], metadata: {} });
  const refuse = async () => { throw { code: "invalid_argument", message: "read-only" }; };
  const doc = p => ({ id: p.split("/").pop(), path: p, get: async () => snap((await load()).docs, p), set: refuse, update: refuse, delete: refuse,
    onSnapshot(next){ load().then(d => next(snap(d.docs, p))); return () => {}; } });
  const coll = c => { const q = { path: c, limit: () => q, doc: id => doc(c + "/" + id),
    onSnapshot(next){ load().then(d => { const n = c.split("/").length + 1;
      const docs = Object.keys(d.docs).filter(k => k.startsWith(c + "/") && k.split("/").length === n).sort().map(k => snap(d.docs, k));
      next({ docs, size: docs.length, empty: !docs.length }); }); return () => {}; } }; return q; };
  window.PORTFOLIO_PUBLIC = true;
  window.claude = { use: async name => name === "db" ? { doc, collection: coll } : name === "user" ? { can: async () => false } : null };
  window.addEventListener("DOMContentLoaded", () => load().then(d => {
    const p = document.createElement("p"); p.className = "pubnote";
    const t = new Date(d.generated);
    p.textContent = "Public scoreboard. Refreshed each morning during the season; last refresh " +
      t.toLocaleString("en-US", { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) + ".";
    document.body.appendChild(p);
  }).catch(() => {}));
})();
</script>
</head>
<body>
"""
open(out, "w").write(HEAD + page + "\n</body>\n</html>\n")
print(out, len(HEAD + page))
