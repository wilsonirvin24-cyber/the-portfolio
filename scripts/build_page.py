#!/usr/bin/env python3
"""Build index.html for the public scoreboard from the app page published in Claude.

Usage: build_page.py <app_page.html> <out_file>
The app page reads its data through window.claude; on the website backend.js provides that interface
(accounts and leagues from Supabase, scores from data.json).
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
<script src="vendor/supabase.js"></script>
<script src="backend.js"></script>
</head>
<body>
"""
open(out, "w").write(HEAD + page + "\n</body>\n</html>\n")
print(out, len(HEAD + page))
