#!/usr/bin/env python3
"""Build data.json for the public scoreboard from an export of the app's database.

Usage: build_data.py <export_dir> <out_file>
<export_dir> holds one JSON file per document: leagues/*.json, games/*.json, meta/sync.json
"""
import json, sys, glob, os, datetime

src, out = sys.argv[1], sys.argv[2]
docs = {}
for coll in ("leagues", "games"):
    for f in sorted(glob.glob(os.path.join(src, coll, "*.json"))):
        docs[f"{coll}/{os.path.basename(f)[:-5]}"] = json.load(open(f))
sync = os.path.join(src, "meta", "sync.json")
if os.path.exists(sync):
    docs["meta/sync"] = json.load(open(sync))
if not any(k.startswith("leagues/") for k in docs):
    sys.exit("No leagues in the export: refusing to write an empty scoreboard.")
payload = {"generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "docs": docs}
json.dump(payload, open(out, "w"), separators=(",", ":"), ensure_ascii=False)
print(f"{out}: {sum(k.startswith('leagues/') for k in docs)} leagues, "
      f"{sum(len(d.get('games', [])) for k, d in docs.items() if k.startswith('games/'))} games")
