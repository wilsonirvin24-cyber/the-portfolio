# The Portfolio — public scoreboard

A read-only copy of The Portfolio league app: standings, rosters, draft results and game results.

- `index.html` — the page. Built from the app page with `scripts/build_page.py`.
- `data.json` — the daily snapshot of leagues and scores. Built with `scripts/build_data.py` and refreshed each morning during the season.

Leagues, drafts and score corrections are managed in the main app; this site only displays them.
