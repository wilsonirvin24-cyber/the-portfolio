/* The Portfolio website backend.
   Accounts and leagues live in Supabase. Game scores come from data.json, which is refreshed each morning.
   The page talks to this file through window.claude (data) and window.portfolioAuth (accounts). */
(function(){
  const CFG = window.PORTFOLIO_BACKEND || {
    url: "https://xwgtcsgjzxyviixczigs.supabase.co",
    key: "sb_publishable_DKSv69HJNsILC_Jalf6nRw_KPqGnmWk"   // publishable key: safe to ship in a public page
  };
  window.PORTFOLIO_PUBLIC = true;
  const HERE = location.origin + location.pathname;

  let stat = null;
  const loadStatic = () => stat || (stat = fetch("data.json?t=" + Date.now()).then(r => r.json()).catch(() => ({ docs: {} })));
  const snapDoc = (id, data) => ({ id, exists: data !== undefined, data: () => data, metadata: {} });
  const fail = (error, fallback) => ({ code: "backend", message: (error && error.message) || fallback || "Something went wrong. Try again." });

  const sb = window.supabase.createClient(CFG.url, CFG.key);
  // level: which database update the project has had. 1 = accounts only, 2 = pick timer, 3 = queue, chat, scheduled drafts.
  const state = { user: null, profile: null, live: true, recovery: false, timer: true, level: 3, offset: 0, google: false };
  const SELECTS = { 3: ",pick_seconds,clock_at,draft_at", 2: ",pick_seconds,clock_at", 1: "" };
  const authSubs = new Set(), leagueSubs = new Set();
  const tellAuth = () => authSubs.forEach(f => { try { f(state); } catch (_) {} });

  async function loadProfile(){
    if (!state.user){ state.profile = null; return; }
    const { data } = await sb.from("profiles").select("username,full_name,phone,alerts,is_admin").eq("id", state.user.id).maybeSingle();
    state.profile = data || null;
  }
  function setSession(session){
    const u = session && session.user;
    state.user = u ? { id: u.id, email: u.email } : null;
  }
  const ready = sb.auth.getSession().then(async ({ data }) => { setSession(data && data.session); await loadProfile(); }).catch(() => {});
  ready.then(() => syncClock()).catch(() => {});
  sb.auth.onAuthStateChange((event, session) => {
    // Supabase asks that no other client calls run inside this callback, so the work is deferred.
    setTimeout(async () => {
      const before = state.user && state.user.id;
      setSession(session);
      if (event === "PASSWORD_RECOVERY") state.recovery = true;
      if ((state.user && state.user.id) !== before || event === "USER_UPDATED" || event === "PASSWORD_RECOVERY"){
        await loadProfile(); tellAuth(); fetchLeagues();
      }
    }, 0);
  });

  /* ---- leagues ---- */
  let fetching = null;
  function fetchLeagues(){
    if (fetching) return fetching;
    return fetching = (async () => {
      await ready;
      let rows;
      const BASE = "id,doc,commissioner,members,created_at";
      let { data, error } = await sb.from("leagues").select(BASE + SELECTS[state.level]).order("created_at");
      while (error && state.level > 1 && (error.code === "42703" || /pick_seconds|clock_at|draft_at/.test(error.message || ""))){
        // The database hasn't had the latest update yet: carry on with the features it does have.
        state.level--; state.timer = state.level >= 2; tellAuth();
        ({ data, error } = await sb.from("leagues").select(BASE + SELECTS[state.level]).order("created_at"));
      }
      if (error){
        // The database isn't set up or can't be reached: show the last published snapshot, read-only.
        const was = state.live; state.live = false; if (was) tellAuth();
        const d = await loadStatic();
        rows = Object.keys(d.docs || {}).filter(k => k.startsWith("leagues/")).map(k => ({ id: k.slice(8), data: d.docs[k] }));
      } else {
        const was = state.live; state.live = true; if (!was) tellAuth();
        rows = data.map(r => ({ id: r.id, data: Object.assign({}, r.doc, { commissioner: r.commissioner, members: r.members || {}, created: r.doc.created || r.created_at,
          pickSeconds: r.pick_seconds || 0, clockAt: r.clock_at || null, draftAt: r.draft_at || null }) }));
      }
      const snap = { docs: rows.map(r => snapDoc(r.id, r.data)), size: rows.length, empty: !rows.length };
      leagueSubs.forEach(f => { try { f(snap); } catch (_) {} });
    })().finally(() => { fetching = null; });
  }
  let liveStarted = false;
  function startLive(){
    if (liveStarted) return; liveStarted = true;
    try {
      sb.channel("leagues-feed").on("postgres_changes", { event: "*", schema: "public", table: "leagues" }, () => fetchLeagues()).subscribe();
    } catch (_) {}
    // Fallback for when the live feed is unavailable: check again while the page is being looked at.
    setInterval(() => { if (document.visibilityState === "visible") fetchLeagues(); }, 20000);
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") fetchLeagues(); });
  }
  async function rpc(fn, args, fallback){
    const { data, error } = await sb.rpc(fn, args);
    if (error) throw fail(error, fallback);
    return data;
  }
  const leagueFields = (d, keepTimer) => { const o = Object.assign({}, d); delete o.commissioner; delete o.members; delete o.id; delete o.clockAt; delete o.draftAt; if (!keepTimer) delete o.pickSeconds; return o; };
  // The pick clock runs on the database's time, so measure how far this device's clock is off.
  async function syncClock(){
    const t0 = Date.now(); const { data, error } = await sb.rpc("pf_now");
    if (!error && data) state.offset = new Date(data).getTime() - (t0 + Date.now()) / 2;
  }

  /* ---- the data interface the page expects ---- */
  function collection(name){
    const q = {
      path: name, limit: () => q, doc: id => doc(name + "/" + id),
      onSnapshot(next){
        if (name === "leagues"){ leagueSubs.add(next); fetchLeagues(); startLive(); return () => leagueSubs.delete(next); }
        loadStatic().then(d => {
          const n = name.split("/").length + 1;
          const docs = Object.keys(d.docs || {}).filter(k => k.startsWith(name + "/") && k.split("/").length === n).sort().map(k => snapDoc(k.split("/").pop(), d.docs[k]));
          next({ docs, size: docs.length, empty: !docs.length });
        });
        return () => {};
      }
    };
    return q;
  }
  function doc(path){
    const id = path.split("/").pop(), isLeague = path.startsWith("leagues/");
    const readOnly = async () => { throw fail(null, "Scores are managed by the site and can't be changed here."); };
    return {
      id, path,
      get: async () => snapDoc(id, ((await loadStatic()).docs || {})[path]),
      set: isLeague ? async data => { await rpc("create_league", { p_id: id, p_doc: leagueFields(data, true) }); await fetchLeagues(); } : readOnly,
      update: isLeague ? async patch => { await rpc("patch_league", { p_id: id, p_patch: leagueFields(patch) }); await fetchLeagues(); } : readOnly,
      delete: isLeague ? async () => { await rpc("delete_league", { p_id: id }); await fetchLeagues(); } : readOnly,
      onSnapshot(next){ loadStatic().then(d => next(snapDoc(id, (d.docs || {})[path]))); return () => {}; }
    };
  }
  window.addEventListener("DOMContentLoaded", () => loadStatic().then(d => {
    if (!d.generated) return;
    const p = document.createElement("p"); p.className = "pubnote";
    p.textContent = "Scores refresh each morning during the season; last refresh " +
      new Date(d.generated).toLocaleString("en-US", { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) + ".";
    document.body.appendChild(p);
  }));
  window.claude = { use: async name => name === "db" ? { doc, collection } : name === "user" ? { can: async () => false } : null };

  /* ---- chat: one open conversation at a time ---- */
  let chatOpen = null;
  function openChat(id, cb){
    if (chatOpen) chatOpen.close();
    let closed = false, busy = false;
    const load = async () => {
      if (closed || busy) return; busy = true;
      try {
        const { data, error } = await sb.from("league_messages").select("id,user_id,name,body,created_at").eq("league_id", id).order("id", { ascending: false }).limit(150);
        if (!closed) cb(error ? { error: fail(error).message, messages: [] } : { messages: (data || []).reverse() });
      } finally { busy = false; }
    };
    let ch = null;
    try { ch = sb.channel("chat-" + id).on("postgres_changes", { event: "*", schema: "public", table: "league_messages", filter: "league_id=eq." + id }, load).subscribe(); } catch (_) {}
    const timer = setInterval(() => { if (document.visibilityState === "visible") load(); }, 8000);   // in case the live feed is unavailable
    load();
    return chatOpen = { id, reload: load, close(){ closed = true; clearInterval(timer); try { if (ch) sb.removeChannel(ch); } catch (_) {} if (chatOpen === this) chatOpen = null; } };
  }
  const rankCache = {};
  // Sign-in providers switched on for this project (decides whether "Continue with Google" is shown).
  fetch(CFG.url + "/auth/v1/settings", { headers: { apikey: CFG.key } }).then(r => r.json())
    .then(d => { if (d && d.external && d.external.google){ state.google = true; tellAuth(); } }).catch(() => {});

  /* ---- accounts ---- */
  window.portfolioAuth = {
    ready, state,
    onChange(fn){ authSubs.add(fn); ready.then(() => fn(state)); return () => authSubs.delete(fn); },
    async usernameAvailable(u){ try { return !!(await rpc("username_available", { p_username: u })); } catch (_) { return true; } },
    async signUp({ email, password, username, full_name, phone }){
      const { data, error } = await sb.auth.signUp({ email, password, options: { data: { username, full_name, phone: phone || "" }, emailRedirectTo: HERE } });
      if (error) throw fail(error);
      return { needsConfirm: !data.session };
    },
    async signIn(email, password){
      const { error } = await sb.auth.signInWithPassword({ email, password });
      if (error) throw fail(error, "That email and password don't match.");
    },
    async signOut(){ await sb.auth.signOut(); },
    async signInWithGoogle(){
      const { error } = await sb.auth.signInWithOAuth({ provider: "google", options: { redirectTo: HERE } });
      if (error) throw fail(error);
    },
    async resetPassword(email){
      const { error } = await sb.auth.resetPasswordForEmail(email, { redirectTo: HERE });
      if (error) throw fail(error);
    },
    async updatePassword(password){
      const { error } = await sb.auth.updateUser({ password });
      if (error) throw fail(error);
      state.recovery = false;
    },
    async updateProfile(fields){
      if (!state.user) throw fail(null, "Sign in first.");
      const { error } = await sb.from("profiles").update(fields).eq("id", state.user.id);
      if (error) throw fail(error.code === "23505" ? { message: "That username is taken." } : error);
      await loadProfile(); tellAuth();
    },
    async join(id, code, seat){ await rpc("join_league", { p_id: id, p_code: code, p_seat: seat }); await fetchLeagues(); },
    async releaseSeat(id, seat){ await rpc("release_seat", { p_id: id, p_seat: seat }); await fetchLeagues(); },
    async invite(id){ return await rpc("league_invite", { p_id: id }); },
    now: () => Date.now() + state.offset,
    async setDraftTime(id, when){ await rpc("set_draft_time", { p_id: id, p_at: when }); await fetchLeagues(); },
    async startIfDue(id){ const ok = await rpc("start_draft_if_due", { p_id: id }); await fetchLeagues(); return ok; },
    async getQueue(id){
      const { data, error } = await sb.from("draft_queues").select("teams").eq("league_id", id).maybeSingle();
      if (error) throw fail(error);
      return (data && data.teams) || [];
    },
    async setQueue(id, teams){ await rpc("set_queue", { p_id: id, p_teams: teams }); },
    // Default auto-pick order for a sport: [{team, pool, rank}], best first.
    ranks(sport){
      return rankCache[sport] || (rankCache[sport] = sb.from("pf_teams").select("team,pool,rank").eq("sport", sport).order("rank").limit(1000)
        .then(({ data, error }) => { if (error){ delete rankCache[sport]; throw fail(error); } return data || []; }));
    },
    openChat,
    async sendMessage(id, body){ await rpc("post_message", { p_id: id, p_body: body }); if (chatOpen && chatOpen.id === id) chatOpen.reload(); },
    async deleteMessage(msgId){ await rpc("delete_message", { p_msg: msgId }); if (chatOpen) chatOpen.reload(); },
    async setClock(id, seconds, running){ await rpc("set_clock", { p_id: id, p_seconds: seconds, p_running: !!running }); await syncClock().catch(() => {}); await fetchLeagues(); },
    async autoPick(id){ const n = await rpc("auto_pick", { p_id: id }); if (n) await fetchLeagues(); return n; },
    async makePick(id, team, pool, slot){ await rpc("make_pick", { p_id: id, p_team: team, p_pool: pool, p_slot: slot }); await fetchLeagues(); },
    refresh: fetchLeagues
  };
})();
