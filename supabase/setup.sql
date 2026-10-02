-- The Portfolio: database setup for Supabase.
-- Run this once in the Supabase SQL editor. It is safe to run again: nothing is dropped or overwritten.
--
-- What it creates
--   profiles        one private row per account (username, full name, phone, alert choices)
--   leagues         one row per league; readable by anyone with the link
--   league_invites  the invite code for each league; only its commissioner can read it
--   functions       the only way league data changes: create, edit, delete, join, leave, pick
--   pf_teams        every team in each sport with a default rank, used when the pick timer runs out
--   alerts_outbox   text alerts waiting to be sent ("you're on the clock"); unused unless a text provider is connected
--   draft_queues    each manager's private wish list, used first when their pick timer runs out
--   league_messages league chat, readable only by that league's managers

-- ---------------------------------------------------------------- profiles
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  username    text not null,
  full_name   text not null default '',
  phone       text,
  alerts      jsonb not null default '{"draft":true,"weekly":true}'::jsonb,
  is_admin    boolean not null default false,
  created_at  timestamptz not null default now()
);
create unique index if not exists profiles_username_lower on public.profiles (lower(username));
alter table public.profiles enable row level security;

drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles for select to authenticated using (auth.uid() = id);
drop policy if exists "update own profile" on public.profiles;
create policy "update own profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

-- Accounts may change their own details but never grant themselves admin.
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (username, full_name, phone, alerts) on public.profiles to authenticated;

-- ----------------------------------------------------------------- leagues
create table if not exists public.leagues (
  id            text primary key,
  doc           jsonb not null,
  commissioner  uuid references auth.users(id) on delete set null,
  members       jsonb not null default '{}'::jsonb,     -- seat name -> account id
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
alter table public.leagues enable row level security;
drop policy if exists "anyone can view leagues" on public.leagues;
create policy "anyone can view leagues" on public.leagues for select to anon, authenticated using (true);
revoke all on public.leagues from anon, authenticated;
grant select on public.leagues to anon, authenticated;

create table if not exists public.league_invites (
  league_id text primary key references public.leagues(id) on delete cascade,
  code      text not null
);
alter table public.league_invites enable row level security;
revoke all on public.league_invites from anon, authenticated;   -- reached only through the functions below

-- Pick timer: seconds allowed per pick (0 = no timer) and when the current pick's clock started (null = stopped).
alter table public.leagues add column if not exists pick_seconds integer not null default 0;
alter table public.leagues add column if not exists clock_at timestamptz;

-- Every team that can be drafted, with a default rank per sport. When a manager's time runs out,
-- the best-ranked team still available for one of their open spots is picked for them.
create table if not exists public.pf_teams (
  sport text not null,
  pool  text not null,
  team  text not null,
  rank  integer not null,
  primary key (sport, pool, team)
);
alter table public.pf_teams enable row level security;
drop policy if exists "anyone can read teams" on public.pf_teams;
create policy "anyone can read teams" on public.pf_teams for select to anon, authenticated using (true);
revoke all on public.pf_teams from anon, authenticated;
grant select on public.pf_teams to anon, authenticated;

-- Scheduled draft: when set, managers can't pick before this time and the clock starts by itself when it arrives.
alter table public.leagues add column if not exists draft_at timestamptz;

-- Each manager's private draft queue for a league: team names in the order they want them.
create table if not exists public.draft_queues (
  league_id   text not null references public.leagues(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  teams       jsonb not null default '[]'::jsonb,
  updated_at  timestamptz not null default now(),
  primary key (league_id, user_id)
);
alter table public.draft_queues enable row level security;
drop policy if exists "read own queue" on public.draft_queues;
create policy "read own queue" on public.draft_queues for select to authenticated using (auth.uid() = user_id);
revoke all on public.draft_queues from anon, authenticated;
grant select on public.draft_queues to authenticated;

-- League chat.
create table if not exists public.league_messages (
  id          bigint generated always as identity primary key,
  league_id   text not null references public.leagues(id) on delete cascade,
  user_id     uuid references auth.users(id) on delete set null,
  name        text not null,
  body        text not null,
  created_at  timestamptz not null default now()
);
create index if not exists league_messages_by_league on public.league_messages (league_id, id desc);
alter table public.league_messages enable row level security;
revoke all on public.league_messages from anon, authenticated;
grant select on public.league_messages to authenticated;

-- Text alerts waiting to be sent. Filled by the functions below; read only by the sender.
create table if not exists public.alerts_outbox (
  id          bigint generated always as identity primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  league_id   text,
  body        text not null,
  created_at  timestamptz not null default now(),
  claimed_at  timestamptz,
  sent_at     timestamptz,
  error       text
);
alter table public.alerts_outbox enable row level security;
revoke all on public.alerts_outbox from anon, authenticated;

-- --------------------------------------------------------------- helpers
create or replace function public.pf_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.pf_can_run(l public.leagues) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (l.commissioner = auth.uid() or public.pf_is_admin());
$$;

-- Is the signed-in account part of this league (a manager, its commissioner, or the site admin)?
create or replace function public.pf_is_member(p_league text) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and exists (
    select 1 from public.leagues l
     where l.id = p_league
       and (l.commissioner = auth.uid() or public.pf_is_admin()
            or exists (select 1 from jsonb_each_text(l.members) m where m.value = auth.uid()::text)));
$$;
drop policy if exists "members read chat" on public.league_messages;
create policy "members read chat" on public.league_messages for select to authenticated using (public.pf_is_member(league_id));

-- Which manager is on the clock, or null when the draft is not open or is finished.
create or replace function public.pf_on_clock(d jsonb) returns text
language plpgsql immutable as $$
declare n int; cnt int; rounds int; r int; pos int;
begin
  if d->>'status' is distinct from 'drafting' or jsonb_typeof(d->'owners') <> 'array' then return null; end if;
  n := jsonb_array_length(coalesce(d->'picks', '[]'::jsonb));
  cnt := jsonb_array_length(d->'owners');
  rounds := coalesce((select sum(value::int) from jsonb_each_text(coalesce(d->'slots', '{}'::jsonb))), 0)
            + coalesce((d->>'flex')::int, 0);
  if cnt = 0 or n >= cnt * rounds then return null; end if;
  r := n / cnt; pos := n % cnt;
  return d->'owners'->>(case when d->>'draftType' = 'straight' or r % 2 = 0 then pos else cnt - 1 - pos end);
end $$;

create or replace function public.pf_now() returns timestamptz language sql stable as $$ select now() $$;

-- Queue a text for whoever is now on the clock, if they asked for texts. p_skip: the account that just acted.
create or replace function public.pf_alert_on_clock(p_id text, p_skip uuid) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues; seat text; uid uuid; pr public.profiles; span text := '';
begin
  select * into l from public.leagues where id = p_id;
  if not found then return; end if;
  seat := public.pf_on_clock(l.doc);
  if seat is null or coalesce(l.members->>seat, '') = '' then return; end if;
  uid := (l.members->>seat)::uuid;
  if uid = p_skip then return; end if;
  select * into pr from public.profiles where id = uid;
  if not found or coalesce(trim(pr.phone), '') = '' then return; end if;
  if coalesce(pr.alerts->>'sms', 'false') <> 'true' or coalesce(pr.alerts->>'draft', 'true') <> 'true' then return; end if;
  if l.clock_at is not null and l.pick_seconds > 0 then
    span := ' You have ' || case when l.pick_seconds < 120 then l.pick_seconds || ' seconds'
                                 when l.pick_seconds < 7200 then (l.pick_seconds / 60) || ' minutes'
                                 else (l.pick_seconds / 3600) || ' hours' end || '.';
  end if;
  insert into public.alerts_outbox (user_id, league_id, body)
  values (uid, p_id, 'The Portfolio: you''re on the clock in ' || left(l.doc->>'name', 40) || '.' || span);
exception when others then
  return;   -- an alert problem must never block a pick
end $$;

-- Records one pick for the manager on the clock, restarts the clock and queues the next alert.
create or replace function public.pf_apply_pick(p_id text, p_team text, p_pool text, p_slot text, p_auto boolean, p_actor uuid) returns integer
language plpgsql security definer set search_path = public as $$
declare l public.leagues; picks jsonb; pick jsonb; n int; cnt int; rounds int; seat text; done boolean;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  seat := public.pf_on_clock(l.doc);
  if seat is null then raise exception 'This draft is not open.'; end if;
  picks := coalesce(l.doc->'picks', '[]'::jsonb);
  n := jsonb_array_length(picks);
  cnt := jsonb_array_length(l.doc->'owners');
  rounds := coalesce((select sum(value::int) from jsonb_each_text(coalesce(l.doc->'slots', '{}'::jsonb))), 0)
            + coalesce((l.doc->>'flex')::int, 0);
  if coalesce(trim(p_team), '') = '' or length(p_team) > 60 or length(p_pool) > 30 or length(p_slot) > 30 then
    raise exception 'That pick is not valid.';
  end if;
  if exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(trim(p_team))) then
    raise exception '% is already drafted.', trim(p_team);
  end if;
  if exists (select 1 from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' = p_slot) then
    raise exception '% has already filled that spot.', seat;
  end if;
  pick := jsonb_build_object('n', n + 1, 'owner', seat, 'team', trim(p_team), 'pool', p_pool, 'slot', p_slot);
  if p_auto then pick := pick || jsonb_build_object('auto', true); end if;
  done := n + 1 >= cnt * rounds;
  update public.leagues
     set doc = l.doc || jsonb_build_object('picks', picks || jsonb_build_array(pick), 'status', case when done then 'complete' else 'drafting' end),
         clock_at = case when done or l.clock_at is null then null else now() end,
         updated_at = now()
   where id = p_id;
  perform public.pf_alert_on_clock(p_id, p_actor);
  return n + 1;
end $$;

-- ------------------------------------------------- new account -> profile
create or replace function public.pf_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  u text := nullif(trim(coalesce(new.raw_user_meta_data->>'username', '')), '');
  first_account boolean := not exists (select 1 from public.profiles);
begin
  if u is null then u := split_part(coalesce(new.email, 'manager'), '@', 1); end if;
  u := left(regexp_replace(u, '[^A-Za-z0-9_.-]', '', 'g'), 24);
  if u = '' then u := 'manager'; end if;
  if exists (select 1 from public.profiles where lower(username) = lower(u)) then
    u := left(u, 19) || floor(random()*9000 + 1000)::int::text;
  end if;
  insert into public.profiles (id, username, full_name, phone, is_admin)
  values (new.id, u,
          left(coalesce(new.raw_user_meta_data->>'full_name', ''), 80),
          nullif(left(coalesce(new.raw_user_meta_data->>'phone', ''), 32), ''),
          first_account);
  -- The first account ever created runs the site and takes over leagues that have no commissioner yet.
  if first_account then
    update public.leagues set commissioner = new.id where commissioner is null;
  end if;
  return new;
end $$;

drop trigger if exists pf_on_auth_user_created on auth.users;
create trigger pf_on_auth_user_created after insert on auth.users
  for each row execute function public.pf_new_user();

create or replace function public.username_available(p_username text) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.profiles where lower(username) = lower(trim(p_username)));
$$;

-- ------------------------------------------------------- league functions
create or replace function public.create_league(p_id text, p_doc jsonb) returns text
language plpgsql security definer set search_path = public as $$
declare code text := substr(md5(random()::text || clock_timestamp()::text), 1, 10);
begin
  if auth.uid() is null then raise exception 'Sign in to create a league.'; end if;
  if p_id !~ '^[a-z0-9][a-z0-9-]{1,79}$' then raise exception 'That league address is not valid.'; end if;
  if jsonb_typeof(p_doc->'owners') <> 'array' or jsonb_array_length(p_doc->'owners') < 2 then raise exception 'A league needs at least two managers.'; end if;
  if coalesce(trim(p_doc->>'name'), '') = '' then raise exception 'Name the league.'; end if;
  if pg_column_size(p_doc) > 60000 then raise exception 'That league is too large.'; end if;
  if (select count(*) from public.leagues where commissioner = auth.uid()) >= 25 then raise exception 'You already run 25 leagues.'; end if;
  insert into public.leagues (id, doc, commissioner, pick_seconds)
  values (p_id, (p_doc - 'pickSeconds' - 'clockAt') || jsonb_build_object('status', 'drafting', 'picks', '[]'::jsonb), auth.uid(),
          case when p_doc->>'pickSeconds' ~ '^[0-9]{1,6}$' then least((p_doc->>'pickSeconds')::int, 604800) else 0 end);
  insert into public.league_invites (league_id, code) values (p_id, code);
  return p_id;
exception when unique_violation then
  raise exception 'A league with that name and season already exists.';
end $$;

-- Commissioner edits: merges the given fields into the league (undo a pick, reopen the draft, rename).
create or replace function public.patch_league(p_id text, p_patch jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues; d jsonb;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if not public.pf_can_run(l) then raise exception 'Only the commissioner can change this league.'; end if;
  d := l.doc || (p_patch - 'pickSeconds' - 'clockAt');
  if pg_column_size(d) > 120000 then raise exception 'That league is too large.'; end if;
  -- Undoing a pick or reopening the draft restarts a running clock; a finished draft stops it.
  update public.leagues
     set doc = d,
         clock_at = case when public.pf_on_clock(d) is null then null
                         when l.clock_at is not null and (p_patch ? 'picks' or p_patch ? 'status') then now()
                         else l.clock_at end,
         updated_at = now()
   where id = p_id;
end $$;

create or replace function public.delete_league(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found then return; end if;
  if not public.pf_can_run(l) then raise exception 'Only the commissioner can delete this league.'; end if;
  delete from public.leagues where id = p_id;
end $$;

create or replace function public.league_invite(p_id text) returns text
language plpgsql security definer set search_path = public as $$
declare l public.leagues; c text;
begin
  select * into l from public.leagues where id = p_id;
  if not found then raise exception 'League not found.'; end if;
  if not public.pf_can_run(l) then raise exception 'Only the commissioner can see the invite link.'; end if;
  select code into c from public.league_invites where league_id = p_id;
  if c is null then
    c := substr(md5(random()::text || clock_timestamp()::text), 1, 10);
    insert into public.league_invites (league_id, code) values (p_id, c);
  end if;
  return c;
end $$;

-- A manager takes a seat using the invite code. One seat per account per league.
create or replace function public.join_league(p_id text, p_code text, p_seat text) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues; held text;
begin
  if auth.uid() is null then raise exception 'Sign in to join a league.'; end if;
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if not exists (select 1 from public.league_invites where league_id = p_id and code = p_code) then
    raise exception 'That invite link is not valid. Ask the commissioner for a new one.';
  end if;
  if not (l.doc->'owners') ? p_seat then raise exception 'That manager is not in this league.'; end if;
  if l.members ? p_seat then raise exception 'Someone has already taken that spot.'; end if;
  select key into held from jsonb_each_text(l.members) where value = auth.uid()::text limit 1;
  if held is not null then raise exception 'You already manage % in this league.', held; end if;
  update public.leagues set members = l.members || jsonb_build_object(p_seat, auth.uid()::text), updated_at = now() where id = p_id;
end $$;

-- Give up your own seat, or (commissioner) free someone else's.
create or replace function public.release_seat(p_id text, p_seat text) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if not (l.members ? p_seat) then return; end if;
  if l.members->>p_seat <> auth.uid()::text and not public.pf_can_run(l) then
    raise exception 'Only the commissioner can free another manager''s spot.';
  end if;
  update public.leagues set members = l.members - p_seat, updated_at = now() where id = p_id;
end $$;

-- One draft pick. Allowed for the manager on the clock, or the commissioner on their behalf.
-- The database decides which spot the team fills, so a pick can't put a team in the wrong pool or an extra spot.
create or replace function public.make_pick(p_id text, p_team text, p_pool text, p_slot text) returns integer
language plpgsql security definer set search_path = public as $$
declare
  l public.leagues; seat text; boss boolean; v_sport text; v_pro text; v_team text; v_pool text; v_slot text;
  slots jsonb; picks jsonb; have int; flex int; used int;
begin
  if auth.uid() is null then raise exception 'Sign in to make a pick.'; end if;
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if l.doc->>'status' <> 'drafting' then raise exception 'This draft is not open.'; end if;
  seat := public.pf_on_clock(l.doc);
  if seat is null then raise exception 'The draft is complete.'; end if;
  boss := public.pf_can_run(l);
  if not boss and coalesce(l.members->>seat, '') <> auth.uid()::text then
    raise exception 'It is %''s pick.', seat;
  end if;
  if not boss and l.draft_at is not null and now() < l.draft_at then
    raise exception 'The draft hasn''t started yet.';
  end if;
  v_sport := coalesce(l.doc->>'sport', 'football');
  v_pro := case v_sport when 'basketball' then 'NBA' else 'NFL' end;
  slots := coalesce(l.doc->'slots', '{}'::jsonb);
  picks := coalesce(l.doc->'picks', '[]'::jsonb);
  select t.team, t.pool into v_team, v_pool from public.pf_teams t
   where t.sport = v_sport and lower(t.team) = lower(trim(p_team)) and t.pool = p_pool;
  if v_team is null then
    if exists (select 1 from public.pf_teams t where t.sport = v_sport and lower(t.team) = lower(trim(p_team))) then
      raise exception '% is not in the % pool.', trim(p_team), p_pool;
    end if;
    if not boss then raise exception 'Only the commissioner can add a team that isn''t on the list.'; end if;
    v_team := trim(p_team); v_pool := p_pool;
  end if;
  select count(*) into have from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = v_pool and e->>'slot' not like 'Any%';
  if coalesce((slots->>v_pool)::int, 0) > have then
    v_slot := case when (slots->>v_pool)::int > 1 then v_pool || ' #' || (have + 1) else v_pool end;
  else
    flex := coalesce((l.doc->>'flex')::int, 0);
    select count(*) into used from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' like 'Any%';
    if v_pool <> v_pro and flex > used then
      v_slot := case when flex > 1 then 'Any #' || (used + 1) else 'Any' end;
    else
      raise exception '% has no open % spot.', seat, v_pool;
    end if;
  end if;
  return public.pf_apply_pick(p_id, v_team, v_pool, v_slot, false, auth.uid());
end $$;

-- ------------------------------------------------ pick timer and auto-pick
-- Commissioner sets the seconds per pick and starts or pauses the clock.
create or replace function public.set_clock(p_id text, p_seconds integer, p_running boolean) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues; s int; run boolean;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if not public.pf_can_run(l) then raise exception 'Only the commissioner can change the pick timer.'; end if;
  s := greatest(0, least(coalesce(p_seconds, l.pick_seconds), 604800));
  run := coalesce(p_running, false) and s > 0 and public.pf_on_clock(l.doc) is not null;
  update public.leagues set pick_seconds = s, clock_at = case when run then now() else null end,
         draft_at = case when run then null else draft_at end, updated_at = now() where id = p_id;
  if run and l.clock_at is null then perform public.pf_alert_on_clock(p_id, auth.uid()); end if;
end $$;

-- Makes the pick for the manager on the clock once their time is up. Returns the pick number, or 0 if nothing was due.
create or replace function public.pf_auto_pick_now(p_id text) returns integer
language plpgsql security definer set search_path = public as $$
declare
  l public.leagues; seat text; v_sport text; v_pro text; slots jsonb; picks jsonb;
  v_team text; v_pool text; v_slot text; have int; flex int; used int;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found then return 0; end if;
  seat := public.pf_on_clock(l.doc);
  if seat is null then
    update public.leagues set clock_at = null where id = p_id and clock_at is not null;
    return 0;
  end if;
  if l.clock_at is null or l.pick_seconds <= 0 or now() < l.clock_at + make_interval(secs => l.pick_seconds) then return 0; end if;
  v_sport := coalesce(l.doc->>'sport', 'football');
  v_pro := case v_sport when 'basketball' then 'NBA' else 'NFL' end;
  slots := coalesce(l.doc->'slots', '{}'::jsonb);
  picks := coalesce(l.doc->'picks', '[]'::jsonb);
  -- First choice: the manager's own queue, in their order, skipping teams that are gone or don't fit an open spot.
  if coalesce(l.members->>seat, '') <> '' then
    select t.team, t.pool into v_team, v_pool
      from public.draft_queues dq
      cross join lateral jsonb_array_elements_text(dq.teams) with ordinality q(name, ord)
      join public.pf_teams t on t.sport = v_sport and lower(t.team) = lower(q.name)
     where dq.league_id = p_id and dq.user_id = (l.members->>seat)::uuid
       and coalesce((slots->>t.pool)::int, 0) >
           (select count(*) from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = t.pool and e->>'slot' not like 'Any%')
       and not exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(t.team))
     order by q.ord limit 1;
  end if;
  -- Otherwise: the best-ranked team still on the board in a pool where this manager has an open required spot.
  if v_team is null then
    select t.team, t.pool into v_team, v_pool
      from public.pf_teams t
     where t.sport = v_sport
       and coalesce((slots->>t.pool)::int, 0) >
           (select count(*) from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = t.pool and e->>'slot' not like 'Any%')
       and not exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(t.team))
     order by t.rank limit 1;
  end if;
  if v_team is not null then
    select count(*) into have from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = v_pool and e->>'slot' not like 'Any%';
    v_slot := case when (slots->>v_pool)::int > 1 then v_pool || ' #' || (have + 1) else v_pool end;
  else
    -- No required spot left to fill: use an "any college team" spot if the league has them.
    flex := coalesce((l.doc->>'flex')::int, 0);
    select count(*) into used from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' like 'Any%';
    if flex > used then
      select t.team, t.pool into v_team, v_pool
        from public.pf_teams t
       where t.sport = v_sport and t.pool <> v_pro
         and not exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(t.team))
       order by t.rank limit 1;
      v_slot := case when flex > 1 then 'Any #' || (used + 1) else 'Any' end;
    end if;
  end if;
  if v_team is null then
    -- Nothing suitable is left: stop the clock so the commissioner can sort it out.
    update public.leagues set clock_at = null, updated_at = now() where id = p_id;
    return 0;
  end if;
  return public.pf_apply_pick(p_id, v_team, v_pool, v_slot, true, null);
end $$;

-- Any signed-in person watching a draft can report that time is up; the check above decides whether it really is.
create or replace function public.auto_pick(p_id text) returns integer
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  return public.pf_auto_pick_now(p_id);
end $$;

-- ------------------------------------------------------- scheduled draft
-- Commissioner sets (or clears, with null) the date and time the draft opens.
create or replace function public.set_draft_time(p_id text, p_at timestamptz) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if not public.pf_can_run(l) then raise exception 'Only the commissioner can schedule the draft.'; end if;
  if p_at is not null and p_at < now() then raise exception 'Choose a time in the future.'; end if;
  if p_at is not null and public.pf_on_clock(l.doc) is null then raise exception 'This draft is not open.'; end if;
  update public.leagues set draft_at = p_at, clock_at = case when p_at is null then clock_at else null end, updated_at = now() where id = p_id;
end $$;

-- Opens a scheduled draft once its time has come: picks unlock and the pick timer (if any) starts.
create or replace function public.pf_start_draft_now(p_id text) returns boolean
language plpgsql security definer set search_path = public as $$
declare l public.leagues;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found or l.draft_at is null or now() < l.draft_at then return false; end if;
  update public.leagues
     set draft_at = null,
         clock_at = case when l.pick_seconds > 0 and public.pf_on_clock(l.doc) is not null then now() else null end,
         updated_at = now()
   where id = p_id;
  perform public.pf_alert_on_clock(p_id, null);
  return true;
end $$;

-- Any signed-in person on the page can report that the start time has arrived; the check above decides.
create or replace function public.start_draft_if_due(p_id text) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  return public.pf_start_draft_now(p_id);
end $$;

-- ------------------------------------------------------------ draft queue
-- A manager saves their wish list for a league. Only people with a seat in the league can keep one.
create or replace function public.set_queue(p_id text, p_teams jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select * into l from public.leagues where id = p_id;
  if not found then raise exception 'League not found.'; end if;
  if not exists (select 1 from jsonb_each_text(l.members) m where m.value = auth.uid()::text) then
    raise exception 'Take your spot in this league before building a queue.';
  end if;
  if jsonb_typeof(p_teams) <> 'array' or jsonb_array_length(p_teams) > 300
     or exists (select 1 from jsonb_array_elements(p_teams) e where jsonb_typeof(e) <> 'string' or length(e #>> '{}') > 60) then
    raise exception 'That queue is not valid.';
  end if;
  insert into public.draft_queues (league_id, user_id, teams) values (p_id, auth.uid(), p_teams)
  on conflict (league_id, user_id) do update set teams = excluded.teams, updated_at = now();
end $$;

-- ------------------------------------------------------------ league chat
create or replace function public.post_message(p_id text, p_body text) returns bigint
language plpgsql security definer set search_path = public as $$
declare l public.leagues; b text := trim(coalesce(p_body, '')); who text; new_id bigint;
begin
  if auth.uid() is null then raise exception 'Sign in to chat.'; end if;
  if not public.pf_is_member(p_id) then raise exception 'Chat is for this league''s managers.'; end if;
  if b = '' then raise exception 'Write a message first.'; end if;
  if length(b) > 500 then raise exception 'Keep messages under 500 characters.'; end if;
  if (select count(*) from public.league_messages where user_id = auth.uid() and created_at > now() - interval '20 seconds') >= 6 then
    raise exception 'Slow down a little and try again.';
  end if;
  select * into l from public.leagues where id = p_id;
  select m.key into who from jsonb_each_text(l.members) m where m.value = auth.uid()::text limit 1;
  if who is null then select username into who from public.profiles where id = auth.uid(); end if;
  insert into public.league_messages (league_id, user_id, name, body) values (p_id, auth.uid(), coalesce(who, 'Manager'), b)
  returning id into new_id;
  return new_id;
end $$;

-- The author can delete their own message; the commissioner can delete any in their league.
create or replace function public.delete_message(p_msg bigint) returns void
language plpgsql security definer set search_path = public as $$
declare m public.league_messages; l public.leagues;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select * into m from public.league_messages where id = p_msg;
  if not found then return; end if;
  select * into l from public.leagues where id = m.league_id;
  if m.user_id is distinct from auth.uid() and not public.pf_can_run(l) then
    raise exception 'Only the commissioner can delete someone else''s message.';
  end if;
  delete from public.league_messages where id = p_msg;
end $$;

-- What this database has switched on. Lets the website (and support) check the setup without any private data.
create or replace function public.pf_status() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare s boolean := false;
begin
  begin
    execute 'select exists (select 1 from cron.job where jobname = ''portfolio-autopick'')' into s;
  exception when others then s := false;
  end;
  return jsonb_build_object('version', 3, 'scheduler', s);
end $$;

-- Run by the scheduler every minute, so picks still happen when nobody has the draft room open.
create or replace function public.pf_autopick_due() returns integer
language plpgsql security definer set search_path = public as $$
declare r record; made int := 0;
begin
  for r in select id from public.leagues where draft_at is not null and now() >= draft_at loop
    perform public.pf_start_draft_now(r.id);
  end loop;
  for r in select id from public.leagues
            where clock_at is not null and pick_seconds > 0 and now() >= clock_at + make_interval(secs => pick_seconds) loop
    if public.pf_auto_pick_now(r.id) > 0 then made := made + 1; end if;
  end loop;
  return made;
end $$;

-- ------------------------------------------------------------ text alerts
-- Used only by the sender (a server function holding the service key): hands out unsent alerts with the phone to text.
create or replace function public.pf_alerts_claim(p_limit integer default 20)
returns table (alert_id bigint, to_phone text, message text)
language plpgsql security definer set search_path = public as $$
begin
  return query
  with c as (
    select o.id from public.alerts_outbox o
     where o.sent_at is null and o.error is null
       and (o.claimed_at is null or o.claimed_at < now() - interval '5 minutes')
       and o.created_at > now() - interval '6 hours'
     order by o.id limit greatest(1, least(coalesce(p_limit, 20), 100))
     for update skip locked
  )
  update public.alerts_outbox o set claimed_at = now()
    from c where o.id = c.id
  returning o.id, (select p.phone from public.profiles p where p.id = o.user_id), o.body;
end $$;

create or replace function public.pf_alerts_done(p_id bigint, p_error text default null) returns void
language sql security definer set search_path = public as $$
  update public.alerts_outbox set sent_at = case when p_error is null then now() end, error = left(p_error, 300) where id = p_id;
$$;

-- Only signed-in accounts may call the functions that change things.
revoke execute on function public.create_league(text, jsonb), public.patch_league(text, jsonb), public.delete_league(text),
  public.league_invite(text), public.join_league(text, text, text), public.release_seat(text, text),
  public.make_pick(text, text, text, text) from public, anon;
grant execute on function public.create_league(text, jsonb), public.patch_league(text, jsonb), public.delete_league(text),
  public.league_invite(text), public.join_league(text, text, text), public.release_seat(text, text),
  public.make_pick(text, text, text, text) to authenticated;
grant execute on function public.username_available(text), public.pf_is_admin() to anon, authenticated;

revoke execute on function public.set_clock(text, integer, boolean), public.auto_pick(text) from public, anon;
grant execute on function public.set_clock(text, integer, boolean), public.auto_pick(text) to authenticated;
grant execute on function public.pf_now(), public.pf_on_clock(jsonb) to anon, authenticated;
revoke execute on function public.set_draft_time(text, timestamptz), public.start_draft_if_due(text), public.set_queue(text, jsonb),
  public.post_message(text, text), public.delete_message(bigint) from public, anon;
grant execute on function public.set_draft_time(text, timestamptz), public.start_draft_if_due(text), public.set_queue(text, jsonb),
  public.post_message(text, text), public.delete_message(bigint) to authenticated;
grant execute on function public.pf_status(), public.pf_is_member(text) to anon, authenticated;
revoke execute on function public.pf_start_draft_now(text) from public, anon, authenticated;
-- Internal pieces: never callable from the website.
revoke execute on function public.pf_apply_pick(text, text, text, text, boolean, uuid), public.pf_auto_pick_now(text),
  public.pf_autopick_due(), public.pf_alert_on_clock(text, uuid), public.pf_alerts_claim(integer), public.pf_alerts_done(bigint, text)
  from public, anon, authenticated;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function public.pf_alerts_claim(integer), public.pf_alerts_done(bigint, text) to service_role;
  end if;
end $$;
revoke execute on function public.pf_new_user() from public, anon, authenticated;

-- Live updates during drafts and in chat.
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'leagues') then
    alter publication supabase_realtime add table public.leagues;
  end if;
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'league_messages') then
    alter publication supabase_realtime add table public.league_messages;
  end if;
end $$;

-- Scheduler: checks every minute for picks whose time has run out. If the scheduler can't be switched on,
-- auto-pick still runs whenever a signed-in person has the draft room open.
do $$ begin
  create extension if not exists pg_cron;
  perform cron.schedule('portfolio-autopick', '* * * * *', 'select public.pf_autopick_due()');
  perform cron.schedule('portfolio-cron-cleanup', '17 9 * * *', 'delete from cron.job_run_details where end_time < now() - interval ''2 days''');
exception when others then
  raise notice 'Scheduler not switched on (%).', sqlerrm;
end $$;

-- ------------------------------------------------ default auto-pick ranks
-- Football: the order teams went in The Portfolio's 2026 draft, then the rest. Basketball: a rough order from last season.
-- Edit ranks any time in the Table Editor; running this script again never overwrites your changes.
insert into public.pf_teams (sport, pool, team, rank) values
('football','ACC','Notre Dame',1),('football','Big 12','Texas Tech',2),('football','SEC','Georgia',3),('football','ACC','Miami',4),('football','NFL','Rams',5),('football','Big Ten','Ohio State',6),('football','Big Ten','Oregon',7),('football','Big Ten','Indiana',8),('football','NFL','Bills',9),('football','SEC','Alabama',10),('football','NFL','Broncos',11),('football','SEC','Texas',12),('football','NFL','Ravens',13),('football','NFL','Seahawks',14),('football','Big 12','BYU',15),('football','NFL','Texans',16),('football','Big Ten','USC',17),('football','NFL','Lions',18),('football','NFL','Eagles',19),('football','SEC','LSU',20),('football','NFL','Bengals',21),('football','NFL','Chargers',22),('football','NFL','Chiefs',23),('football','NFL','Cowboys',24),('football','NFL','Patriots',25),('football','NFL','49ers',26),('football','NFL','Buccaneers',27),('football','NFL','Bears',28),
('football','NFL','Jaguars',29),('football','NFL','Packers',30),('football','ACC','Clemson',31),('football','ACC','SMU',32),('football','NFL','Vikings',33),('football','NFL','Commanders',34),('football','NFL','Steelers',35),('football','Big 12','Utah',36),('football','NFL','Colts',37),('football','Big 12','Houston',38),('football','Big Ten','Penn State',39),('football','Big Ten','Michigan',40),('football','NFL','Saints',41),('football','ACC','Louisville',42),('football','Big Ten','Washington',43),('football','SEC','Texas A&M',44),('football','SEC','Oklahoma',45),('football','SEC','Ole Miss',46),('football','ACC','Virginia',47),('football','Big 12','Kansas State',48),('football','Non-P4','James Madison',49),('football','NFL','Panthers',50),('football','Big Ten','Iowa',51),('football','NFL','Falcons',52),('football','Non-P4','North Dakota State',53),('football','SEC','Tennessee',54),
('football','ACC','Pittsburgh',55),('football','ACC','NC State',56),('football','Non-P4','UNLV',57),('football','ACC','Virginia Tech',58),('football','NFL','Giants',59),('football','Big 12','Arizona',60),('football','NFL','Titans',61),('football','Non-P4','South Florida',62),('football','NFL','Browns',63),('football','Big 12','TCU',64),('football','Big Ten','Illinois',65),('football','Non-P4','Boise State',66),('football','Non-P4','Tulane',67),('football','SEC','Missouri',68),('football','Big 12','UCF',69),('football','Big 12','Arizona State',70),('football','Non-P4','Navy',71),('football','Big Ten','UCLA',72),('football','ACC','Florida State',73),('football','Big 12','Oklahoma State',74),('football','NFL','Raiders',75),('football','Non-P4','Army',76),('football','NFL','Jets',77),('football','Non-P4','Memphis',78),('football','SEC','South Carolina',79),('football','Non-P4','Liberty',80),
('football','NFL','Dolphins',81),('football','SEC','Vanderbilt',82),('football','Big Ten','Nebraska',83),('football','Big 12','Iowa State',84),('football','ACC','Georgia Tech',85),('football','Non-P4','North Texas',86),('football','NFL','Cardinals',87),('football','SEC','Florida',88),('football','Big Ten','Minnesota',89),('football','Big 12','Cincinnati',90),('football','ACC','Duke',91),('football','Non-P4','Old Dominion',92),('football','SEC','Auburn',93),('football','Big Ten','Wisconsin',94),('football','Big 12','Baylor',95),('football','ACC','Wake Forest',96),('football','Non-P4','Western Michigan',97),('football','SEC','Kentucky',98),('football','Big Ten','Northwestern',99),('football','Big 12','Kansas',100),('football','ACC','California',101),('football','Non-P4','Toledo',102),('football','SEC','Arkansas',103),('football','Big Ten','Michigan State',104),
('football','Big 12','Colorado',105),('football','ACC','North Carolina',106),('football','Non-P4','Fresno State',107),('football','SEC','Mississippi State',108),('football','Big Ten','Rutgers',109),('football','Big 12','West Virginia',110),('football','ACC','Syracuse',111),('football','Non-P4','San Diego State',112),('football','Big Ten','Maryland',113),('football','ACC','Boston College',114),('football','Non-P4','New Mexico',115),('football','Big Ten','Purdue',116),('football','ACC','Stanford',117),('football','Non-P4','Western Kentucky',118),('football','Non-P4','Kennesaw State',119),('football','Non-P4','Jacksonville State',120),('football','Non-P4','UTSA',121),('football','Non-P4','East Carolina',122),('football','Non-P4','Ohio',123),('football','Non-P4','Miami (OH)',124),('football','Non-P4','Troy',125),('football','Non-P4','Louisiana Tech',126),
('football','Non-P4','Texas State',127),('football','Non-P4','Washington State',128),('football','Non-P4','Hawaii',129),('football','Non-P4','UConn',130),('football','Non-P4','Georgia Southern',131),('football','Non-P4','Coastal Carolina',132),('football','Non-P4','Louisiana',133),('football','Non-P4','Appalachian State',134),('football','Non-P4','Marshall',135),('football','Non-P4','Utah State',136),('football','Non-P4','Central Michigan',137),('football','Non-P4','Air Force',138),('football','Non-P4','Temple',139),('football','Non-P4','Florida Atlantic',140),('football','Non-P4','Arkansas State',141),('football','Non-P4','Southern Miss',142),('football','Non-P4','Delaware',143),('football','Non-P4','Missouri State',144),('football','Non-P4','FIU',145),('football','Non-P4','Bowling Green',146),('football','Non-P4','Buffalo',147),('football','Non-P4','Wyoming',148),
('football','Non-P4','Nevada',149),('football','Non-P4','Colorado State',150),('football','Non-P4','Oregon State',151),('football','Non-P4','Rice',152),('football','Non-P4','Tulsa',153),('football','Non-P4','UAB',154),('football','Non-P4','South Alabama',155),('football','Non-P4','San Jose State',156),('football','Non-P4','Eastern Michigan',157),('football','Non-P4','Northern Illinois',158),('football','Non-P4','Kent State',159),('football','Non-P4','Ball State',160),('football','Non-P4','Akron',161),('football','Non-P4','Charlotte',162),('football','Non-P4','Georgia State',163),('football','Non-P4','Louisiana-Monroe',164),('football','Non-P4','Middle Tennessee',165),('football','Non-P4','New Mexico State',166),('football','Non-P4','Sam Houston',167),('football','Non-P4','UTEP',168),('football','Non-P4','UMass',169),('football','Non-P4','Sacramento State',170),
('basketball','NBA','Thunder',1),('basketball','NBA','Spurs',2),('basketball','SEC','Florida',3),('basketball','Big Ten','Michigan',4),('basketball','Big 12','Arizona',5),('basketball','ACC','Duke',6),('basketball','Big East','UConn',7),('basketball','NBA','Pistons',8),('basketball','Other','Gonzaga',9),('basketball','SEC','Alabama',10),('basketball','Big Ten','Purdue',11),('basketball','Big 12','Houston',12),('basketball','ACC','Louisville',13),('basketball','Big East','St. John''s',14),('basketball','Other','Saint Mary''s',15),('basketball','NBA','Celtics',16),('basketball','Other','Miami (OH)',17),('basketball','Other','Utah State',18),('basketball','Other','Saint Louis',19),('basketball','NBA','Knicks',20),('basketball','Other','VCU',21),('basketball','SEC','Tennessee',22),('basketball','Big Ten','Michigan State',23),('basketball','Big 12','Iowa State',24),
('basketball','ACC','Virginia',25),('basketball','Big East','Villanova',26),('basketball','Other','San Diego State',27),('basketball','Other','Santa Clara',28),('basketball','Other','Memphis',29),('basketball','NBA','Nuggets',30),('basketball','Other','Dayton',31),('basketball','Other','New Mexico',32),('basketball','Other','Boise State',33),('basketball','SEC','Arkansas',34),('basketball','Big Ten','Illinois',35),('basketball','Big 12','Kansas',36),('basketball','ACC','North Carolina',37),('basketball','Big East','Creighton',38),('basketball','Other','McNeese',39),('basketball','NBA','Cavaliers',40),('basketball','Other','High Point',41),('basketball','Other','Akron',42),('basketball','Other','South Florida',43),('basketball','Other','Liberty',44),('basketball','NBA','Rockets',45),('basketball','SEC','Vanderbilt',46),('basketball','Big Ten','Nebraska',47),
('basketball','Big 12','Texas Tech',48),('basketball','ACC','Clemson',49),('basketball','Big East','Seton Hall',50),('basketball','Other','Grand Canyon',51),('basketball','Other','Yale',52),('basketball','Other','Tulsa',53),('basketball','NBA','Lakers',54),('basketball','Other','Belmont',55),('basketball','Other','George Mason',56),('basketball','Other','Northern Iowa',57),('basketball','SEC','Kentucky',58),('basketball','Big Ten','Wisconsin',59),('basketball','Big 12','BYU',60),('basketball','ACC','NC State',61),('basketball','Big East','Marquette',62),('basketball','Other','UC Irvine',63),('basketball','NBA','Timberwolves',64),('basketball','Other','UC San Diego',65),('basketball','Other','Colorado State',66),('basketball','Other','Nevada',67),('basketball','Other','Wichita State',68),('basketball','NBA','Magic',69),('basketball','SEC','Auburn',70),('basketball','Big Ten','UCLA',71),
('basketball','Big 12','Baylor',72),('basketball','ACC','Miami',73),('basketball','Big East','Georgetown',74),('basketball','Other','North Texas',75),('basketball','Other','Drake',76),('basketball','Other','Bradley',77),('basketball','Other','Murray State',78),('basketball','NBA','Hawks',79),('basketball','Other','Loyola Chicago',80),('basketball','Other','Saint Joseph''s',81),('basketball','SEC','Texas A&M',82),('basketball','Big Ten','Iowa',83),('basketball','Big 12','TCU',84),('basketball','ACC','SMU',85),('basketball','Big East','Butler',86),('basketball','Other','Davidson',87),('basketball','NBA','Raptors',88),('basketball','Other','San Francisco',89),('basketball','Other','Princeton',90),('basketball','Other','Vermont',91),('basketball','Other','Charleston',92),('basketball','NBA','76ers',93),('basketball','SEC','Georgia',94),('basketball','Big Ten','Ohio State',95),
('basketball','Big 12','UCF',96),('basketball','ACC','Virginia Tech',97),('basketball','Big East','Xavier',98),('basketball','Other','UNC Wilmington',99),('basketball','Other','Kent State',100),('basketball','Other','Toledo',101),('basketball','Other','Hofstra',102),('basketball','NBA','Suns',103),('basketball','Other','Utah Valley',104),('basketball','Other','Florida Atlantic',105),('basketball','SEC','Missouri',106),('basketball','Big Ten','Indiana',107),('basketball','Big 12','Cincinnati',108),('basketball','ACC','Wake Forest',109),('basketball','Big East','Providence',110),('basketball','Other','UAB',111),('basketball','Other','Illinois State',112),('basketball','NBA','Pacers',113),('basketball','Other','Stephen F. Austin',114),('basketball','Other','Troy',115),('basketball','Other','Arkansas State',116),('basketball','NBA','Heat',117),('basketball','SEC','Texas',118),
('basketball','Big Ten','USC',119),('basketball','Big 12','West Virginia',120),('basketball','ACC','Syracuse',121),('basketball','Big East','DePaul',122),('basketball','Other','James Madison',123),('basketball','Other','Marshall',124),('basketball','Other','Oregon State',125),('basketball','Other','Washington State',126),('basketball','NBA','Clippers',127),('basketball','Other','Chattanooga',128),('basketball','Other','Furman',129),('basketball','SEC','Ole Miss',130),('basketball','Big Ten','Oregon',131),('basketball','Big 12','Kansas State',132),('basketball','ACC','Notre Dame',133),('basketball','Other','Samford',134),('basketball','Other','Lipscomb',135),('basketball','NBA','Trail Blazers',136),('basketball','Other','Winthrop',137),('basketball','Other','Montana',138),('basketball','Other','Northern Colorado',139),('basketball','SEC','Oklahoma',140),
('basketball','Big Ten','Washington',141),('basketball','Big 12','Oklahoma State',142),('basketball','ACC','California',143),('basketball','Other','South Dakota State',144),('basketball','NBA','Warriors',145),('basketball','Other','North Dakota State',146),('basketball','Other','St. Thomas',147),('basketball','Other','Robert Morris',148),('basketball','NBA','Hornets',149),('basketball','Other','Wright State',150),('basketball','Other','Oakland',151),('basketball','SEC','LSU',152),('basketball','Big Ten','Minnesota',153),('basketball','Big 12','Colorado',154),('basketball','ACC','Stanford',155),('basketball','Other','Cal Baptist',156),('basketball','Other','Hawaii',157),('basketball','NBA','Bucks',158),('basketball','Other','UC Santa Barbara',159),('basketball','Other','Quinnipiac',160),('basketball','Other','Siena',161),('basketball','Other','Merrimack',162),
('basketball','SEC','Mississippi State',163),('basketball','Big Ten','Northwestern',164),('basketball','Big 12','Arizona State',165),('basketball','ACC','Florida State',166),('basketball','NBA','Bulls',167),('basketball','Other','Bryant',168),('basketball','Other','Colgate',169),('basketball','Other','Navy',170),('basketball','Other','Norfolk State',171),('basketball','NBA','Grizzlies',172),('basketball','Other','Southern',173),('basketball','SEC','South Carolina',174),('basketball','Big Ten','Maryland',175),('basketball','Big 12','Utah',176),('basketball','ACC','Pittsburgh',177),('basketball','Other','Bethune-Cookman',178),('basketball','Other','Howard',179),('basketball','NBA','Mavericks',180),('basketball','Other','LIU',181),('basketball','Other','Tennessee State',182),('basketball','Other','Queens',183),('basketball','Big Ten','Rutgers',184),('basketball','ACC','Georgia Tech',185),
('basketball','Other','Duquesne',186),('basketball','NBA','Pelicans',187),('basketball','Other','Rhode Island',188),('basketball','Other','George Washington',189),('basketball','Other','Richmond',190),('basketball','Other','Temple',191),('basketball','NBA','Jazz',192),('basketball','Other','UNLV',193),('basketball','Big Ten','Penn State',194),('basketball','ACC','Boston College',195),('basketball','Other','Wyoming',196),('basketball','NBA','Kings',197),('basketball','NBA','Nets',198),('basketball','NBA','Wizards',199),('basketball','Other','Abilene Christian',200),('basketball','Other','Air Force',201),('basketball','Other','Alabama A&M',202),('basketball','Other','Alabama State',203),('basketball','Other','Albany',204),('basketball','Other','Alcorn State',205),('basketball','Other','American',206),('basketball','Other','Appalachian State',207),
('basketball','Other','Arkansas-Pine Bluff',208),('basketball','Other','Army',209),('basketball','Other','Austin Peay',210),('basketball','Other','Ball State',211),('basketball','Other','Bellarmine',212),('basketball','Other','Binghamton',213),('basketball','Other','Boston University',214),('basketball','Other','Bowling Green',215),('basketball','Other','Brown',216),('basketball','Other','Bucknell',217),('basketball','Other','Buffalo',218),('basketball','Other','Cal Poly',219),('basketball','Other','Cal State Bakersfield',220),('basketball','Other','Cal State Fullerton',221),('basketball','Other','Cal State Northridge',222),('basketball','Other','Campbell',223),('basketball','Other','Canisius',224),('basketball','Other','Central Arkansas',225),('basketball','Other','Central Connecticut',226),('basketball','Other','Central Michigan',227),('basketball','Other','Charleston Southern',228),
('basketball','Other','Charlotte',229),('basketball','Other','Chicago State',230),('basketball','Other','Cleveland State',231),('basketball','Other','Coastal Carolina',232),('basketball','Other','Columbia',233),('basketball','Other','Coppin State',234),('basketball','Other','Cornell',235),('basketball','Other','Dartmouth',236),('basketball','Other','Delaware',237),('basketball','Other','Delaware State',238),('basketball','Other','Denver',239),('basketball','Other','Detroit Mercy',240),('basketball','Other','Drexel',241),('basketball','Other','East Carolina',242),('basketball','Other','East Tennessee State',243),('basketball','Other','East Texas A&M',244),('basketball','Other','Eastern Illinois',245),('basketball','Other','Eastern Kentucky',246),('basketball','Other','Eastern Michigan',247),('basketball','Other','Eastern Washington',248),('basketball','Other','Elon',249),
('basketball','Other','Evansville',250),('basketball','Other','FIU',251),('basketball','Other','Fairfield',252),('basketball','Other','Fairleigh Dickinson',253),('basketball','Other','Florida A&M',254),('basketball','Other','Florida Gulf Coast',255),('basketball','Other','Fordham',256),('basketball','Other','Fresno State',257),('basketball','Other','Gardner-Webb',258),('basketball','Other','Georgia Southern',259),('basketball','Other','Georgia State',260),('basketball','Other','Grambling State',261),('basketball','Other','Green Bay',262),('basketball','Other','Hampton',263),('basketball','Other','Harvard',264),('basketball','Other','Holy Cross',265),('basketball','Other','Houston Christian',266),('basketball','Other','IU Indy',267),('basketball','Other','Idaho',268),('basketball','Other','Idaho State',269),('basketball','Other','Incarnate Word',270),
('basketball','Other','Indiana State',271),('basketball','Other','Iona',272),('basketball','Other','Jackson State',273),('basketball','Other','Jacksonville',274),('basketball','Other','Jacksonville State',275),('basketball','Other','Kansas City',276),('basketball','Other','Kennesaw State',277),('basketball','Other','La Salle',278),('basketball','Other','Lafayette',279),('basketball','Other','Lamar',280),('basketball','Other','Le Moyne',281),('basketball','Other','Lehigh',282),('basketball','Other','Lindenwood',283),('basketball','Other','Little Rock',284),('basketball','Other','Long Beach State',285),('basketball','Other','Longwood',286),('basketball','Other','Louisiana',287),('basketball','Other','Louisiana Tech',288),('basketball','Other','Louisiana-Monroe',289),('basketball','Other','Loyola Marymount',290),('basketball','Other','Loyola Maryland',291),('basketball','Other','Maine',292),
('basketball','Other','Manhattan',293),('basketball','Other','Marist',294),('basketball','Other','Maryland Eastern Shore',295),('basketball','Other','Mercer',296),('basketball','Other','Mercyhurst',297),('basketball','Other','Middle Tennessee',298),('basketball','Other','Milwaukee',299),('basketball','Other','Mississippi Valley State',300),('basketball','Other','Missouri State',301),('basketball','Other','Monmouth',302),('basketball','Other','Montana State',303),('basketball','Other','Morehead State',304),('basketball','Other','Morgan State',305),('basketball','Other','Mount St. Mary''s',306),('basketball','Other','NJIT',307),('basketball','Other','New Hampshire',308),('basketball','Other','New Haven',309),('basketball','Other','New Mexico State',310),('basketball','Other','New Orleans',311),('basketball','Other','Niagara',312),('basketball','Other','Nicholls',313),
('basketball','Other','North Alabama',314),('basketball','Other','North Carolina A&T',315),('basketball','Other','North Carolina Central',316),('basketball','Other','North Dakota',317),('basketball','Other','North Florida',318),('basketball','Other','Northeastern',319),('basketball','Other','Northern Arizona',320),('basketball','Other','Northern Illinois',321),('basketball','Other','Northern Kentucky',322),('basketball','Other','Northwestern State',323),('basketball','Other','Ohio',324),('basketball','Other','Old Dominion',325),('basketball','Other','Omaha',326),('basketball','Other','Oral Roberts',327),('basketball','Other','Pacific',328),('basketball','Other','Penn',329),('basketball','Other','Pepperdine',330),('basketball','Other','Portland',331),('basketball','Other','Portland State',332),('basketball','Other','Prairie View A&M',333),('basketball','Other','Presbyterian',334),
('basketball','Other','Purdue Fort Wayne',335),('basketball','Other','Radford',336),('basketball','Other','Rice',337),('basketball','Other','Rider',338),('basketball','Other','SIU Edwardsville',339),('basketball','Other','Sacramento State',340),('basketball','Other','Sacred Heart',341),('basketball','Other','Saint Peter''s',342),('basketball','Other','Sam Houston',343),('basketball','Other','San Diego',344),('basketball','Other','San Jose State',345),('basketball','Other','Seattle',346),('basketball','Other','South Alabama',347),('basketball','Other','South Carolina State',348),('basketball','Other','South Dakota',349),('basketball','Other','Southeast Missouri State',350),('basketball','Other','Southeastern Louisiana',351),('basketball','Other','Southern Illinois',352),('basketball','Other','Southern Indiana',353),('basketball','Other','Southern Miss',354),
('basketball','Other','Southern Utah',355),('basketball','Other','St. Bonaventure',356),('basketball','Other','Stetson',357),('basketball','Other','Stonehill',358),('basketball','Other','Stony Brook',359),('basketball','Other','Tarleton State',360),('basketball','Other','Tennessee Tech',361),('basketball','Other','Texas A&M-Corpus Christi',362),('basketball','Other','Texas Southern',363),('basketball','Other','Texas State',364),('basketball','Other','The Citadel',365),('basketball','Other','Towson',366),('basketball','Other','Tulane',367),('basketball','Other','UC Davis',368),('basketball','Other','UC Riverside',369),('basketball','Other','UIC',370),('basketball','Other','UMBC',371),('basketball','Other','UMass',372),('basketball','Other','UMass Lowell',373),('basketball','Other','UNC Asheville',374),('basketball','Other','UNC Greensboro',375),('basketball','Other','USC Upstate',376),
('basketball','Other','UT Arlington',377),('basketball','Other','UT Martin',378),('basketball','Other','UTEP',379),('basketball','Other','UTRGV',380),('basketball','Other','UTSA',381),('basketball','Other','Utah Tech',382),('basketball','Other','VMI',383),('basketball','Other','Valparaiso',384),('basketball','Other','Wagner',385),('basketball','Other','Weber State',386),('basketball','Other','West Florida',387),('basketball','Other','West Georgia',388),('basketball','Other','Western Carolina',389),('basketball','Other','Western Illinois',390),('basketball','Other','Western Kentucky',391),('basketball','Other','Western Michigan',392),('basketball','Other','William & Mary',393),('basketball','Other','Wofford',394),('basketball','Other','Youngstown State',395)
on conflict (sport, pool, team) do nothing;

-- ------------------------------------------------ the existing league
-- Brings over The Portfolio 2026-27 with its completed draft. The first account created becomes its commissioner.
insert into public.leagues (id, doc, created_at)
values ('the-portfolio-2026', '{"created":"2026-08-24T00:00:00Z","draftType":"snake","name":"The Portfolio","owners":["Chuck","Ryland","Jonah","Will","Luke","Wilson","Chris","Marshall","Ian","Pearse"],"picks":[{"n":1,"owner":"Chuck","pool":"ACC","slot":"ACC","team":"Notre Dame"},{"n":2,"owner":"Ryland","pool":"Big 12","slot":"Big 12","team":"Texas Tech"},{"n":3,"owner":"Jonah","pool":"SEC","slot":"SEC","team":"Georgia"},{"n":4,"owner":"Will","pool":"ACC","slot":"ACC","team":"Miami"},{"n":5,"owner":"Luke","pool":"NFL","slot":"NFL #1","team":"Rams"},{"n":6,"owner":"Wilson","pool":"Big Ten","slot":"Big Ten","team":"Ohio State"},{"n":7,"owner":"Chris","pool":"Big Ten","slot":"Big Ten","team":"Oregon"},{"n":8,"owner":"Marshall","pool":"Big Ten","slot":"Big Ten","team":"Indiana"},{"n":9,"owner":"Ian","pool":"NFL","slot":"NFL #1","team":"Bills"},{"n":10,"owner":"Pearse","pool":"SEC","slot":"SEC","team":"Alabama"},{"n":11,"owner":"Pearse","pool":"NFL","slot":"NFL #1","team":"Broncos"},{"n":12,"owner":"Ian","pool":"SEC","slot":"SEC","team":"Texas"},{"n":13,"owner":"Marshall","pool":"NFL","slot":"NFL #1","team":"Ravens"},{"n":14,"owner":"Chris","pool":"NFL","slot":"NFL #1","team":"Seahawks"},{"n":15,"owner":"Wilson","pool":"Big 12","slot":"Big 12","team":"BYU"},{"n":16,"owner":"Luke","pool":"NFL","slot":"NFL #2","team":"Texans"},{"n":17,"owner":"Will","pool":"Big Ten","slot":"Big Ten","team":"USC"},{"n":18,"owner":"Jonah","pool":"NFL","slot":"NFL #1","team":"Lions"},{"n":19,"owner":"Ryland","pool":"NFL","slot":"NFL #1","team":"Eagles"},{"n":20,"owner":"Chuck","pool":"SEC","slot":"SEC","team":"LSU"},{"n":21,"owner":"Chuck","pool":"NFL","slot":"NFL #1","team":"Bengals"},{"n":22,"owner":"Ryland","pool":"NFL","slot":"NFL #2","team":"Chargers"},{"n":23,"owner":"Jonah","pool":"NFL","slot":"NFL #2","team":"Chiefs"},{"n":24,"owner":"Will","pool":"NFL","slot":"NFL #1","team":"Cowboys"},{"n":25,"owner":"Luke","pool":"NFL","slot":"NFL #3","team":"Patriots"},{"n":26,"owner":"Wilson","pool":"NFL","slot":"NFL #1","team":"49ers"},{"n":27,"owner":"Chris","pool":"NFL","slot":"NFL #2","team":"Buccaneers"},{"n":28,"owner":"Marshall","pool":"NFL","slot":"NFL #2","team":"Bears"},{"n":29,"owner":"Ian","pool":"NFL","slot":"NFL #2","team":"Jaguars"},{"n":30,"owner":"Pearse","pool":"NFL","slot":"NFL #2","team":"Packers"},{"n":31,"owner":"Pearse","pool":"ACC","slot":"ACC","team":"Clemson"},{"n":32,"owner":"Ian","pool":"ACC","slot":"ACC","team":"SMU"},{"n":33,"owner":"Marshall","pool":"NFL","slot":"NFL #3","team":"Vikings"},{"n":34,"owner":"Chris","pool":"NFL","slot":"NFL #3","team":"Commanders"},{"n":35,"owner":"Wilson","pool":"NFL","slot":"NFL #2","team":"Steelers"},{"n":36,"owner":"Luke","pool":"Big 12","slot":"Big 12","team":"Utah"},{"n":37,"owner":"Will","pool":"NFL","slot":"NFL #2","team":"Colts"},{"n":38,"owner":"Jonah","pool":"Big 12","slot":"Big 12","team":"Houston"},{"n":39,"owner":"Ryland","pool":"Big Ten","slot":"Big Ten","team":"Penn State"},{"n":40,"owner":"Chuck","pool":"Big Ten","slot":"Big Ten","team":"Michigan"},{"n":41,"owner":"Chuck","pool":"NFL","slot":"NFL #2","team":"Saints"},{"n":42,"owner":"Ryland","pool":"ACC","slot":"ACC","team":"Louisville"},{"n":43,"owner":"Jonah","pool":"Big Ten","slot":"Big Ten","team":"Washington"},{"n":44,"owner":"Will","pool":"SEC","slot":"SEC","team":"Texas A&M"},{"n":45,"owner":"Luke","pool":"SEC","slot":"SEC","team":"Oklahoma"},{"n":46,"owner":"Wilson","pool":"SEC","slot":"SEC","team":"Ole Miss"},{"n":47,"owner":"Chris","pool":"ACC","slot":"ACC","team":"Virginia"},{"n":48,"owner":"Marshall","pool":"Big 12","slot":"Big 12","team":"Kansas State"},{"n":49,"owner":"Ian","pool":"Non-P4","slot":"Non-P4","team":"James Madison"},{"n":50,"owner":"Pearse","pool":"NFL","slot":"NFL #3","team":"Panthers"},{"n":51,"owner":"Pearse","pool":"Big Ten","slot":"Big Ten","team":"Iowa"},{"n":52,"owner":"Ian","pool":"NFL","slot":"NFL #3","team":"Falcons"},{"n":53,"owner":"Marshall","pool":"Non-P4","slot":"Non-P4","team":"North Dakota State"},{"n":54,"owner":"Chris","pool":"SEC","slot":"SEC","team":"Tennessee"},{"n":55,"owner":"Wilson","pool":"ACC","slot":"ACC","team":"Pittsburgh"},{"n":56,"owner":"Luke","pool":"ACC","slot":"ACC","team":"NC State"},{"n":57,"owner":"Will","pool":"Non-P4","slot":"Non-P4","team":"UNLV"},{"n":58,"owner":"Jonah","pool":"ACC","slot":"ACC","team":"Virginia Tech"},{"n":59,"owner":"Ryland","pool":"NFL","slot":"NFL #3","team":"Giants"},{"n":60,"owner":"Chuck","pool":"Big 12","slot":"Big 12","team":"Arizona"},{"n":61,"owner":"Chuck","pool":"NFL","slot":"NFL #3","team":"Titans"},{"n":62,"owner":"Ryland","pool":"Non-P4","slot":"Non-P4","team":"South Florida"},{"n":63,"owner":"Jonah","pool":"NFL","slot":"NFL #3","team":"Browns"},{"n":64,"owner":"Will","pool":"Big 12","slot":"Big 12","team":"TCU"},{"n":65,"owner":"Luke","pool":"Big Ten","slot":"Big Ten","team":"Illinois"},{"n":66,"owner":"Wilson","pool":"Non-P4","slot":"Non-P4","team":"Boise State"},{"n":67,"owner":"Chris","pool":"Non-P4","slot":"Non-P4","team":"Tulane"},{"n":68,"owner":"Marshall","pool":"SEC","slot":"SEC","team":"Missouri"},{"n":69,"owner":"Ian","pool":"Big 12","slot":"Big 12","team":"UCF"},{"n":70,"owner":"Pearse","pool":"Big 12","slot":"Big 12","team":"Arizona State"},{"n":71,"owner":"Pearse","pool":"Non-P4","slot":"Non-P4","team":"Navy"},{"n":72,"owner":"Ian","pool":"Big Ten","slot":"Big Ten","team":"UCLA"},{"n":73,"owner":"Marshall","pool":"ACC","slot":"ACC","team":"Florida State"},{"n":74,"owner":"Chris","pool":"Big 12","slot":"Big 12","team":"Oklahoma State"},{"n":75,"owner":"Wilson","pool":"NFL","slot":"NFL #3","team":"Raiders"},{"n":76,"owner":"Luke","pool":"Non-P4","slot":"Non-P4","team":"Army"},{"n":77,"owner":"Will","pool":"NFL","slot":"NFL #3","team":"Jets"},{"n":78,"owner":"Jonah","pool":"Non-P4","slot":"Non-P4","team":"Memphis"},{"n":79,"owner":"Ryland","pool":"SEC","slot":"SEC","team":"South Carolina"},{"n":80,"owner":"Chuck","pool":"Non-P4","slot":"Non-P4","team":"Liberty"}],"slots":{"ACC":1,"Big 12":1,"Big Ten":1,"NFL":3,"Non-P4":1,"SEC":1},"status":"complete","year":2026,"sport":"football"}'::jsonb, '2026-08-24T00:00:00Z')
on conflict (id) do nothing;
insert into public.league_invites (league_id, code)
values ('the-portfolio-2026', substr(md5(random()::text || clock_timestamp()::text), 1, 10))
on conflict (league_id) do nothing;

-- Tell the API layer about the new columns and functions straight away.
notify pgrst, 'reload schema';
