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
--   trade_offers    trade proposals, readable only by the two managers involved and the commissioner
--   score_days      every NFL, college football, NBA, college basketball and European soccer final, collected from ESPN's public scoreboard every few minutes
--   pf_logos        team logos and colors from ESPN's team lists, refreshed weekly

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
            + coalesce((d->>'flex')::int, 0) + coalesce((d->>'flexNP')::int, 0);
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
            + coalesce((l.doc->>'flex')::int, 0) + coalesce((l.doc->>'flexNP')::int, 0);
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
  if (p_patch ? 'picks' or p_patch->>'status' = 'drafting') and jsonb_typeof(l.doc->'holds') = 'array' and jsonb_array_length(l.doc->'holds') > 0 then
    raise exception 'The draft can''t be changed after pickups or trades have been made.';
  end if;
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

-- Which pools can fill an "Any" spot: any college team (not NFL/NBA), any club in soccer, any conference in college basketball.
create or replace function public.pf_flex_ok(p_sport text, p_pool text) returns boolean
language sql immutable as $$
  select case coalesce(p_sport, 'football')
    when 'cbb' then true
    when 'basketball' then p_pool <> 'NBA'
    when 'soccer' then true
    else p_pool <> 'NFL' end $$;
-- College basketball "Non-P4" spots: any team outside the SEC, Big Ten, Big 12 and ACC.
create or replace function public.pf_np_ok(p_pool text) returns boolean
language sql immutable as $$ select p_pool not in ('SEC','Big Ten','Big 12','ACC') $$;
-- Whether a pick's spot is a flexible one (not tied to its own pool).
create or replace function public.pf_is_flex(p_sport text, p_slot text) returns boolean
language sql immutable as $$ select p_slot like 'Any%' or (p_sport = 'cbb' and p_slot like 'Non-P4%') $$;

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
  select count(*) into have from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = v_pool and not public.pf_is_flex(v_sport, e->>'slot');
  if coalesce((slots->>v_pool)::int, 0) > have then
    v_slot := case when (slots->>v_pool)::int > 1 then v_pool || ' #' || (have + 1) else v_pool end;
  else
    flex := coalesce((l.doc->>'flexNP')::int, 0);
    select count(*) into used from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' like 'Non-P4%';
    if v_sport = 'cbb' and public.pf_np_ok(v_pool) and flex > used then
      v_slot := case when flex > 1 then 'Non-P4 #' || (used + 1) else 'Non-P4' end;
    else
      flex := coalesce((l.doc->>'flex')::int, 0);
      select count(*) into used from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' like 'Any%';
      if public.pf_flex_ok(v_sport, v_pool) and flex > used then
        v_slot := case when flex > 1 then 'Any #' || (used + 1) else 'Any' end;
      else
        raise exception '% has no open % spot.', seat, v_pool;
      end if;
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
           (select count(*) from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = t.pool and not public.pf_is_flex(v_sport, e->>'slot'))
       and not exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(t.team))
     order by q.ord limit 1;
  end if;
  -- Otherwise: the best-ranked team still on the board in a pool where this manager has an open required spot.
  if v_team is null then
    select t.team, t.pool into v_team, v_pool
      from public.pf_teams t
     where t.sport = v_sport
       and coalesce((slots->>t.pool)::int, 0) >
           (select count(*) from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = t.pool and not public.pf_is_flex(v_sport, e->>'slot'))
       and not exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(t.team))
     order by t.rank limit 1;
  end if;
  if v_team is not null then
    select count(*) into have from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'pool' = v_pool and not public.pf_is_flex(v_sport, e->>'slot');
    v_slot := case when (slots->>v_pool)::int > 1 then v_pool || ' #' || (have + 1) else v_pool end;
  else
    -- No required spot left to fill: a college basketball "Non-P4" spot first, then an "any" spot.
    flex := case when v_sport = 'cbb' then coalesce((l.doc->>'flexNP')::int, 0) else 0 end;
    select count(*) into used from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' like 'Non-P4%';
    if flex > used then
      select t.team, t.pool into v_team, v_pool
        from public.pf_teams t
       where t.sport = v_sport and public.pf_np_ok(t.pool)
         and not exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(t.team))
       order by t.rank limit 1;
      v_slot := case when flex > 1 then 'Non-P4 #' || (used + 1) else 'Non-P4' end;
    end if;
    flex := coalesce((l.doc->>'flex')::int, 0);
    select count(*) into used from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' like 'Any%';
    if v_team is null and flex > used then
      select t.team, t.pool into v_team, v_pool
        from public.pf_teams t
       where t.sport = v_sport and public.pf_flex_ok(v_sport, t.pool)
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
declare s boolean := false; sc jsonb := null;
begin
  begin
    execute 'select exists (select 1 from cron.job where jobname = ''portfolio-autopick'')' into s;
  exception when others then s := false;
  end;
  begin   -- basketball results: when ESPN was last read and how many days of finals are stored
    execute 'select jsonb_build_object(''last'', (select max(at) from public.score_log where status = 200),
      ''days'', (select count(*) from public.score_days), ''logos'', (select count(*) from public.pf_logos), ''net'', exists (select 1 from pg_extension where extname = ''pg_net''))' into sc;
    execute 'select $1 || jsonb_build_object(''job'', exists (select 1 from cron.job where jobname = ''portfolio-scores''))' into sc using sc;
  exception when others then null;
  end;
  return jsonb_build_object('version', 10, 'scheduler', s, 'scores', sc);
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

-- ------------------------------------------------ pickups and trades
-- Rosters change over time. Once the first pickup or trade happens, the league keeps "holds": one entry per
-- team a manager has held, with the league week it started counting ("from") and the week it stopped ("to").
-- A change made during a week takes effect at the start of the next league week (Tuesday, Eastern time).
create table if not exists public.trade_offers (
  id          bigint generated always as identity primary key,
  league_id   text not null references public.leagues(id) on delete cascade,
  from_owner  text not null,
  to_owner    text not null,
  give        jsonb not null,          -- team names the proposer sends
  get         jsonb not null,          -- team names the proposer receives
  status      text not null default 'pending',   -- pending, accepted, declined, canceled, failed
  note        text,
  created_by  uuid,
  created_at  timestamptz not null default now(),
  decided_at  timestamptz
);
create index if not exists trade_offers_by_league on public.trade_offers (league_id, id desc);
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'trade_offers') then
    alter publication supabase_realtime add table public.trade_offers;     -- offers update live
  end if;
end $$;
alter table public.trade_offers enable row level security;
revoke all on public.trade_offers from anon, authenticated;
grant select on public.trade_offers to authenticated;

-- Start of the league week (Tuesday) containing a date.
create or replace function public.pf_week_start(d date) returns date
language sql immutable as $$ select d - ((extract(dow from d)::int + 5) % 7) $$;
-- Today in Eastern time, and the date a change made now takes effect.
create or replace function public.pf_today() returns date
language sql stable as $$ select (now() at time zone 'America/New_York')::date $$;
create or replace function public.pf_next_week() returns date
language sql stable as $$ select public.pf_week_start(public.pf_today()) + 7 $$;

-- The league's holds, built from the draft the first time they're needed.
create or replace function public.pf_holds(d jsonb) returns jsonb
language sql immutable as $$
  select case when jsonb_typeof(d->'holds') = 'array' and jsonb_array_length(d->'holds') > 0 then d->'holds'
    else coalesce((select jsonb_agg(jsonb_build_object('owner', e->>'owner', 'team', e->>'team', 'pool', e->>'pool', 'slot', e->>'slot', 'n', e->'n')
                     order by (e->>'n')::int) from jsonb_array_elements(coalesce(d->'picks', '[]'::jsonb)) e), '[]'::jsonb) end;
$$;

-- Is this person allowed to act for this seat (they hold it, or they run the league)?
create or replace function public.pf_acts_for(l public.leagues, p_owner text) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (l.doc->'owners') ? p_owner
     and (coalesce(l.members->>p_owner, '') = auth.uid()::text or public.pf_can_run(l));
$$;

-- Can the signed-in person see this trade offer? The two managers involved and the commissioner can.
create or replace function public.pf_trade_visible(p_league text, p_from text, p_to text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.leagues l where l.id = p_league
    and (public.pf_can_run(l) or coalesce(l.members->>p_from, '') = auth.uid()::text or coalesce(l.members->>p_to, '') = auth.uid()::text));
$$;
drop policy if exists "involved can read offers" on public.trade_offers;
create policy "involved can read offers" on public.trade_offers for select to authenticated
  using (public.pf_trade_visible(league_id, from_owner, to_owner));

-- Offers that include a team which has since moved can no longer go through.
create or replace function public.pf_fail_offers(p_id text, p_teams text[], p_except bigint) returns void
language sql security definer set search_path = public as $$
  update public.trade_offers set status = 'failed', note = 'A team in this offer has moved since it was made.', decided_at = now()
   where league_id = p_id and status = 'pending' and id is distinct from p_except
     and (give ?| p_teams or get ?| p_teams);
$$;

-- Pick up a free agent and drop a team from the same conference (or the same "any" spot).
create or replace function public.add_drop(p_id text, p_owner text, p_add text, p_drop text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  l public.leagues; h jsonb; i int; drop_ix int := -1; dropped jsonb; v_sport text; v_pro text;
  v_team text; v_pool text; eff date := public.pf_next_week(); until text; moves jsonb;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if not public.pf_acts_for(l, p_owner) then raise exception 'You can only make moves for your own team.'; end if;
  if coalesce(l.doc->>'status', '') <> 'complete' then raise exception 'Pickups open once the draft is finished.'; end if;
  until := l.doc->>'waiverUntil';
  if coalesce(until, '') <> '' and public.pf_today() > until::date then raise exception 'The pickup deadline has passed.'; end if;
  h := public.pf_holds(l.doc);
  for i in 0 .. jsonb_array_length(h) - 1 loop
    if h->i->>'owner' = p_owner and lower(h->i->>'team') = lower(trim(p_drop)) and coalesce(h->i->>'to', '') = '' then drop_ix := i; end if;
  end loop;
  if drop_ix < 0 then raise exception '% isn''t on %''s roster.', trim(p_drop), p_owner; end if;
  dropped := h->drop_ix;
  v_sport := coalesce(l.doc->>'sport', 'football');
  v_pro := case v_sport when 'basketball' then 'NBA' when 'football' then 'NFL' else '' end;
  select t.team, t.pool into v_team, v_pool from public.pf_teams t where t.sport = v_sport and lower(t.team) = lower(trim(p_add));
  if v_team is null then raise exception '% isn''t a team in this league''s pool.', trim(p_add); end if;
  if dropped->>'slot' like 'Any%' then
    if not public.pf_flex_ok(v_sport, v_pool) then raise exception 'That spot is for a college team.'; end if;
  elsif v_sport = 'cbb' and dropped->>'slot' like 'Non-P4%' then
    if not public.pf_np_ok(v_pool) then raise exception 'That spot is for a team outside the SEC, Big Ten, Big 12 and ACC.'; end if;
  elsif v_pool <> dropped->>'pool' then
    raise exception 'Replace % with another % team.', dropped->>'team', dropped->>'pool';
  end if;
  if exists (select 1 from jsonb_array_elements(h) e where lower(e->>'team') = lower(v_team) and coalesce(e->>'to', '') = '') then
    raise exception '% is already on a roster.', v_team;
  end if;
  h := jsonb_set(h, array[drop_ix::text], dropped || jsonb_build_object('to', eff::text));
  h := h || jsonb_build_array(jsonb_build_object('owner', p_owner, 'team', v_team, 'pool', v_pool, 'slot', dropped->>'slot', 'from', eff::text, 'via', 'add'));
  moves := coalesce(l.doc->'moves', '[]'::jsonb) || jsonb_build_array(jsonb_build_object(
    'at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 'eff', eff::text, 'kind', 'add',
    'owner', p_owner, 'add', v_team, 'drop', dropped->>'team', 'pool', v_pool));
  if pg_column_size(l.doc || jsonb_build_object('holds', h, 'moves', moves)) > 200000 then raise exception 'This league has too many moves to store.'; end if;
  update public.leagues set doc = l.doc || jsonb_build_object('holds', h, 'moves', moves), updated_at = now() where id = p_id;
  perform public.pf_fail_offers(p_id, array[dropped->>'team'], null);
  return jsonb_build_object('eff', eff::text, 'add', v_team, 'drop', dropped->>'team');
end $$;

-- Propose a trade. Each side sends the same number of teams from the same conferences.
create or replace function public.propose_trade(p_id text, p_from text, p_to text, p_give jsonb, p_get jsonb) returns bigint
language plpgsql security definer set search_path = public as $$
declare l public.leagues; h jsonb; until text; a text[]; b text[]; pa text[]; pb text[]; t text; p text; new_id bigint;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select * into l from public.leagues where id = p_id;
  if not found then raise exception 'League not found.'; end if;
  if not public.pf_acts_for(l, p_from) then raise exception 'You can only offer trades for your own team.'; end if;
  if not (l.doc->'owners') ? p_to or p_to = p_from then raise exception 'Choose another manager to trade with.'; end if;
  if coalesce(l.doc->>'status', '') <> 'complete' then raise exception 'Trades open once the draft is finished.'; end if;
  until := l.doc->>'tradeUntil';
  if coalesce(until, '') <> '' and public.pf_today() > until::date then raise exception 'The trade deadline has passed.'; end if;
  if jsonb_typeof(p_give) <> 'array' or jsonb_typeof(p_get) <> 'array' then raise exception 'That trade is not valid.'; end if;
  select array_agg(x) into a from jsonb_array_elements_text(p_give) x;
  select array_agg(x) into b from jsonb_array_elements_text(p_get) x;
  if a is null or b is null or cardinality(a) = 0 then raise exception 'Choose at least one team on each side.'; end if;
  if cardinality(a) <> cardinality(b) or cardinality(a) > 8 then raise exception 'Each side has to send the same number of teams.'; end if;
  h := public.pf_holds(l.doc);
  pa := '{}'; pb := '{}';
  foreach t in array a loop
    select e->>'pool' into p from jsonb_array_elements(h) e where e->>'owner' = p_from and lower(e->>'team') = lower(t) and coalesce(e->>'to', '') = '';
    if p is null then raise exception '% isn''t on %''s roster.', t, p_from; end if;
    pa := pa || p;
  end loop;
  foreach t in array b loop
    select e->>'pool' into p from jsonb_array_elements(h) e where e->>'owner' = p_to and lower(e->>'team') = lower(t) and coalesce(e->>'to', '') = '';
    if p is null then raise exception '% isn''t on %''s roster.', t, p_to; end if;
    pb := pb || p;
  end loop;
  if (select array_agg(x order by x) from unnest(pa) x) is distinct from (select array_agg(x order by x) from unnest(pb) x) then
    raise exception 'Trades are conference for conference: both sides must send teams from the same conferences.';
  end if;
  if (select count(distinct lower(x)) from unnest(a) x) <> cardinality(a) or (select count(distinct lower(x)) from unnest(b) x) <> cardinality(b) then
    raise exception 'A team is listed twice.';
  end if;
  insert into public.trade_offers (league_id, from_owner, to_owner, give, get, created_by)
  values (p_id, p_from, p_to, to_jsonb(a), to_jsonb(b), auth.uid()) returning id into new_id;
  return new_id;
end $$;

-- Accept or decline. Accepting swaps the teams, effective at the start of next week.
create or replace function public.respond_trade(p_offer bigint, p_accept boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  o public.trade_offers; l public.leagues; h jsonb; eff date := public.pf_next_week(); until text;
  pools text[]; pool text; ga int[]; gb int[]; k int; ia int; ib int; ea jsonb; eb jsonb; moves jsonb; ok boolean := true; j int;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select * into o from public.trade_offers where id = p_offer for update;
  if not found then raise exception 'That offer no longer exists.'; end if;
  select * into l from public.leagues where id = o.league_id for update;
  if not public.pf_acts_for(l, o.to_owner) then raise exception 'Only % can answer this offer.', o.to_owner; end if;
  if o.status <> 'pending' then raise exception 'This offer is no longer open.'; end if;
  if not p_accept then
    update public.trade_offers set status = 'declined', decided_at = now() where id = p_offer;
    return jsonb_build_object('status', 'declined');
  end if;
  until := l.doc->>'tradeUntil';
  if coalesce(until, '') <> '' and public.pf_today() > until::date then raise exception 'The trade deadline has passed.'; end if;
  h := public.pf_holds(l.doc);
  select array_agg(distinct e->>'pool') into pools from jsonb_array_elements(h) e;
  -- Pair the teams conference by conference, then swap each pair.
  for pool in select distinct hh->>'pool' from jsonb_array_elements(h) hh loop
    ga := '{}'; gb := '{}';
    for j in 0 .. jsonb_array_length(h) - 1 loop
      if h->j->>'pool' = pool and coalesce(h->j->>'to', '') = '' then
        if h->j->>'owner' = o.from_owner and exists (select 1 from jsonb_array_elements_text(o.give) x where lower(x) = lower(h->j->>'team')) then ga := ga || j; end if;
        if h->j->>'owner' = o.to_owner and exists (select 1 from jsonb_array_elements_text(o.get) x where lower(x) = lower(h->j->>'team')) then gb := gb || j; end if;
      end if;
    end loop;
    if coalesce(cardinality(ga), 0) <> coalesce(cardinality(gb), 0) then ok := false; end if;
    for k in 1 .. coalesce(cardinality(ga), 0) loop
      if k > coalesce(cardinality(gb), 0) then exit; end if;
      ia := ga[k]; ib := gb[k]; ea := h->ia; eb := h->ib;
      h := jsonb_set(h, array[ia::text], ea || jsonb_build_object('to', eff::text));
      h := jsonb_set(h, array[ib::text], eb || jsonb_build_object('to', eff::text));
      h := h || jsonb_build_array(
        jsonb_build_object('owner', o.to_owner, 'team', ea->>'team', 'pool', pool, 'slot', eb->>'slot', 'from', eff::text, 'via', 'trade'),
        jsonb_build_object('owner', o.from_owner, 'team', eb->>'team', 'pool', pool, 'slot', ea->>'slot', 'from', eff::text, 'via', 'trade'));
    end loop;
  end loop;
  -- Every team in the offer must still be where it was when the offer was made.
  if not ok or (select count(*) from jsonb_array_elements(h) e where coalesce(e->>'from', '') = eff::text and coalesce(e->>'to', '') = ''
                 and exists (select 1 from jsonb_array_elements_text(o.give || o.get) x where lower(x) = lower(e->>'team'))) * 1
                 < jsonb_array_length(o.give) + jsonb_array_length(o.get) then
    update public.trade_offers set status = 'failed', note = 'A team in this offer has moved since it was made.', decided_at = now() where id = p_offer;
    return jsonb_build_object('status', 'failed');
  end if;
  moves := coalesce(l.doc->'moves', '[]'::jsonb) || jsonb_build_array(jsonb_build_object(
    'at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 'eff', eff::text, 'kind', 'trade',
    'a', o.from_owner, 'b', o.to_owner, 'aGive', o.give, 'bGive', o.get));
  update public.leagues set doc = l.doc || jsonb_build_object('holds', h, 'moves', moves), updated_at = now() where id = l.id;
  update public.trade_offers set status = 'accepted', decided_at = now() where id = p_offer;
  perform public.pf_fail_offers(l.id, (select array_agg(x) from jsonb_array_elements_text(o.give || o.get) x), p_offer);
  return jsonb_build_object('status', 'accepted', 'eff', eff::text);
end $$;

create or replace function public.cancel_trade(p_offer bigint) returns void
language plpgsql security definer set search_path = public as $$
declare o public.trade_offers; l public.leagues;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select * into o from public.trade_offers where id = p_offer for update;
  if not found then return; end if;
  select * into l from public.leagues where id = o.league_id;
  if not public.pf_acts_for(l, o.from_owner) then raise exception 'Only % can withdraw this offer.', o.from_owner; end if;
  if o.status = 'pending' then update public.trade_offers set status = 'canceled', decided_at = now() where id = p_offer; end if;
end $$;

revoke execute on function public.add_drop(text, text, text, text), public.propose_trade(text, text, text, jsonb, jsonb),
  public.respond_trade(bigint, boolean), public.cancel_trade(bigint) from public, anon;
grant execute on function public.add_drop(text, text, text, text), public.propose_trade(text, text, text, jsonb, jsonb),
  public.respond_trade(bigint, boolean), public.cancel_trade(bigint) to authenticated;
grant execute on function public.pf_trade_visible(text, text, text), public.pf_week_start(date), public.pf_today(), public.pf_next_week() to anon, authenticated;
revoke execute on function public.pf_fail_offers(text, text[], bigint), public.pf_acts_for(public.leagues, text) from public, anon, authenticated;
grant execute on function public.pf_acts_for(public.leagues, text) to authenticated;

-- ------------------------------------------------ basketball scores
-- Every 5 minutes during the season the database asks ESPN's public scoreboard for today's NFL, college football,
-- NBA and college basketball games (and, before noon Eastern, yesterday's late finishers) and keeps every final in score_days.
-- Nothing here needs a key or account. The website reads score_days; browsers fill in live scores themselves.
--   NBA counts the regular season only (no preseason, NBA Cup final, play-in or playoffs).
--   College counts every Division I game except exhibitions, including conference tournaments and March Madness.
create table if not exists public.score_days (
  lg          text not null,
  day         date not null,
  games       jsonb not null default '[]'::jsonb,    -- [{i: ESPN id, h: home, a: away, hs, as}]
  updated_at  timestamptz not null default now(),
  primary key (lg, day)
);
alter table public.score_days drop constraint if exists score_days_lg_check;
alter table public.score_days add constraint score_days_lg_check check (lg in ('NBA','CBB','NFL','CFB','SOC'));
alter table public.score_days enable row level security;
drop policy if exists "Scores are public" on public.score_days;
create policy "Scores are public" on public.score_days for select to anon, authenticated using (true);
grant select on public.score_days to anon, authenticated;

create table if not exists public.score_fetch (       -- requests sent and not yet read
  request_id  bigint primary key,
  lg          text not null,
  day         date not null,
  created_at  timestamptz not null default now()
);
create table if not exists public.score_log (         -- one line per response read, kept two weeks
  id          bigint generated always as identity primary key,
  at          timestamptz not null default now(),
  lg          text not null,
  day         date not null,
  status      int,
  events      int,
  finals      int,
  note        text
);
alter table public.score_fetch enable row level security;
alter table public.score_log enable row level security;
revoke all on public.score_fetch, public.score_log from anon, authenticated;

create or replace function public.pf_espn_url(p_lg text, p_day date) returns text
language sql immutable as $$
  select case
    -- Soccer: one request per competition. 'SOC-eng.1' is a Premier League day, 'T-SOC-eng.1' its team list.
    when p_lg like 'T-SOC-%' then 'https://site.api.espn.com/apis/site/v2/sports/soccer/' || substr(p_lg, 7) || '/teams'
    when p_lg like 'SOC-%' then 'https://site.api.espn.com/apis/site/v2/sports/soccer/' || substr(p_lg, 5) || '/scoreboard?dates=' || to_char(p_day, 'YYYYMMDD')
    else case p_lg
    when 'T-NFL' then 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/teams?limit=100'
    when 'T-NBA' then 'https://site.api.espn.com/apis/site/v2/sports/basketball/nba/teams?limit=100'
    when 'T-CFB' then 'https://site.api.espn.com/apis/site/v2/sports/football/college-football/teams?groups=80&limit=500'
    when 'T-CBB' then 'https://site.api.espn.com/apis/site/v2/sports/basketball/mens-college-basketball/teams?limit=500'
    when 'NFL' then 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard?limit=100&dates=' || to_char(p_day, 'YYYYMMDD')
    when 'CFB' then 'https://site.api.espn.com/apis/site/v2/sports/football/college-football/scoreboard?groups=80&limit=500&dates=' || to_char(p_day, 'YYYYMMDD')
    when 'CFB-FCS' then 'https://site.api.espn.com/apis/site/v2/sports/football/college-football/scoreboard?groups=81&limit=500&dates=' || to_char(p_day, 'YYYYMMDD')
    when 'NBA' then 'https://site.api.espn.com/apis/site/v2/sports/basketball/nba/scoreboard?dates=' || to_char(p_day, 'YYYYMMDD')
    else 'https://site.api.espn.com/apis/site/v2/sports/basketball/mens-college-basketball/scoreboard?groups=50&limit=500&dates=' || to_char(p_day, 'YYYYMMDD')
  end end $$;

-- Finished games that count, from one ESPN scoreboard response.
--   NFL: regular season. College football: everything after preseason, including bowls and the playoff.
create or replace function public.pf_parse_scoreboard(p_lg text, p_body jsonb) returns jsonb
language sql immutable as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'i', e->>'id',
           'h', case when p_lg in ('NBA','NFL') then h->'team'->>'name' when p_lg = 'SOC' then h->'team'->>'displayName' else h->'team'->>'location' end,
           'a', case when p_lg in ('NBA','NFL') then w->'team'->>'name' when p_lg = 'SOC' then w->'team'->>'displayName' else w->'team'->>'location' end,
           'hs', (h->>'score')::int, 'as', (w->>'score')::int) order by e->>'id'), '[]'::jsonb)
  from jsonb_array_elements(coalesce(p_body->'events', '[]'::jsonb)) e
  cross join lateral (select e->'competitions'->0 as c) c
  cross join lateral (select (select x from jsonb_array_elements(c.c->'competitors') x where x->>'homeAway' = 'home' limit 1) as h,
                             (select x from jsonb_array_elements(c.c->'competitors') x where x->>'homeAway' = 'away' limit 1) as w) t
  where coalesce((c.c->'status'->'type'->>'completed')::boolean, (e->'status'->'type'->>'completed')::boolean, false)
    and h is not null and w is not null
    and (h->>'score') ~ '^\d+$' and (w->>'score') ~ '^\d+$'
    and case when p_lg = 'SOC' then true      -- soccer: every competitive match (a shootout leaves the score level: a draw)
          when p_lg = 'NFL' then coalesce(e->'season'->>'type', '2') = '2'
          when p_lg = 'NBA'
          then coalesce(e->'season'->>'type', '2') = '2'
               and coalesce((select string_agg(n->>'headline', ' ') from jsonb_array_elements(coalesce(c.c->'notes', '[]'::jsonb)) n), '') !~* 'cup.*(final|championship)'
          else coalesce(e->'season'->>'type', '2') <> '1'
               and coalesce((select string_agg(n->>'headline', ' ') from jsonb_array_elements(coalesce(c.c->'notes', '[]'::jsonb)) n), '') !~* 'exhibition'
        end
$$;

-- Other spellings ESPN and others use for college teams. Add a row here if score_unmatched lists a Division I team.
create table if not exists public.pf_aliases (alias text primary key, team text not null);
alter table public.pf_aliases enable row level security;
drop policy if exists "Aliases are public" on public.pf_aliases;
create policy "Aliases are public" on public.pf_aliases for select to anon, authenticated using (true);
grant select on public.pf_aliases to anon, authenticated;
insert into public.pf_aliases (alias, team) values
('app state','Appalachian State'),('american university','American'),('seattle u','Seattle'),('seattle university','Seattle'),('st. thomas-minnesota','St. Thomas'),('st. thomas (mn)','St. Thomas'),('st. thomas minnesota','St. Thomas'),('iu indianapolis','IU Indy'),
('iupui','IU Indy'),('hawai''i','Hawaii'),('long island university','LIU'),('long island','LIU'),('ualbany','Albany'),('se louisiana','Southeastern Louisiana'),('southeastern la.','Southeastern Louisiana'),('se missouri state','Southeast Missouri State'),
('southeast missouri','Southeast Missouri State'),('semo','Southeast Missouri State'),('ul monroe','Louisiana-Monroe'),('ut rio grande valley','UTRGV'),('texas rio grande valley','UTRGV'),('texas a&m-cc','Texas A&M-Corpus Christi'),('texas a&m corpus christi','Texas A&M-Corpus Christi'),('a&m-corpus christi','Texas A&M-Corpus Christi'),
('siue','SIU Edwardsville'),('southern illinois-edwardsville','SIU Edwardsville'),('csun','Cal State Northridge'),('csu northridge','Cal State Northridge'),('csu bakersfield','Cal State Bakersfield'),('csu fullerton','Cal State Fullerton'),('queens university','Queens'),('queens (nc)','Queens'),
('grambling','Grambling State'),('florida international','FIU'),('san josé state','San Jose State'),('mcneese state','McNeese'),('nicholls state','Nicholls'),('nebraska omaha','Omaha'),('umkc','Kansas City'),('fort wayne','Purdue Fort Wayne'),
('detroit','Detroit Mercy'),('loyola (md)','Loyola Maryland'),('loyola (chi)','Loyola Chicago'),('loyola-chicago','Loyola Chicago'),('loyola marymount university','Loyola Marymount'),('lmu','Loyola Marymount'),('fdu','Fairleigh Dickinson'),('pitt','Pittsburgh'),
('ucsb','UC Santa Barbara'),('college of charleston','Charleston'),('citadel','The Citadel'),('texas a&m-commerce','East Texas A&M'),('tennessee-martin','UT Martin'),('arkansas-little rock','Little Rock'),('ualr','Little Rock'),('southern university','Southern'),
('prairie view','Prairie View A&M'),('md eastern shore','Maryland Eastern Shore'),('maryland-eastern shore','Maryland Eastern Shore'),('umes','Maryland Eastern Shore'),('mississippi valley','Mississippi Valley State'),('bethune cookman','Bethune-Cookman'),('n.c. a&t','North Carolina A&T'),('nc a&t','North Carolina A&T'),
('nc central','North Carolina Central'),('n.c. central','North Carolina Central'),('gardner webb','Gardner-Webb'),('sc upstate','USC Upstate'),('south carolina upstate','USC Upstate'),('stephen f austin','Stephen F. Austin'),('sfa','Stephen F. Austin'),('texas-arlington','UT Arlington'),
('california baptist','Cal Baptist'),('tarleton','Tarleton State'),('dixie state','Utah Tech'),('st. joseph''s','Saint Joseph''s'),('st. peter''s','Saint Peter''s'),('st. mary''s','Saint Mary''s'),('st. louis','Saint Louis'),('saint john''s','St. John''s'),
('boston u','Boston University'),('william and mary','William & Mary'),('houston baptist','Houston Christian'),('etsu','East Tennessee State'),('uncg','UNC Greensboro'),('unc-wilmington','UNC Wilmington'),('uncw','UNC Wilmington'),('unc-asheville','UNC Asheville'),
('unc-greensboro','UNC Greensboro'),('sacramento st.','Sacramento State'),('csu sacramento','Sacramento State'),('mount st. marys','Mount St. Mary''s'),('miami (fla.)','Miami'),('miami (oh)','Miami (OH)'),('uconn','UConn'),('connecticut','UConn'),
('massachusetts','UMass'),('ole miss','Ole Miss'),('mississippi','Ole Miss'),('nc state','NC State'),('n.c. state','NC State'),('usc','USC'),('southern california','USC'),('lsu','LSU'),
('tcu','TCU'),('smu','SMU'),('ucf','UCF'),('byu','BYU'),('vcu','VCU'),('ucla','UCLA'),('unlv','UNLV'),('utep','UTEP'),
('utsa','UTSA'),('uab','UAB'),('uic','UIC'),('umbc','UMBC'),('njit','NJIT'),('fiu','FIU'),('liu','LIU'),('vmi','VMI'),
('army west point','Army'),('southern miss','Southern Miss'),('southern mississippi','Southern Miss'),('sam houston state','Sam Houston'),('louisiana-lafayette','Louisiana'),('ul lafayette','Louisiana'),('louisiana monroe','Louisiana-Monroe'),('ulm','Louisiana-Monroe')
on conflict (alias) do nothing;

create or replace function public.pf_cbb_name(p_name text) returns text
language sql stable set search_path = public as $$
  select coalesce((select team from public.pf_teams where sport = 'cbb' and lower(team) = lower(p_name) limit 1),
                  (select team from public.pf_aliases where alias = lower(p_name)), p_name) $$;
create or replace function public.pf_canon_cbb(p_games jsonb) returns jsonb
language sql stable set search_path = public as $$
  select coalesce(jsonb_agg(g || jsonb_build_object('h', public.pf_cbb_name(g->>'h'), 'a', public.pf_cbb_name(g->>'a')) order by g->>'i'), '[]'::jsonb)
  from jsonb_array_elements(p_games) g $$;

-- Team logos and colors, from ESPN's team lists. Refreshed weekly by the same job; the website reads them.
create table if not exists public.pf_logos (
  lg          text not null,                 -- NFL, NBA, CFB, CBB
  name        text not null,                 -- nickname for pro teams, school for college
  abbr        text,
  color       text,
  logo        text,
  updated_at  timestamptz not null default now(),
  primary key (lg, name)
);
alter table public.pf_logos enable row level security;
drop policy if exists "Logos are public" on public.pf_logos;
create policy "Logos are public" on public.pf_logos for select to anon, authenticated using (true);
grant select on public.pf_logos to anon, authenticated;

create or replace function public.pf_store_logos(p_lg text, p_body jsonb) returns int
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  with t as (
    select x->'team' as t from jsonb_array_elements(coalesce(p_body->'sports'->0->'leagues'->0->'teams', '[]'::jsonb)) x
  ), v as (
    select distinct on (nm) nm, t->>'abbreviation' as abbr,
           case when (t->>'color') ~* '^[0-9a-f]{6}$' then lower(t->>'color') end as color,
           case when (t->'logos'->0->>'href') ~* '^https://a[0-9]?\.espncdn\.com/' then t->'logos'->0->>'href' end as logo
    from t cross join lateral (select case when p_lg in ('NFL','NBA') then t->>'name' when p_lg = 'SOC' then t->>'displayName'
                                           when p_lg = 'CBB' then public.pf_cbb_name(t->>'location') else t->>'location' end as nm) z
    where nm is not null and nm <> ''
    order by nm
  )
  insert into public.pf_logos (lg, name, abbr, color, logo, updated_at)
  select p_lg, nm, abbr, color, logo, now() from v
  on conflict (lg, name) do update set abbr = excluded.abbr, color = coalesce(excluded.color, pf_logos.color),
    logo = coalesce(excluded.logo, pf_logos.logo), updated_at = now();
  get diagnostics n = row_count;
  return n;
end $$;
revoke execute on function public.pf_store_logos(text, jsonb) from public, anon, authenticated;

-- Soccer: keep the matches that involve a club on the list (cup ties against lower-division clubs included).
create or replace function public.pf_keep_soc(p_games jsonb) returns jsonb
language sql stable set search_path = public as $$
  select coalesce(jsonb_agg(g order by g->>'i'), '[]'::jsonb) from jsonb_array_elements(p_games) g
  where exists (select 1 from public.pf_teams t where t.sport = 'soccer' and lower(t.team) in (lower(g->>'h'), lower(g->>'a'))) $$;

-- Soccer competition-days already read, so the season so far is filled in a little at a time.
create table if not exists public.score_bf (lg text not null, day date not null, primary key (lg, day));
alter table public.score_bf enable row level security;
revoke all on public.score_bf from anon, authenticated;

-- Every competition a club from the five leagues can play in: league, domestic cups and super cups, Europe.
create or replace function public.pf_soc_comps() returns text[]
language sql immutable as $$
  select array['eng.1','esp.1','ger.1','ita.1','fra.1','uefa.champions','uefa.europa','uefa.europa.conf',
               'eng.fa','eng.league_cup','esp.copa_del_rey','ger.dfb_pokal','ita.coppa_italia','fra.coupe_de_france',
               'uefa.super_cup','eng.charity','esp.super_cup','ita.super_cup','ger.super_cup','fra.super_cup'] $$;

-- Adds finals to a day, replacing any earlier copy of the same game. Returns how many finals the day now holds.
create or replace function public.pf_store_scores(p_lg text, p_day date, p_games jsonb) returns int
language plpgsql security definer set search_path = public as $$
declare merged jsonb;
begin
  if jsonb_array_length(p_games) = 0 then
    return coalesce((select jsonb_array_length(games) from public.score_days where lg = p_lg and day = p_day), 0);
  end if;
  select coalesce(jsonb_agg(g order by g->>'i'), '[]'::jsonb) into merged from (
    select distinct on (g->>'i') g from (
      select g, 0 as pri from jsonb_array_elements(p_games) g
      union all
      select g, 1 from public.score_days s, jsonb_array_elements(s.games) g where s.lg = p_lg and s.day = p_day
    ) x order by g->>'i', pri) y;
  insert into public.score_days (lg, day, games, updated_at) values (p_lg, p_day, merged, now())
  on conflict (lg, day) do update set games = excluded.games, updated_at = now()
    where public.score_days.games is distinct from excluded.games;
  return jsonb_array_length(merged);
end $$;

-- Asks ESPN for one league-day. Does nothing if that request is already waiting.
create or replace function public.pf_request_scores(p_lg text, p_day date) returns bigint
language plpgsql security definer set search_path = public as $$
declare rid bigint;
begin
  if exists (select 1 from public.score_fetch where lg = p_lg and day = p_day and created_at > now() - interval '10 minutes') then return null; end if;
  delete from public.score_fetch where lg = p_lg and day = p_day;
  execute 'select net.http_get(url := $1, timeout_milliseconds := 25000)' into rid using public.pf_espn_url(p_lg, p_day);
  insert into public.score_fetch (request_id, lg, day) values (rid, p_lg, p_day);
  return rid;
end $$;

-- The scheduled job: read whatever ESPN has sent back, then ask again for the days that are in play.
create or replace function public.pf_scores_tick() returns void
language plpgsql security definer set search_path = public as $$
declare
  f record; r record; body jsonb; got jsonb; n int;
  et timestamp := now() at time zone 'America/New_York';
  today date := (now() at time zone 'America/New_York')::date;
  md int := extract(month from today)::int * 100 + extract(day from today)::int;
  lgs text[] := '{}';
  d date;
begin
  for f in select * from public.score_fetch order by created_at loop
    begin
      execute 'select status_code, content, timed_out, error_msg from net._http_response where id = $1' into r using f.request_id;
    exception when others then r := null;
    end;
    if r is null then
      if f.created_at < now() - interval '30 minutes' then
        delete from public.score_fetch where request_id = f.request_id;
        insert into public.score_log (lg, day, note) values (f.lg, f.day, 'no response');
      end if;
      continue;
    end if;
    begin
      if r.status_code = 200 and f.lg like 'T-%' then
        n := public.pf_store_logos(case when f.lg like 'T-SOC-%' then 'SOC' else substr(f.lg, 3) end, r.content::jsonb);
        insert into public.score_log (lg, day, status, events) values (f.lg, f.day, r.status_code, n);
      elsif r.status_code = 200 then
        body := r.content::jsonb;
        got := public.pf_parse_scoreboard(case when f.lg = 'CFB-FCS' then 'CFB' when f.lg like 'SOC-%' then 'SOC' else f.lg end, body);
        if f.lg = 'CBB' then got := public.pf_canon_cbb(got); end if;
        if f.lg like 'SOC-%' then
          got := public.pf_keep_soc(got);
          insert into public.score_bf (lg, day) values (f.lg, f.day) on conflict do nothing;
        end if;
        n := public.pf_store_scores(case when f.lg = 'CFB-FCS' then 'CFB' when f.lg like 'SOC-%' then 'SOC' else f.lg end, f.day, got);
        insert into public.score_log (lg, day, status, events, finals)
          values (f.lg, f.day, r.status_code, jsonb_array_length(coalesce(body->'events', '[]'::jsonb)), jsonb_array_length(got));
      else
        insert into public.score_log (lg, day, status, note)
          values (f.lg, f.day, r.status_code, left(coalesce(r.error_msg, case when r.timed_out then 'timed out' end, 'error'), 200));
        -- A competition ESPN doesn't know (4xx) isn't asked for again for that day.
        if f.lg like 'SOC-%' and r.status_code between 400 and 499 then
          insert into public.score_bf (lg, day) values (f.lg, f.day) on conflict do nothing;
        end if;
      end if;
    exception when others then
      insert into public.score_log (lg, day, status, note) values (f.lg, f.day, r.status_code, left('could not read: ' || sqlerrm, 200));
    end;
    delete from public.score_fetch where request_id = f.request_id;
    begin
      execute 'delete from net._http_response where id = $1' using f.request_id;
    exception when others then null;
    end;
  end loop;

  -- In season: NBA October through April, college November through the first days of April.
  if md >= 1001 or md <= 430 then lgs := lgs || 'NBA'::text; end if;
  if md >= 1101 or md <= 410 then lgs := lgs || 'CBB'::text; end if;
  -- Football: NFL September to mid-February; college late August to late January (FBS and FCS lists).
  if md >= 901 or md <= 215 then lgs := lgs || 'NFL'::text; end if;
  if md >= 820 or md <= 125 then lgs := lgs || 'CFB'::text || 'CFB-FCS'::text; end if;
  -- Soccer: August to early June, every competition.
  if md >= 801 or md <= 610 then
    lgs := lgs || array(select 'SOC-' || cc.comp from unnest(public.pf_soc_comps()) as cc(comp));
    -- Fill in earlier days of the season, about 100 requests per run, until every competition-day has been read.
    begin
    perform public.pf_request_scores(q.lg, q.day) from (
      select 'SOC-' || cc.comp as lg, ds.dd::date as day
      from unnest(public.pf_soc_comps()) as cc(comp),
           generate_series(make_date(case when md >= 701 then extract(year from today)::int else extract(year from today)::int - 1 end, 8, 1), today - 2, interval '1 day') as ds(dd)
      where not exists (select 1 from public.score_bf b where b.lg = 'SOC-' || cc.comp and b.day = ds.dd::date)
        and not exists (select 1 from public.score_fetch sf where sf.lg = 'SOC-' || cc.comp and sf.day = ds.dd::date)
      order by ds.dd limit 100) q;
    exception when others then
      insert into public.score_log (lg, day, note) values ('SOC', today, left('soccer backfill: ' || sqlerrm, 200));
    end;
  end if;
  -- First run with football: fill in the season so far, once.
  if not exists (select 1 from public.score_days where lg in ('NFL','CFB'))
     and not exists (select 1 from public.score_log where lg = 'BF-FB') then
    for d in select generate_series(make_date(case when md >= 701 then extract(year from today)::int else extract(year from today)::int - 1 end, 8, 20), today - 1, interval '1 day')::date loop
      perform public.pf_request_scores('CFB', d);
      perform public.pf_request_scores('CFB-FCS', d);
      if d >= make_date(extract(year from d)::int, 9, 1) or extract(month from d) < 3 then perform public.pf_request_scores('NFL', d); end if;
    end loop;
    insert into public.score_log (lg, day, note) values ('BF-FB', today, 'football season requested');
  end if;
  for i in 1 .. coalesce(array_length(lgs, 1), 0) loop
    if not exists (select 1 from public.score_log where lg = lgs[i] and day = today and at > now() - interval '9 minutes') then
      perform public.pf_request_scores(lgs[i], today);
    end if;
    -- Late games finish after midnight Eastern, so keep checking yesterday until noon.
    if extract(hour from et) < 12
       and not exists (select 1 from public.score_log where lg = lgs[i] and day = today - 1 and at > now() - interval '29 minutes') then
      perform public.pf_request_scores(lgs[i], today - 1);
    end if;
  end loop;
  -- Team logos: once a week (or straight away when there are none yet).
  if (not exists (select 1 from public.pf_logos where updated_at > now() - interval '7 days')
      or not exists (select 1 from public.pf_logos where lg = 'SOC'))
     and not exists (select 1 from public.score_log where lg like 'T-%' and at > now() - interval '6 hours') then
    perform public.pf_request_scores(x, today) from unnest(array['T-NFL','T-NBA','T-CFB','T-CBB','T-SOC-eng.1','T-SOC-esp.1','T-SOC-ger.1','T-SOC-ita.1','T-SOC-fra.1']) x;
  end if;
  delete from public.score_log where at < now() - interval '14 days';
end $$;

-- Fill in past days (for example after switching this on mid-season). Run in the SQL editor:
--   select public.pf_scores_backfill('2026-11-02', '2026-11-30');
-- Results arrive over the next few minutes as the job reads them.
create or replace function public.pf_scores_backfill(p_from date, p_to date) returns int
language plpgsql security definer set search_path = public as $$
declare d date; n int := 0;
begin
  if p_to - p_from > 200 then raise exception 'Pick at most 200 days at a time.'; end if;
  for d in select generate_series(p_from, p_to, interval '1 day')::date loop
    if public.pf_request_scores('NBA', d) is not null then n := n + 1; end if;
    if public.pf_request_scores('CBB', d) is not null then n := n + 1; end if;
  end loop;
  return n;
end $$;

-- College team names ESPN uses that don't match a team on the list. Should be empty, or only non-Division I opponents.
create or replace view public.score_unmatched with (security_invoker = true) as
  select x.name, count(*) as games, max(s.day) as last_seen
  from public.score_days s
  cross join lateral jsonb_array_elements(s.games) g
  cross join lateral (values (g->>'h'), (g->>'a')) as x(name)
  where s.lg = 'CBB' and not exists (select 1 from public.pf_teams t where t.sport = 'cbb' and lower(t.team) = lower(x.name))
  group by x.name;

revoke execute on function public.pf_store_scores(text, date, jsonb), public.pf_request_scores(text, date),
  public.pf_scores_tick(), public.pf_scores_backfill(date, date) from public, anon, authenticated;

do $$ begin
  create extension if not exists pg_net;
exception when others then
  raise notice 'Web requests (pg_net) not switched on (%). Basketball results will not be collected.', sqlerrm;
end $$;
do $$ begin
  perform cron.schedule('portfolio-scores', '*/5 * * * *', 'select public.pf_scores_tick()');
exception when others then
  raise notice 'Basketball score job not scheduled (%).', sqlerrm;
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

-- College basketball leagues: every Division I team in its 2026-27 conference, ranked like the basketball list.
insert into public.pf_teams (sport, pool, team, rank) values
('cbb','SEC','Florida',1),('cbb','Big Ten','Michigan',2),('cbb','Big 12','Arizona',3),('cbb','ACC','Duke',4),('cbb','Big East','UConn',5),('cbb','Pac-12','Gonzaga',6),('cbb','SEC','Alabama',7),('cbb','Big Ten','Purdue',8),('cbb','Big 12','Houston',9),('cbb','ACC','Louisville',10),('cbb','Big East','St. John''s',11),('cbb','WCC','Saint Mary''s',12),('cbb','MAC','Miami (OH)',13),('cbb','Pac-12','Utah State',14),('cbb','Atlantic 10','Saint Louis',15),('cbb','Atlantic 10','VCU',16),('cbb','SEC','Tennessee',17),('cbb','Big Ten','Michigan State',18),('cbb','Big 12','Iowa State',19),('cbb','ACC','Virginia',20),('cbb','Big East','Villanova',21),('cbb','Pac-12','San Diego State',22),('cbb','WCC','Santa Clara',23),('cbb','American','Memphis',24),('cbb','Atlantic 10','Dayton',25),('cbb','Mountain West','New Mexico',26),('cbb','Pac-12','Boise State',27),('cbb','SEC','Arkansas',28),
('cbb','Big Ten','Illinois',29),('cbb','Big 12','Kansas',30),('cbb','ACC','North Carolina',31),('cbb','Big East','Creighton',32),('cbb','Southland','McNeese',33),('cbb','Big South','High Point',34),('cbb','MAC','Akron',35),('cbb','American','South Florida',36),('cbb','Conference USA','Liberty',37),('cbb','SEC','Vanderbilt',38),('cbb','Big Ten','Nebraska',39),('cbb','Big 12','Texas Tech',40),('cbb','ACC','Clemson',41),('cbb','Big East','Seton Hall',42),('cbb','Mountain West','Grand Canyon',43),('cbb','Ivy','Yale',44),('cbb','American','Tulsa',45),('cbb','Missouri Valley','Belmont',46),('cbb','Atlantic 10','George Mason',47),('cbb','Missouri Valley','Northern Iowa',48),('cbb','SEC','Kentucky',49),('cbb','Big Ten','Wisconsin',50),('cbb','Big 12','BYU',51),('cbb','ACC','NC State',52),('cbb','Big East','Marquette',53),('cbb','Big West','UC Irvine',54),('cbb','Big West','UC San Diego',55),
('cbb','Pac-12','Colorado State',56),('cbb','Mountain West','Nevada',57),('cbb','American','Wichita State',58),('cbb','SEC','Auburn',59),('cbb','Big Ten','UCLA',60),('cbb','Big 12','Baylor',61),('cbb','ACC','Miami',62),('cbb','Big East','Georgetown',63),('cbb','American','North Texas',64),('cbb','Missouri Valley','Drake',65),('cbb','Missouri Valley','Bradley',66),('cbb','Missouri Valley','Murray State',67),('cbb','Atlantic 10','Loyola Chicago',68),('cbb','Atlantic 10','Saint Joseph''s',69),('cbb','SEC','Texas A&M',70),('cbb','Big Ten','Iowa',71),('cbb','Big 12','TCU',72),('cbb','ACC','SMU',73),('cbb','Big East','Butler',74),('cbb','Atlantic 10','Davidson',75),('cbb','WCC','San Francisco',76),('cbb','Ivy','Princeton',77),('cbb','America East','Vermont',78),('cbb','CAA','Charleston',79),('cbb','SEC','Georgia',80),('cbb','Big Ten','Ohio State',81),('cbb','Big 12','UCF',82),
('cbb','ACC','Virginia Tech',83),('cbb','Big East','Xavier',84),('cbb','CAA','UNC Wilmington',85),('cbb','MAC','Kent State',86),('cbb','MAC','Toledo',87),('cbb','CAA','Hofstra',88),('cbb','Big West','Utah Valley',89),('cbb','American','Florida Atlantic',90),('cbb','SEC','Missouri',91),('cbb','Big Ten','Indiana',92),('cbb','Big 12','Cincinnati',93),('cbb','ACC','Wake Forest',94),('cbb','Big East','Providence',95),('cbb','American','UAB',96),('cbb','Missouri Valley','Illinois State',97),('cbb','Southland','Stephen F. Austin',98),('cbb','Sun Belt','Troy',99),('cbb','Sun Belt','Arkansas State',100),('cbb','SEC','Texas',101),('cbb','Big Ten','USC',102),('cbb','Big 12','West Virginia',103),('cbb','ACC','Syracuse',104),('cbb','Big East','DePaul',105),('cbb','Sun Belt','James Madison',106),('cbb','Sun Belt','Marshall',107),('cbb','Pac-12','Oregon State',108),
('cbb','Pac-12','Washington State',109),('cbb','SoCon','Chattanooga',110),('cbb','SoCon','Furman',111),('cbb','SEC','Ole Miss',112),('cbb','Big Ten','Oregon',113),('cbb','Big 12','Kansas State',114),('cbb','ACC','Notre Dame',115),('cbb','SoCon','Samford',116),('cbb','ASUN','Lipscomb',117),('cbb','Big South','Winthrop',118),('cbb','Big Sky','Montana',119),('cbb','Big Sky','Northern Colorado',120),('cbb','SEC','Oklahoma',121),('cbb','Big Ten','Washington',122),('cbb','Big 12','Oklahoma State',123),('cbb','ACC','California',124),('cbb','Summit','South Dakota State',125),('cbb','Summit','North Dakota State',126),('cbb','Summit','St. Thomas',127),('cbb','Horizon','Robert Morris',128),('cbb','Horizon','Wright State',129),('cbb','Horizon','Oakland',130),('cbb','SEC','LSU',131),('cbb','Big Ten','Minnesota',132),('cbb','Big 12','Colorado',133),('cbb','ACC','Stanford',134),
('cbb','Big West','Cal Baptist',135),('cbb','Mountain West','Hawaii',136),('cbb','Big West','UC Santa Barbara',137),('cbb','MAAC','Quinnipiac',138),('cbb','MAAC','Siena',139),('cbb','MAAC','Merrimack',140),('cbb','SEC','Mississippi State',141),('cbb','Big Ten','Northwestern',142),('cbb','Big 12','Arizona State',143),('cbb','ACC','Florida State',144),('cbb','America East','Bryant',145),('cbb','Patriot','Colgate',146),('cbb','Patriot','Navy',147),('cbb','MEAC','Norfolk State',148),('cbb','SWAC','Southern',149),('cbb','SEC','South Carolina',150),('cbb','Big Ten','Maryland',151),('cbb','Big 12','Utah',152),('cbb','ACC','Pittsburgh',153),('cbb','SWAC','Bethune-Cookman',154),('cbb','MEAC','Howard',155),('cbb','NEC','LIU',156),('cbb','OVC','Tennessee State',157),('cbb','ASUN','Queens',158),('cbb','Big Ten','Rutgers',159),('cbb','ACC','Georgia Tech',160),('cbb','Atlantic 10','Duquesne',161),
('cbb','Atlantic 10','Rhode Island',162),('cbb','Atlantic 10','George Washington',163),('cbb','Atlantic 10','Richmond',164),('cbb','American','Temple',165),('cbb','Mountain West','UNLV',166),('cbb','Big Ten','Penn State',167),('cbb','ACC','Boston College',168),('cbb','Mountain West','Wyoming',169),('cbb','UAC','Abilene Christian',170),('cbb','Mountain West','Air Force',171),('cbb','SWAC','Alabama A&M',172),('cbb','SWAC','Alabama State',173),('cbb','America East','Albany',174),('cbb','SWAC','Alcorn State',175),('cbb','Patriot','American',176),('cbb','Sun Belt','Appalachian State',177),('cbb','SWAC','Arkansas-Pine Bluff',178),('cbb','Patriot','Army',179),('cbb','UAC','Austin Peay',180),('cbb','MAC','Ball State',181),('cbb','ASUN','Bellarmine',182),('cbb','America East','Binghamton',183),('cbb','Patriot','Boston University',184),('cbb','MAC','Bowling Green',185),('cbb','Ivy','Brown',186),
('cbb','Patriot','Bucknell',187),('cbb','MAC','Buffalo',188),('cbb','Big West','Cal Poly',189),('cbb','Big West','Cal State Bakersfield',190),('cbb','Big West','Cal State Fullerton',191),('cbb','Big West','Cal State Northridge',192),('cbb','CAA','Campbell',193),('cbb','MAAC','Canisius',194),('cbb','UAC','Central Arkansas',195),('cbb','NEC','Central Connecticut',196),('cbb','MAC','Central Michigan',197),('cbb','Big South','Charleston Southern',198),('cbb','American','Charlotte',199),('cbb','NEC','Chicago State',200),('cbb','Horizon','Cleveland State',201),('cbb','Sun Belt','Coastal Carolina',202),('cbb','Ivy','Columbia',203),('cbb','MEAC','Coppin State',204),('cbb','Ivy','Cornell',205),('cbb','Ivy','Dartmouth',206),('cbb','Conference USA','Delaware',207),('cbb','MEAC','Delaware State',208),('cbb','WCC','Denver',209),('cbb','Horizon','Detroit Mercy',210),('cbb','CAA','Drexel',211),
('cbb','American','East Carolina',212),('cbb','SoCon','East Tennessee State',213),('cbb','Southland','East Texas A&M',214),('cbb','OVC','Eastern Illinois',215),('cbb','UAC','Eastern Kentucky',216),('cbb','MAC','Eastern Michigan',217),('cbb','Big Sky','Eastern Washington',218),('cbb','CAA','Elon',219),('cbb','Missouri Valley','Evansville',220),('cbb','Conference USA','FIU',221),('cbb','MAAC','Fairfield',222),('cbb','NEC','Fairleigh Dickinson',223),('cbb','SWAC','Florida A&M',224),('cbb','ASUN','Florida Gulf Coast',225),('cbb','Atlantic 10','Fordham',226),('cbb','Pac-12','Fresno State',227),('cbb','Big South','Gardner-Webb',228),('cbb','Sun Belt','Georgia Southern',229),('cbb','Sun Belt','Georgia State',230),('cbb','SWAC','Grambling State',231),('cbb','Horizon','Green Bay',232),('cbb','CAA','Hampton',233),('cbb','Ivy','Harvard',234),('cbb','Patriot','Holy Cross',235),
('cbb','Southland','Houston Christian',236),('cbb','Horizon','IU Indy',237),('cbb','Big Sky','Idaho',238),('cbb','Big Sky','Idaho State',239),('cbb','Southland','Incarnate Word',240),('cbb','Missouri Valley','Indiana State',241),('cbb','MAAC','Iona',242),('cbb','SWAC','Jackson State',243),('cbb','ASUN','Jacksonville',244),('cbb','Conference USA','Jacksonville State',245),('cbb','Summit','Kansas City',246),('cbb','Conference USA','Kennesaw State',247),('cbb','Atlantic 10','La Salle',248),('cbb','Patriot','Lafayette',249),('cbb','Southland','Lamar',250),('cbb','NEC','Le Moyne',251),('cbb','Patriot','Lehigh',252),('cbb','OVC','Lindenwood',253),('cbb','UAC','Little Rock',254),('cbb','Big West','Long Beach State',255),('cbb','Big South','Longwood',256),('cbb','Sun Belt','Louisiana',257),('cbb','Sun Belt','Louisiana Tech',258),('cbb','Sun Belt','Louisiana-Monroe',259),
('cbb','WCC','Loyola Marymount',260),('cbb','Patriot','Loyola Maryland',261),('cbb','America East','Maine',262),('cbb','MAAC','Manhattan',263),('cbb','MAAC','Marist',264),('cbb','MEAC','Maryland Eastern Shore',265),('cbb','SoCon','Mercer',266),('cbb','NEC','Mercyhurst',267),('cbb','Conference USA','Middle Tennessee',268),('cbb','Horizon','Milwaukee',269),('cbb','SWAC','Mississippi Valley State',270),('cbb','Conference USA','Missouri State',271),('cbb','CAA','Monmouth',272),('cbb','Big Sky','Montana State',273),('cbb','OVC','Morehead State',274),('cbb','MEAC','Morgan State',275),('cbb','MAAC','Mount St. Mary''s',276),('cbb','America East','NJIT',277),('cbb','America East','New Hampshire',278),('cbb','NEC','New Haven',279),('cbb','Conference USA','New Mexico State',280),('cbb','Southland','New Orleans',281),('cbb','MAAC','Niagara',282),('cbb','Southland','Nicholls',283),
('cbb','UAC','North Alabama',284),('cbb','CAA','North Carolina A&T',285),('cbb','MEAC','North Carolina Central',286),('cbb','Summit','North Dakota',287),('cbb','ASUN','North Florida',288),('cbb','CAA','Northeastern',289),('cbb','Big Sky','Northern Arizona',290),('cbb','Horizon','Northern Illinois',291),('cbb','Horizon','Northern Kentucky',292),('cbb','Southland','Northwestern State',293),('cbb','MAC','Ohio',294),('cbb','Sun Belt','Old Dominion',295),('cbb','Summit','Omaha',296),('cbb','Summit','Oral Roberts',297),('cbb','WCC','Pacific',298),('cbb','Ivy','Penn',299),('cbb','WCC','Pepperdine',300),('cbb','WCC','Portland',301),('cbb','Big Sky','Portland State',302),('cbb','SWAC','Prairie View A&M',303),('cbb','Big South','Presbyterian',304),('cbb','Horizon','Purdue Fort Wayne',305),('cbb','Big South','Radford',306),('cbb','American','Rice',307),('cbb','MAAC','Rider',308),
('cbb','OVC','SIU Edwardsville',309),('cbb','Big West','Sacramento State',310),('cbb','MAAC','Sacred Heart',311),('cbb','MAAC','Saint Peter''s',312),('cbb','Conference USA','Sam Houston',313),('cbb','WCC','San Diego',314),('cbb','Mountain West','San Jose State',315),('cbb','WCC','Seattle',316),('cbb','Sun Belt','South Alabama',317),('cbb','MEAC','South Carolina State',318),('cbb','Summit','South Dakota',319),('cbb','OVC','Southeast Missouri State',320),('cbb','Southland','Southeastern Louisiana',321),('cbb','Missouri Valley','Southern Illinois',322),('cbb','OVC','Southern Indiana',323),('cbb','Sun Belt','Southern Miss',324),('cbb','Big Sky','Southern Utah',325),('cbb','Atlantic 10','St. Bonaventure',326),('cbb','ASUN','Stetson',327),('cbb','NEC','Stonehill',328),('cbb','CAA','Stony Brook',329),('cbb','UAC','Tarleton State',330),('cbb','SoCon','Tennessee Tech',331),
('cbb','Southland','Texas A&M-Corpus Christi',332),('cbb','SWAC','Texas Southern',333),('cbb','Pac-12','Texas State',334),('cbb','SoCon','The Citadel',335),('cbb','CAA','Towson',336),('cbb','American','Tulane',337),('cbb','Mountain West','UC Davis',338),('cbb','Big West','UC Riverside',339),('cbb','Missouri Valley','UIC',340),('cbb','America East','UMBC',341),('cbb','MAC','UMass',342),('cbb','America East','UMass Lowell',343),('cbb','Big South','UNC Asheville',344),('cbb','SoCon','UNC Greensboro',345),('cbb','Big South','USC Upstate',346),('cbb','UAC','UT Arlington',347),('cbb','OVC','UT Martin',348),('cbb','Mountain West','UTEP',349),('cbb','Southland','UTRGV',350),('cbb','American','UTSA',351),('cbb','Big Sky','Utah Tech',352),('cbb','SoCon','VMI',353),('cbb','Missouri Valley','Valparaiso',354),('cbb','NEC','Wagner',355),('cbb','Big Sky','Weber State',356),
('cbb','ASUN','West Florida',357),('cbb','UAC','West Georgia',358),('cbb','SoCon','Western Carolina',359),('cbb','OVC','Western Illinois',360),('cbb','Conference USA','Western Kentucky',361),('cbb','MAC','Western Michigan',362),('cbb','CAA','William & Mary',363),('cbb','SoCon','Wofford',364),('cbb','Horizon','Youngstown State',365)
on conflict (sport, pool, team) do nothing;

-- Soccer leagues: every club in the five big European leagues for 2026-27, roughly strongest first.
insert into public.pf_teams (sport, pool, team, rank) values
('soccer','LaLiga','Real Madrid',1),
('soccer','LaLiga','Barcelona',2),
('soccer','Bundesliga','Bayern Munich',3),
('soccer','Premier League','Arsenal',4),
('soccer','Premier League','Liverpool',5),
('soccer','Premier League','Manchester City',6),
('soccer','Ligue 1','Paris Saint-Germain',7),
('soccer','Serie A','Internazionale',8),
('soccer','Premier League','Chelsea',9),
('soccer','LaLiga','Atlético Madrid',10),
('soccer','Serie A','Napoli',11),
('soccer','Bundesliga','Bayer Leverkusen',12),
('soccer','Bundesliga','Borussia Dortmund',13),
('soccer','Premier League','Newcastle United',14),
('soccer','Premier League','Aston Villa',15),
('soccer','Premier League','Tottenham Hotspur',16),
('soccer','Premier League','Manchester United',17),
('soccer','Serie A','Juventus',18),
('soccer','Serie A','AC Milan',19),
('soccer','Serie A','Atalanta',20),
('soccer','Serie A','AS Roma',21),
('soccer','Ligue 1','Marseille',22),
('soccer','Ligue 1','AS Monaco',23),
('soccer','Bundesliga','RB Leipzig',24),
('soccer','Bundesliga','Eintracht Frankfurt',25),
('soccer','LaLiga','Athletic Club',26),
('soccer','LaLiga','Villarreal',27),
('soccer','LaLiga','Real Betis',28),
('soccer','Premier League','Brighton & Hove Albion',29),
('soccer','Premier League','Nottingham Forest',30),
('soccer','Ligue 1','Lille',31),
('soccer','Ligue 1','Lyon',32),
('soccer','Serie A','Como',33),
('soccer','Serie A','Lazio',34),
('soccer','Serie A','Bologna',35),
('soccer','Bundesliga','VfB Stuttgart',36),
('soccer','LaLiga','Real Sociedad',37),
('soccer','Ligue 1','Lens',38),
('soccer','Premier League','Crystal Palace',39),
('soccer','Premier League','Fulham',40),
('soccer','Premier League','Brentford',41),
('soccer','Premier League','AFC Bournemouth',42),
('soccer','Serie A','Fiorentina',43),
('soccer','Bundesliga','SC Freiburg',44),
('soccer','Bundesliga','TSG Hoffenheim',45),
('soccer','LaLiga','Celta Vigo',46),
('soccer','Ligue 1','Nice',47),
('soccer','Ligue 1','Strasbourg',48),
('soccer','Ligue 1','Stade Rennais',49),
('soccer','Premier League','Everton',50),
('soccer','LaLiga','Sevilla',51),
('soccer','LaLiga','Valencia',52),
('soccer','LaLiga','Osasuna',53),
('soccer','Bundesliga','Borussia Mönchengladbach',54),
('soccer','Bundesliga','Werder Bremen',55),
('soccer','Bundesliga','Mainz',56),
('soccer','Serie A','Torino',57),
('soccer','Serie A','Udinese',58),
('soccer','Ligue 1','Brest',59),
('soccer','Ligue 1','Toulouse',60),
('soccer','LaLiga','Rayo Vallecano',61),
('soccer','LaLiga','Getafe',62),
('soccer','LaLiga','Espanyol',63),
('soccer','Bundesliga','1. FC Union Berlin',64),
('soccer','Bundesliga','FC Augsburg',65),
('soccer','Premier League','Leeds United',66),
('soccer','Premier League','Sunderland',67),
('soccer','Serie A','Genoa',68),
('soccer','Serie A','Cagliari',69),
('soccer','Serie A','Parma',70),
('soccer','Serie A','Sassuolo',71),
('soccer','Ligue 1','Paris FC',72),
('soccer','Ligue 1','Le Havre AC',73),
('soccer','Ligue 1','AJ Auxerre',74),
('soccer','Ligue 1','Angers',75),
('soccer','Ligue 1','Lorient',76),
('soccer','LaLiga','Alavés',77),
('soccer','LaLiga','Elche',78),
('soccer','LaLiga','Levante',79),
('soccer','Bundesliga','Hamburg SV',80),
('soccer','Bundesliga','FC Cologne',81),
('soccer','Bundesliga','Schalke 04',82),
('soccer','Serie A','Lecce',83),
('soccer','Serie A','Monza',84),
('soccer','Serie A','Venezia',85),
('soccer','Serie A','Frosinone',86),
('soccer','Premier League','Coventry City',87),
('soccer','Premier League','Ipswich Town',88),
('soccer','Premier League','Hull City',89),
('soccer','LaLiga','Deportivo La Coruña',90),
('soccer','LaLiga','Málaga',91),
('soccer','LaLiga','Racing Santander',92),
('soccer','Bundesliga','SC Paderborn 07',93),
('soccer','Bundesliga','SV Elversberg',94),
('soccer','Ligue 1','Le Mans',95),
('soccer','Ligue 1','Troyes',96)
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
