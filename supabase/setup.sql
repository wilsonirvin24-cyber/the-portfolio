-- The Portfolio: database setup for Supabase.
-- Run this once in the Supabase SQL editor. It is safe to run again: nothing is dropped or overwritten.
--
-- What it creates
--   profiles        one private row per account (username, full name, phone, alert choices)
--   leagues         one row per league; readable by anyone with the link
--   league_invites  the invite code for each league; only its commissioner can read it
--   functions       the only way league data changes: create, edit, delete, join, leave, pick

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

-- --------------------------------------------------------------- helpers
create or replace function public.pf_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.pf_can_run(l public.leagues) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (l.commissioner = auth.uid() or public.pf_is_admin());
$$;

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
  insert into public.leagues (id, doc, commissioner)
  values (p_id, p_doc || jsonb_build_object('status', 'drafting', 'picks', '[]'::jsonb), auth.uid());
  insert into public.league_invites (league_id, code) values (p_id, code);
  return p_id;
exception when unique_violation then
  raise exception 'A league with that name and season already exists.';
end $$;

-- Commissioner edits: merges the given fields into the league (undo a pick, reopen the draft, rename).
create or replace function public.patch_league(p_id text, p_patch jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare l public.leagues;
begin
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if not public.pf_can_run(l) then raise exception 'Only the commissioner can change this league.'; end if;
  if pg_column_size(l.doc || p_patch) > 120000 then raise exception 'That league is too large.'; end if;
  update public.leagues set doc = l.doc || p_patch, updated_at = now() where id = p_id;
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
create or replace function public.make_pick(p_id text, p_team text, p_pool text, p_slot text) returns integer
language plpgsql security definer set search_path = public as $$
declare
  l public.leagues; owners jsonb; picks jsonb;
  n int; cnt int; rounds int; r int; pos int; seat text;
begin
  if auth.uid() is null then raise exception 'Sign in to make a pick.'; end if;
  select * into l from public.leagues where id = p_id for update;
  if not found then raise exception 'League not found.'; end if;
  if l.doc->>'status' <> 'drafting' then raise exception 'This draft is not open.'; end if;
  owners := l.doc->'owners';
  picks  := coalesce(l.doc->'picks', '[]'::jsonb);
  n := jsonb_array_length(picks);
  cnt := jsonb_array_length(owners);
  rounds := coalesce((select sum(value::int) from jsonb_each_text(coalesce(l.doc->'slots', '{}'::jsonb))), 0)
            + coalesce((l.doc->>'flex')::int, 0);
  if n >= cnt * rounds then raise exception 'The draft is complete.'; end if;
  r := n / cnt; pos := n % cnt;
  seat := owners->>(case when l.doc->>'draftType' = 'straight' or r % 2 = 0 then pos else cnt - 1 - pos end);
  if not public.pf_can_run(l) and coalesce(l.members->>seat, '') <> auth.uid()::text then
    raise exception 'It is %''s pick.', seat;
  end if;
  if coalesce(trim(p_team), '') = '' or length(p_team) > 60 or length(p_pool) > 30 or length(p_slot) > 30 then
    raise exception 'That pick is not valid.';
  end if;
  if exists (select 1 from jsonb_array_elements(picks) e where lower(e->>'team') = lower(trim(p_team))) then
    raise exception '% is already drafted.', trim(p_team);
  end if;
  if exists (select 1 from jsonb_array_elements(picks) e where e->>'owner' = seat and e->>'slot' = p_slot) then
    raise exception '% has already filled that spot.', seat;
  end if;
  picks := picks || jsonb_build_array(jsonb_build_object('n', n + 1, 'owner', seat, 'team', trim(p_team), 'pool', p_pool, 'slot', p_slot));
  update public.leagues
     set doc = l.doc || jsonb_build_object('picks', picks, 'status', case when n + 1 >= cnt * rounds then 'complete' else 'drafting' end),
         updated_at = now()
   where id = p_id;
  return n + 1;
end $$;

-- Only signed-in accounts may call the functions that change things.
revoke execute on function public.create_league(text, jsonb), public.patch_league(text, jsonb), public.delete_league(text),
  public.league_invite(text), public.join_league(text, text, text), public.release_seat(text, text),
  public.make_pick(text, text, text, text) from public, anon;
grant execute on function public.create_league(text, jsonb), public.patch_league(text, jsonb), public.delete_league(text),
  public.league_invite(text), public.join_league(text, text, text), public.release_seat(text, text),
  public.make_pick(text, text, text, text) to authenticated;
grant execute on function public.username_available(text), public.pf_is_admin() to anon, authenticated;
revoke execute on function public.pf_new_user() from public, anon, authenticated;

-- Live updates during drafts.
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'leagues') then
    alter publication supabase_realtime add table public.leagues;
  end if;
end $$;

-- ------------------------------------------------ the existing league
-- Brings over The Portfolio 2026-27 with its completed draft. The first account created becomes its commissioner.
insert into public.leagues (id, doc, created_at)
values ('the-portfolio-2026', '{"created":"2026-08-24T00:00:00Z","draftType":"snake","name":"The Portfolio","owners":["Chuck","Ryland","Jonah","Will","Luke","Wilson","Chris","Marshall","Ian","Pearse"],"picks":[{"n":1,"owner":"Chuck","pool":"ACC","slot":"ACC","team":"Notre Dame"},{"n":2,"owner":"Ryland","pool":"Big 12","slot":"Big 12","team":"Texas Tech"},{"n":3,"owner":"Jonah","pool":"SEC","slot":"SEC","team":"Georgia"},{"n":4,"owner":"Will","pool":"ACC","slot":"ACC","team":"Miami"},{"n":5,"owner":"Luke","pool":"NFL","slot":"NFL #1","team":"Rams"},{"n":6,"owner":"Wilson","pool":"Big Ten","slot":"Big Ten","team":"Ohio State"},{"n":7,"owner":"Chris","pool":"Big Ten","slot":"Big Ten","team":"Oregon"},{"n":8,"owner":"Marshall","pool":"Big Ten","slot":"Big Ten","team":"Indiana"},{"n":9,"owner":"Ian","pool":"NFL","slot":"NFL #1","team":"Bills"},{"n":10,"owner":"Pearse","pool":"SEC","slot":"SEC","team":"Alabama"},{"n":11,"owner":"Pearse","pool":"NFL","slot":"NFL #1","team":"Broncos"},{"n":12,"owner":"Ian","pool":"SEC","slot":"SEC","team":"Texas"},{"n":13,"owner":"Marshall","pool":"NFL","slot":"NFL #1","team":"Ravens"},{"n":14,"owner":"Chris","pool":"NFL","slot":"NFL #1","team":"Seahawks"},{"n":15,"owner":"Wilson","pool":"Big 12","slot":"Big 12","team":"BYU"},{"n":16,"owner":"Luke","pool":"NFL","slot":"NFL #2","team":"Texans"},{"n":17,"owner":"Will","pool":"Big Ten","slot":"Big Ten","team":"USC"},{"n":18,"owner":"Jonah","pool":"NFL","slot":"NFL #1","team":"Lions"},{"n":19,"owner":"Ryland","pool":"NFL","slot":"NFL #1","team":"Eagles"},{"n":20,"owner":"Chuck","pool":"SEC","slot":"SEC","team":"LSU"},{"n":21,"owner":"Chuck","pool":"NFL","slot":"NFL #1","team":"Bengals"},{"n":22,"owner":"Ryland","pool":"NFL","slot":"NFL #2","team":"Chargers"},{"n":23,"owner":"Jonah","pool":"NFL","slot":"NFL #2","team":"Chiefs"},{"n":24,"owner":"Will","pool":"NFL","slot":"NFL #1","team":"Cowboys"},{"n":25,"owner":"Luke","pool":"NFL","slot":"NFL #3","team":"Patriots"},{"n":26,"owner":"Wilson","pool":"NFL","slot":"NFL #1","team":"49ers"},{"n":27,"owner":"Chris","pool":"NFL","slot":"NFL #2","team":"Buccaneers"},{"n":28,"owner":"Marshall","pool":"NFL","slot":"NFL #2","team":"Bears"},{"n":29,"owner":"Ian","pool":"NFL","slot":"NFL #2","team":"Jaguars"},{"n":30,"owner":"Pearse","pool":"NFL","slot":"NFL #2","team":"Packers"},{"n":31,"owner":"Pearse","pool":"ACC","slot":"ACC","team":"Clemson"},{"n":32,"owner":"Ian","pool":"ACC","slot":"ACC","team":"SMU"},{"n":33,"owner":"Marshall","pool":"NFL","slot":"NFL #3","team":"Vikings"},{"n":34,"owner":"Chris","pool":"NFL","slot":"NFL #3","team":"Commanders"},{"n":35,"owner":"Wilson","pool":"NFL","slot":"NFL #2","team":"Steelers"},{"n":36,"owner":"Luke","pool":"Big 12","slot":"Big 12","team":"Utah"},{"n":37,"owner":"Will","pool":"NFL","slot":"NFL #2","team":"Colts"},{"n":38,"owner":"Jonah","pool":"Big 12","slot":"Big 12","team":"Houston"},{"n":39,"owner":"Ryland","pool":"Big Ten","slot":"Big Ten","team":"Penn State"},{"n":40,"owner":"Chuck","pool":"Big Ten","slot":"Big Ten","team":"Michigan"},{"n":41,"owner":"Chuck","pool":"NFL","slot":"NFL #2","team":"Saints"},{"n":42,"owner":"Ryland","pool":"ACC","slot":"ACC","team":"Louisville"},{"n":43,"owner":"Jonah","pool":"Big Ten","slot":"Big Ten","team":"Washington"},{"n":44,"owner":"Will","pool":"SEC","slot":"SEC","team":"Texas A&M"},{"n":45,"owner":"Luke","pool":"SEC","slot":"SEC","team":"Oklahoma"},{"n":46,"owner":"Wilson","pool":"SEC","slot":"SEC","team":"Ole Miss"},{"n":47,"owner":"Chris","pool":"ACC","slot":"ACC","team":"Virginia"},{"n":48,"owner":"Marshall","pool":"Big 12","slot":"Big 12","team":"Kansas State"},{"n":49,"owner":"Ian","pool":"Non-P4","slot":"Non-P4","team":"James Madison"},{"n":50,"owner":"Pearse","pool":"NFL","slot":"NFL #3","team":"Panthers"},{"n":51,"owner":"Pearse","pool":"Big Ten","slot":"Big Ten","team":"Iowa"},{"n":52,"owner":"Ian","pool":"NFL","slot":"NFL #3","team":"Falcons"},{"n":53,"owner":"Marshall","pool":"Non-P4","slot":"Non-P4","team":"North Dakota State"},{"n":54,"owner":"Chris","pool":"SEC","slot":"SEC","team":"Tennessee"},{"n":55,"owner":"Wilson","pool":"ACC","slot":"ACC","team":"Pittsburgh"},{"n":56,"owner":"Luke","pool":"ACC","slot":"ACC","team":"NC State"},{"n":57,"owner":"Will","pool":"Non-P4","slot":"Non-P4","team":"UNLV"},{"n":58,"owner":"Jonah","pool":"ACC","slot":"ACC","team":"Virginia Tech"},{"n":59,"owner":"Ryland","pool":"NFL","slot":"NFL #3","team":"Giants"},{"n":60,"owner":"Chuck","pool":"Big 12","slot":"Big 12","team":"Arizona"},{"n":61,"owner":"Chuck","pool":"NFL","slot":"NFL #3","team":"Titans"},{"n":62,"owner":"Ryland","pool":"Non-P4","slot":"Non-P4","team":"South Florida"},{"n":63,"owner":"Jonah","pool":"NFL","slot":"NFL #3","team":"Browns"},{"n":64,"owner":"Will","pool":"Big 12","slot":"Big 12","team":"TCU"},{"n":65,"owner":"Luke","pool":"Big Ten","slot":"Big Ten","team":"Illinois"},{"n":66,"owner":"Wilson","pool":"Non-P4","slot":"Non-P4","team":"Boise State"},{"n":67,"owner":"Chris","pool":"Non-P4","slot":"Non-P4","team":"Tulane"},{"n":68,"owner":"Marshall","pool":"SEC","slot":"SEC","team":"Missouri"},{"n":69,"owner":"Ian","pool":"Big 12","slot":"Big 12","team":"UCF"},{"n":70,"owner":"Pearse","pool":"Big 12","slot":"Big 12","team":"Arizona State"},{"n":71,"owner":"Pearse","pool":"Non-P4","slot":"Non-P4","team":"Navy"},{"n":72,"owner":"Ian","pool":"Big Ten","slot":"Big Ten","team":"UCLA"},{"n":73,"owner":"Marshall","pool":"ACC","slot":"ACC","team":"Florida State"},{"n":74,"owner":"Chris","pool":"Big 12","slot":"Big 12","team":"Oklahoma State"},{"n":75,"owner":"Wilson","pool":"NFL","slot":"NFL #3","team":"Raiders"},{"n":76,"owner":"Luke","pool":"Non-P4","slot":"Non-P4","team":"Army"},{"n":77,"owner":"Will","pool":"NFL","slot":"NFL #3","team":"Jets"},{"n":78,"owner":"Jonah","pool":"Non-P4","slot":"Non-P4","team":"Memphis"},{"n":79,"owner":"Ryland","pool":"SEC","slot":"SEC","team":"South Carolina"},{"n":80,"owner":"Chuck","pool":"Non-P4","slot":"Non-P4","team":"Liberty"}],"slots":{"ACC":1,"Big 12":1,"Big Ten":1,"NFL":3,"Non-P4":1,"SEC":1},"status":"complete","year":2026,"sport":"football"}'::jsonb, '2026-08-24T00:00:00Z')
on conflict (id) do nothing;
insert into public.league_invites (league_id, code)
values ('the-portfolio-2026', substr(md5(random()::text || clock_timestamp()::text), 1, 10))
on conflict (league_id) do nothing;
