-- =====================================================================
-- My Vault — complete Supabase schema
-- Run this whole file once in: Supabase Dashboard -> SQL Editor -> New query
-- It is idempotent: safe to re-run after edits, and re-running it is also
-- how an existing vault is upgraded (see "Upgrading" in README.md). Existing
-- rows, objects, quotas and the bucket's size limit are preserved.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Extensions
-- ---------------------------------------------------------------------
-- pg_trgm powers fast substring search ("inv" matches "invoice-2024.pdf")
create extension if not exists pg_trgm with schema extensions;

-- ---------------------------------------------------------------------
-- 1. Sessions: automatic sign-out 5 minutes after sign-in
-- ---------------------------------------------------------------------
-- Every session ends 5 minutes after the password sign-in, whatever the
-- user is doing: activity does not extend it. The browser signs out at that
-- moment, but a timer in the page is not a security boundary, so every
-- table and storage policy below also requires session_is_active(), which
-- counts from the session's own sign-in time in auth.sessions. A session
-- older than 5 minutes, or one that was signed out (its auth.sessions row is
-- gone), can no longer read or change anything, even with an access token
-- that has not expired yet. The user has to sign in again.
create table if not exists public.session_activity (
  session_id uuid primary key,
  user_id    uuid not null references auth.users (id) on delete cascade,
  started_at timestamptz not null default now()
);
-- Upgrade from the 9-minute inactivity version, where this column held the
-- last activity. It now holds when the app first saw the session.
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'session_activity' and column_name = 'last_seen_at') then
    alter table public.session_activity rename column last_seen_at to started_at;
  end if;
end;
$$;
create index if not exists session_activity_user_idx on public.session_activity (user_id);

-- No policies and no grants: only the security definer functions below
-- read or write this table.
alter table public.session_activity enable row level security;
revoke all on public.session_activity from anon, authenticated;

-- The session limit. Keep in sync with SESSION_MAX_AGE_MS in src/lib/session.ts.
create or replace function public.session_max_age()
returns interval
language sql
immutable
set search_path = ''
as $$
  select interval '5 minutes';
$$;

-- When the session in the caller's verified JWT signed in. Normally read
-- from auth.sessions (Supabase Auth's own record, which also proves the
-- session has not been signed out). If auth.sessions is unreadable, falls
-- back to when the app first reported the session, so a platform permission
-- change can't lock everyone out.
create or replace function public.session_state()
returns text
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  uid     uuid := auth.uid();
  raw_sid text := auth.jwt() ->> 'session_id';
  sid     uuid;
  started timestamptz;
begin
  if uid is null or raw_sid is null or raw_sid !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    return 'revoked';
  end if;
  sid := raw_sid::uuid;

  if to_regclass('auth.sessions') is not null and has_table_privilege('auth.sessions', 'select') then
    -- Supabase Auth deletes the row on sign-out (this device, another
    -- device, or "sign out everywhere").
    select s.created_at into started from auth.sessions s where s.id = sid and s.user_id = uid;
    if not found then
      return 'revoked';
    end if;
  else
    select a.started_at into started from public.session_activity a where a.session_id = sid and a.user_id = uid;
    if not found then
      return 'active';
    end if;
  end if;

  return case when started > now() - public.session_max_age() then 'active' else 'expired' end;
end;
$$;

create or replace function public.session_is_active()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.session_state() = 'active';
$$;

-- Called by the app on sign-in, page load and when a tab is reopened.
-- Raises SESSION_EXPIRED / SESSION_REVOKED instead of extending a session:
-- calling it never adds time.
create or replace function public.touch_session()
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  state text := public.session_state();
begin
  if state = 'revoked' then
    raise exception 'SESSION_REVOKED' using hint = 'This session has been signed out. Sign in again.';
  elsif state = 'expired' then
    raise exception 'SESSION_EXPIRED' using hint = 'Sessions end 5 minutes after sign-in. Sign in again.';
  end if;

  -- Remember the first time this session was seen (used only if
  -- auth.sessions can't be read). Never moved forward.
  insert into public.session_activity (session_id, user_id, started_at)
  values ((auth.jwt() ->> 'session_id')::uuid, auth.uid(), now())
  on conflict (session_id) do nothing;

  -- With auth.sessions readable these rows decide nothing, so drop old ones.
  if to_regclass('auth.sessions') is not null and has_table_privilege('auth.sessions', 'select') then
    delete from public.session_activity a
    where a.user_id = auth.uid() and a.started_at < now() - interval '1 day';
  end if;
end;
$$;

revoke all on function public.session_max_age() from public, anon, authenticated;
revoke all on function public.session_state() from public, anon, authenticated;
revoke all on function public.session_is_active() from public, anon;
revoke all on function public.touch_session() from public, anon;
grant execute on function public.session_is_active() to authenticated;
grant execute on function public.touch_session() to authenticated;

-- Optional (recommended): Supabase Auth also refuses to issue or refresh a
-- token for a session older than 5 minutes, so its refresh token is useless
-- even if the tab was closed. Enable in Authentication -> Hooks ->
-- Customize Access Token (JWT) Claims -> Postgres ->
-- public.idle_timeout_access_token_hook. (The name is kept from the
-- 9-minute version so an already-enabled hook keeps working.) A new sign-in
-- is never affected: its session was created a moment ago.
create or replace function public.idle_timeout_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  raw_sid text := event -> 'claims' ->> 'session_id';
  started timestamptz;
begin
  if raw_sid ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    if to_regclass('auth.sessions') is not null and has_table_privilege('auth.sessions', 'select') then
      select s.created_at into started from auth.sessions s where s.id = raw_sid::uuid;
    end if;
    if started is null then
      select a.started_at into started from public.session_activity a where a.session_id = raw_sid::uuid;
    end if;
    if started is not null and started <= now() - public.session_max_age() then
      return jsonb_build_object('error', jsonb_build_object(
        'http_code', 401,
        'message', 'Your session has expired. Please log in again to continue.'));
    end if;
  end if;
  return event;
end;
$$;

revoke all on function public.idle_timeout_access_token_hook(jsonb) from public, anon, authenticated;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then
    grant execute on function public.idle_timeout_access_token_hook(jsonb) to supabase_auth_admin;
  end if;
end;
$$;

-- Replaced by session_max_age() (9-minute inactivity version).
drop function if exists public.session_idle_limit();

-- ---------------------------------------------------------------------
-- 2. Profiles (one row per auth user)
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id                  uuid primary key references auth.users (id) on delete cascade,
  full_name           text not null default '' check (char_length(full_name) <= 120),
  avatar_path         text,
  preferences         jsonb not null default '{}'::jsonb,
  -- Per-user storage quota. Default 1 GB (the Supabase Free plan total).
  -- Raise it with:  update public.profiles set storage_quota_bytes = 100 * 1024^3;
  storage_quota_bytes bigint not null default 1073741824 check (storage_quota_bytes >= 0),
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Users may read and edit only their own profile...
drop policy if exists "profiles: select own" on public.profiles;
create policy "profiles: select own" on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) and (select public.session_is_active()));

drop policy if exists "profiles: update own" on public.profiles;
create policy "profiles: update own" on public.profiles
  for update to authenticated
  using (id = (select auth.uid()) and (select public.session_is_active()))
  with check (
    id = (select auth.uid())
    and (select public.session_is_active())
    and (avatar_path is null or split_part(avatar_path, '/', 1) = (select auth.uid())::text)
  );

-- ...and only these columns. A user can never raise their own quota.
revoke all on public.profiles from anon;
revoke insert, update, delete on public.profiles from authenticated;
grant select on public.profiles to authenticated;
grant update (full_name, avatar_path, preferences) on public.profiles to authenticated;

-- Create a profile automatically whenever an auth user is created.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Backfill profiles for users created before this script ran.
insert into public.profiles (id)
select id from auth.users
on conflict (id) do nothing;

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists profiles_touch on public.profiles;
create trigger profiles_touch
  before update on public.profiles
  for each row execute function public.touch_updated_at();

-- ---------------------------------------------------------------------
-- 3. Files (metadata for every stored object)
-- ---------------------------------------------------------------------
create table if not exists public.files (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null default auth.uid() references auth.users (id) on delete cascade,
  original_name    text not null check (char_length(original_name) between 1 and 255),
  display_name     text not null check (char_length(display_name) between 1 and 255),
  storage_path     text not null unique,
  thumbnail_path   text,
  mime_type        text not null default 'application/octet-stream',
  extension        text not null default '',
  -- Allowed values are set by files_category_check below.
  category         text not null,
  size_bytes       bigint not null check (size_bytes >= 0),
  width            integer,
  height           integer,
  page_count       integer,
  duration_seconds integer check (duration_seconds >= 0),
  is_favorite      boolean not null default false,
  tags             text[] not null default '{}',
  description      text not null default '' check (char_length(description) <= 2000),
  search_text      text not null default '',
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  last_accessed_at timestamptz,
  deleted_at       timestamptz,
  -- Executables are never accepted (mirrored in the storage policy below).
  constraint files_extension_not_blocked check (
    extension not in ('exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1', 'vbs', 'jar', 'app', 'dll', 'sh')
  )
);

-- Upgrades for vaults created by an earlier version of this file.
-- `create table if not exists` leaves an existing table alone, so new
-- columns and changed checks are applied here instead.
alter table public.files add column if not exists duration_seconds integer check (duration_seconds >= 0);

-- Categories and their storage folders. Dropped and re-created on every run
-- so adding a category only needs this block edited (plus
-- src/lib/categories.ts). Existing rows are re-validated and always pass,
-- because categories are only ever added.
alter table public.files drop constraint if exists files_category_check;
alter table public.files add constraint files_category_check
  check (category in ('image', 'screenshot', 'pdf', 'document', 'video', 'other'));

-- Object key layout: <user-id>/<category-folder>/<file-uuid>.<ext>
alter table public.files drop constraint if exists files_storage_path_format;
alter table public.files add constraint files_storage_path_format check (
  storage_path ~ '^[0-9a-f-]{36}/(images|screenshots|pdfs|documents|videos|other)/[^/]+$'
);

-- Indexes tuned for the app's queries (always scoped to user_id).
create index if not exists files_user_active_created_idx
  on public.files (user_id, created_at desc) where deleted_at is null;
create index if not exists files_user_category_created_idx
  on public.files (user_id, category, created_at desc) where deleted_at is null;
create index if not exists files_user_favorite_idx
  on public.files (user_id, created_at desc) where is_favorite and deleted_at is null;
create index if not exists files_user_accessed_idx
  on public.files (user_id, last_accessed_at desc) where last_accessed_at is not null and deleted_at is null;
create index if not exists files_user_trash_idx
  on public.files (user_id, deleted_at desc) where deleted_at is not null;
create index if not exists files_user_size_idx
  on public.files (user_id, size_bytes desc);
create index if not exists files_user_name_idx
  on public.files (user_id, lower(display_name));
create index if not exists files_search_trgm_idx
  on public.files using gin (search_text extensions.gin_trgm_ops);
create index if not exists files_tags_idx
  on public.files using gin (tags);

alter table public.files enable row level security;

drop policy if exists "files: select own" on public.files;
create policy "files: select own" on public.files
  for select to authenticated
  using (user_id = (select auth.uid()) and (select public.session_is_active()));

drop policy if exists "files: insert own" on public.files;
create policy "files: insert own" on public.files
  for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and (select public.session_is_active())
    and split_part(storage_path, '/', 1) = (select auth.uid())::text
    and (thumbnail_path is null or split_part(thumbnail_path, '/', 1) = (select auth.uid())::text)
  );

drop policy if exists "files: update own" on public.files;
create policy "files: update own" on public.files
  for update to authenticated
  using (user_id = (select auth.uid()) and (select public.session_is_active()))
  with check (
    user_id = (select auth.uid())
    and (select public.session_is_active())
    and (thumbnail_path is null or split_part(thumbnail_path, '/', 1) = (select auth.uid())::text)
  );

drop policy if exists "files: delete own" on public.files;
create policy "files: delete own" on public.files
  for delete to authenticated
  using (user_id = (select auth.uid()) and (select public.session_is_active()));

revoke all on public.files from anon;
grant select, insert, update, delete on public.files to authenticated;

-- Normalise input, protect immutable columns, maintain search_text.
create or replace function public.files_before_write()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'UPDATE' then
    if new.user_id      is distinct from old.user_id
    or new.storage_path is distinct from old.storage_path
    or new.original_name is distinct from old.original_name
    or new.size_bytes   is distinct from old.size_bytes
    or new.mime_type    is distinct from old.mime_type
    or new.extension    is distinct from old.extension
    or new.created_at   is distinct from old.created_at then
      raise exception 'IMMUTABLE_COLUMN' using hint = 'Storage path, size, type and owner cannot be changed.';
    end if;
    -- Only images and screenshots may be moved between each other.
    if new.category is distinct from old.category
       and not (old.category in ('image', 'screenshot') and new.category in ('image', 'screenshot')) then
      raise exception 'INVALID_CATEGORY_CHANGE';
    end if;
    new.updated_at := now();
  end if;

  new.display_name := btrim(new.display_name);
  if new.display_name = '' then
    raise exception 'EMPTY_NAME' using hint = 'File name cannot be empty.';
  end if;
  new.extension := lower(new.extension);
  new.description := btrim(coalesce(new.description, ''));

  -- Tags: lower-case, trimmed, unique, max 30 tags of max 40 chars.
  select coalesce(array_agg(t order by t), '{}')
    into new.tags
    from (
      select distinct left(lower(btrim(x)), 40) as t
      from unnest(coalesce(new.tags, '{}')) as x
      where btrim(x) <> ''
    ) s;
  if cardinality(new.tags) > 30 then
    raise exception 'TOO_MANY_TAGS' using hint = 'A file can have at most 30 tags.';
  end if;

  new.search_text := lower(concat_ws(' ',
    new.display_name, new.original_name, new.extension, new.category,
    array_to_string(new.tags, ' '), new.description));
  return new;
end;
$$;

drop trigger if exists files_before_write on public.files;
create trigger files_before_write
  before insert or update on public.files
  for each row execute function public.files_before_write();

-- Enforce the per-user storage quota on insert.
create or replace function public.files_enforce_quota()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  used  bigint;
  quota bigint;
begin
  select coalesce(sum(size_bytes), 0) into used from public.files where user_id = new.user_id;
  select storage_quota_bytes into quota from public.profiles where id = new.user_id;
  if quota is not null and used + new.size_bytes > quota then
    raise exception 'STORAGE_LIMIT_EXCEEDED'
      using hint = 'Your vault storage quota is full. Empty the trash or raise the quota.';
  end if;
  return new;
end;
$$;

drop trigger if exists files_enforce_quota on public.files;
create trigger files_enforce_quota
  before insert on public.files
  for each row execute function public.files_enforce_quota();

-- Aggregate stats in one round-trip (never fetch all rows to count them).
create or replace function public.vault_stats()
returns json
language sql
stable
security invoker
set search_path = ''
as $$
  select json_build_object(
    'total_files', count(*) filter (where f.deleted_at is null),
    'images',      count(*) filter (where f.deleted_at is null and f.category = 'image'),
    'screenshots', count(*) filter (where f.deleted_at is null and f.category = 'screenshot'),
    'pdfs',        count(*) filter (where f.deleted_at is null and f.category = 'pdf'),
    'documents',   count(*) filter (where f.deleted_at is null and f.category = 'document'),
    'videos',      count(*) filter (where f.deleted_at is null and f.category = 'video'),
    'other',       count(*) filter (where f.deleted_at is null and f.category = 'other'),
    'favorites',   count(*) filter (where f.deleted_at is null and f.is_favorite),
    'trash',       count(*) filter (where f.deleted_at is not null),
    'recent_7d',   count(*) filter (where f.deleted_at is null and f.created_at > now() - interval '7 days'),
    'total_bytes', coalesce(sum(f.size_bytes), 0),
    'trash_bytes', coalesce(sum(f.size_bytes) filter (where f.deleted_at is not null), 0),
    'bytes_by_category', coalesce((
      select json_object_agg(s.category, s.bytes)
      from (
        select category, sum(size_bytes) as bytes
        from public.files
        where user_id = (select auth.uid())
        group by category
      ) s
    ), '{}'::json),
    'quota_bytes', (select p.storage_quota_bytes from public.profiles p where p.id = (select auth.uid()))
  )
  from public.files f
  where f.user_id = (select auth.uid());
$$;

revoke all on function public.vault_stats() from public, anon;
grant execute on function public.vault_stats() to authenticated;

-- ---------------------------------------------------------------------
-- 4. Storage: private bucket + per-user folder policies
-- ---------------------------------------------------------------------
-- file_size_limit: 50 MB (Free plan maximum) when the bucket is first
-- created. Raise it on paid plans (Storage -> vault-files -> Edit bucket) and
-- set VITE_MAX_UPLOAD_MB to match. Re-running this file keeps a limit you
-- raised; it only forces the bucket back to private.
insert into storage.buckets (id, name, public, file_size_limit)
values ('vault-files', 'vault-files', false, 52428800)
on conflict (id) do update
  set public = false;

-- Objects live at <auth.uid()>/<folder>/<uuid>.<ext>. The first folder
-- segment must equal the caller's verified JWT user id; the client never
-- decides who owns a file.
drop policy if exists "vault: select own objects" on storage.objects;
create policy "vault: select own objects" on storage.objects
  for select to authenticated
  using (
    bucket_id = 'vault-files'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select public.session_is_active())
  );

drop policy if exists "vault: insert own objects" on storage.objects;
create policy "vault: insert own objects" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'vault-files'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select public.session_is_active())
    and (storage.foldername(name))[2] in ('images', 'screenshots', 'pdfs', 'documents', 'videos', 'other', 'thumbs', 'avatar')
    and lower(storage.extension(name)) not in ('exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1', 'vbs', 'jar', 'app', 'dll', 'sh')
  );

-- Updates (overwrite / move) must land somewhere an insert could, so a
-- rename can't be used to sneak in a blocked extension or unknown folder.
drop policy if exists "vault: update own objects" on storage.objects;
create policy "vault: update own objects" on storage.objects
  for update to authenticated
  using (
    bucket_id = 'vault-files'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select public.session_is_active())
  )
  with check (
    bucket_id = 'vault-files'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select public.session_is_active())
    and (storage.foldername(name))[2] in ('images', 'screenshots', 'pdfs', 'documents', 'videos', 'other', 'thumbs', 'avatar')
    and lower(storage.extension(name)) not in ('exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1', 'vbs', 'jar', 'app', 'dll', 'sh')
  );

drop policy if exists "vault: delete own objects" on storage.objects;
create policy "vault: delete own objects" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'vault-files'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select public.session_is_active())
  );

-- ---------------------------------------------------------------------
-- 5. Two-step verification is mandatory
-- ---------------------------------------------------------------------
-- A password alone only yields an aal1 session. These RESTRICTIVE policies
-- are AND-ed with every policy above, so nothing in the vault can be read or
-- changed until the authenticator-app code is verified (aal2). This holds
-- even for someone calling the API directly with a stolen password.
drop policy if exists "profiles: require 2fa" on public.profiles;
create policy "profiles: require 2fa" on public.profiles
  as restrictive for all to authenticated
  using ((select auth.jwt() ->> 'aal') = 'aal2')
  with check ((select auth.jwt() ->> 'aal') = 'aal2');

drop policy if exists "files: require 2fa" on public.files;
create policy "files: require 2fa" on public.files
  as restrictive for all to authenticated
  using ((select auth.jwt() ->> 'aal') = 'aal2')
  with check ((select auth.jwt() ->> 'aal') = 'aal2');

drop policy if exists "vault: require 2fa" on storage.objects;
create policy "vault: require 2fa" on storage.objects
  as restrictive for all to authenticated
  using (bucket_id <> 'vault-files' or (select auth.jwt() ->> 'aal') = 'aal2')
  with check (bucket_id <> 'vault-files' or (select auth.jwt() ->> 'aal') = 'aal2');
