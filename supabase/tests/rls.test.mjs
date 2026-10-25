// Security tests for supabase/schema.sql, run against PGlite (Postgres in WASM)
// with minimal stand-ins for Supabase auth/storage. Run: npm run test:db
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import fs from 'node:fs';

const schema = fs.readFileSync(process.argv[2] ?? new URL('../schema.sql', import.meta.url), 'utf8');
const schemaV1 = fs.readFileSync(new URL('./fixtures/schema-v1.sql', import.meta.url), 'utf8');
const schemaV3Idle = fs.readFileSync(new URL('./fixtures/schema-v3-idle.sql', import.meta.url), 'utf8');

// ---- Minimal Supabase platform stubs (mirrors Supabase's definitions) ----
const PLATFORM = `
create schema auth; create schema storage; create schema extensions;
create role anon nologin; create role authenticated nologin; create role supabase_auth_admin nologin;
grant usage on schema public, auth, storage, extensions to anon, authenticated;
alter default privileges in schema public grant all on tables to anon, authenticated;
alter default privileges in schema public grant all on functions to anon, authenticated;
create table auth.users (id uuid primary key, email text, raw_user_meta_data jsonb default '{}');
create table auth.sessions (id uuid primary key, user_id uuid not null, created_at timestamptz not null default now());
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claim', true), ''), nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
grant execute on function auth.uid(), auth.jwt() to anon, authenticated;
create table storage.buckets (id text primary key, name text, public boolean, file_size_limit bigint, allowed_mime_types text[]);
create table storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text, name text);
alter table storage.objects enable row level security;
grant all on storage.objects to anon, authenticated;
create function storage.foldername(name text) returns text[] language plpgsql immutable as $$
declare _parts text[]; begin _parts := string_to_array(name, '/'); return _parts[1 : array_length(_parts,1) - 1]; end $$;
create function storage.extension(name text) returns text language plpgsql immutable as $$
declare _parts text[]; _filename text; begin _parts := string_to_array(name, '/'); _filename := _parts[array_length(_parts,1)]; return reverse(split_part(reverse(_filename), '.', 1)); end $$;
`;
async function freshDb() {
  const d = new PGlite({ extensions: { pg_trgm } });
  await d.exec(PLATFORM);
  return d;
}
let db = await freshDb();

await db.exec(schema);
await db.exec(schema); // idempotency
console.log('schema applied twice OK');

const A = '11111111-1111-1111-1111-111111111111';
const B = '22222222-2222-2222-2222-222222222222';
// Each user's signed-in session (the session_id claim in their JWT).
const SESSION = { [A]: 'a5e55100-0000-4000-8000-000000000001', [B]: 'b5e55100-0000-4000-8000-000000000001' };
const addSessions = (d) => d.exec(`insert into auth.sessions (id, user_id) values ('${SESSION[A]}','${A}'), ('${SESSION[B]}','${B}')`);
await db.exec(`insert into auth.users (id, email, raw_user_meta_data) values ('${A}','a@x.com','{"full_name":"Alice"}'), ('${B}','b@x.com','{}')`);
await addSessions(db);

let pass = 0;
let fail = 0;
// aal2 = signed in with password + authenticator code; aal1 = password only.
// sid is the session_id claim (the Supabase Auth session).
const as = async (uid, role = 'authenticated', aal = 'aal2', sid = uid ? SESSION[uid] : null) => {
  const claims = uid ? JSON.stringify({ sub: uid, role, aal, ...(sid ? { session_id: sid } : {}) }) : '';
  await db.exec(
    `reset role; select set_config('request.jwt.claim.sub', '${uid ?? ''}', false), set_config('request.jwt.claims', '${claims}', false); set role ${role};`,
  );
};
async function expectOk(name, sql, check) {
  try {
    const r = await db.query(sql);
    if (check && !check(r)) throw new Error('check failed: ' + JSON.stringify(r.rows));
    console.log('PASS', name);
    pass++;
    return r;
  } catch (e) {
    console.log('FAIL', name, '-', e.message);
    fail++;
  }
}
async function expectErr(name, sql, match) {
  try {
    const r = await db.query(sql);
    console.log('FAIL', name, '- no error, rows:', r.rows.length);
    fail++;
  } catch (e) {
    if (match && !match.test(e.message)) {
      console.log('FAIL', name, '- wrong error:', e.message);
      fail++;
    } else {
      console.log('PASS', name, '(' + e.message.slice(0, 70) + ')');
      pass++;
    }
  }
}

await expectOk('profiles created by trigger', `select count(*)::int n from public.profiles`, (r) => r.rows[0].n === 2);
await expectOk('profile name from metadata', `select full_name from public.profiles where id='${A}'`, (r) => r.rows[0].full_name === 'Alice');

await as(A);
await expectOk(
  'A inserts own file',
  `insert into public.files (id, user_id, original_name, display_name, storage_path, mime_type, extension, category, size_bytes, tags, description)
   values ('aaaaaaaa-0000-0000-0000-000000000001', '${A}', 'Invoice 2024.PDF', '  Invoice 2024  ', '${A}/pdfs/aaaaaaaa-0000-0000-0000-000000000001.pdf',
   'application/pdf', 'PDF', 'pdf', 1000, array['  Receipts','receipts','Tax '], 'Q1 paperwork')`,
);
await expectOk('name trimmed, tags normalised, ext lowercased, search_text built', `select display_name, tags, extension, search_text from public.files`, (r) =>
  r.rows[0].display_name === 'Invoice 2024' &&
  JSON.stringify(r.rows[0].tags) === '["receipts","tax"]' &&
  r.rows[0].extension === 'pdf' &&
  r.rows[0].search_text.includes('q1 paperwork'),
);
await expectOk('substring AND search via ilike', `select count(*)::int n from public.files where search_text ilike '%voic%' and search_text ilike '%rece%'`, (r) => r.rows[0].n === 1);
await expectErr('A cannot insert into B folder', `insert into public.files (user_id, original_name, display_name, storage_path, category, size_bytes) values ('${A}','x','x','${B}/pdfs/x.pdf','pdf',1)`, /row-level security/);
await expectErr('A cannot insert row owned by B', `insert into public.files (user_id, original_name, display_name, storage_path, category, size_bytes) values ('${B}','x','x','${B}/pdfs/y.pdf','pdf',1)`, /row-level security/);
await expectErr('A cannot point thumbnail at B', `insert into public.files (original_name, display_name, storage_path, thumbnail_path, category, size_bytes) values ('x','x','${A}/pdfs/t.pdf','${B}/thumbs/t.webp','pdf',1)`, /row-level security/);
await expectErr('bad path format rejected', `insert into public.files (original_name, display_name, storage_path, category, size_bytes) values ('x','x','${A}/secret/x.pdf','pdf',1)`, /files_storage_path_format/);
await expectErr('blocked extension rejected', `insert into public.files (original_name, display_name, storage_path, extension, category, size_bytes) values ('x.exe','x','${A}/other/x.exe','exe','other',1)`, /files_extension_not_blocked/);
await expectErr('quota enforced', `insert into public.files (original_name, display_name, storage_path, category, size_bytes) values ('big','big','${A}/other/big.bin','other', 2147483648)`, /STORAGE_LIMIT_EXCEEDED/);
await expectErr('storage_path immutable', `update public.files set storage_path='${A}/pdfs/zzz.pdf'`, /IMMUTABLE_COLUMN/);
await expectErr('size immutable', `update public.files set size_bytes=1`, /IMMUTABLE_COLUMN/);
await expectErr('pdf -> image category change blocked', `update public.files set category='image'`, /INVALID_CATEGORY_CHANGE/);
await expectErr('empty name blocked', `update public.files set display_name='   '`, /EMPTY_NAME/);
await expectOk('A can rename / favorite / trash', `update public.files set display_name='Renamed', is_favorite=true, deleted_at=now() returning id`, (r) => r.rows.length === 1);
await expectErr('A cannot raise own quota', `update public.profiles set storage_quota_bytes = 999999999999 where id='${A}'`, /permission denied/);
await expectOk('A can update own name + prefs', `update public.profiles set full_name='Alice B', preferences='{"view":"list"}' where id='${A}' returning id`, (r) => r.rows.length === 1);
await expectErr('A avatar_path must be in own folder', `update public.profiles set avatar_path='${B}/avatar/x.webp' where id='${A}'`, /row-level security/);
await expectOk('vault_stats for A', `select public.vault_stats() s`, (r) => {
  const s = r.rows[0].s;
  return s.trash === 1 && s.total_bytes === 1000 && s.quota_bytes === 1073741824 && s.bytes_by_category.pdf === 1000;
});

await as(B);
await expectOk('B sees none of A files', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await expectOk('B update of A file affects 0 rows', `update public.files set display_name='pwned' returning id`, (r) => r.rows.length === 0);
await expectOk('B delete of A file affects 0 rows', `delete from public.files returning id`, (r) => r.rows.length === 0);
await expectOk('B sees only own profile', `select count(*)::int n from public.profiles`, (r) => r.rows[0].n === 1);
await expectOk('B stats are empty', `select public.vault_stats() s`, (r) => r.rows[0].s.total_files === 0 && r.rows[0].s.total_bytes === 0);

await as(A);
await expectOk('A uploads object to own folder', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/images/a.jpg') returning id`);
await expectOk('A uploads thumbnail', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/thumbs/a.webp') returning id`);
await expectErr('A cannot upload into B folder', `insert into storage.objects (bucket_id, name) values ('vault-files', '${B}/images/evil.jpg')`, /row-level security/);
await expectErr('A cannot upload to unknown subfolder', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/random/x.jpg')`, /row-level security/);
await expectErr('A cannot upload .exe', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/other/x.exe')`, /row-level security/);
await expectErr('A cannot upload to another bucket', `insert into storage.objects (bucket_id, name) values ('other-bucket', '${A}/images/x.jpg')`, /row-level security/);
await as(B);
await expectOk('B cannot see A objects', `select count(*)::int n from storage.objects`, (r) => r.rows[0].n === 0);
await expectOk('B cannot delete A objects', `delete from storage.objects returning id`, (r) => r.rows.length === 0);

// ---- Videos ----
const V = 'aaaaaaaa-0000-0000-0000-00000000000a';
await as(A);
await expectOk(
  'A inserts a video (MOV) with duration',
  `insert into public.files (id, original_name, display_name, storage_path, mime_type, extension, category, size_bytes, width, height, duration_seconds)
   values ('${V}', 'IMG_0042.MOV', 'IMG_0042', '${A}/videos/${V}.mov', 'video/quicktime', 'mov', 'video', 5000, 1920, 1080, 42) returning id`,
  (r) => r.rows.length === 1,
);
await expectErr('video must live in videos/ or another known folder', `insert into public.files (original_name, display_name, storage_path, category, size_bytes) values ('m.mp4','m','${A}/movies/m.mp4','video',1)`, /files_storage_path_format/);
await expectErr('unknown category rejected', `insert into public.files (original_name, display_name, storage_path, category, size_bytes) values ('a.mp3','a','${A}/other/a.mp3','audio',1)`, /files_category_check/);
await expectErr('negative duration rejected', `insert into public.files (original_name, display_name, storage_path, category, size_bytes, duration_seconds) values ('n.mp4','n','${A}/videos/n.mp4','video',1,-5)`, /check constraint/);
await expectErr('video -> image category change blocked', `update public.files set category='image' where id='${V}'`, /INVALID_CATEGORY_CHANGE/);
await expectOk('vault_stats counts videos', `select public.vault_stats() s`, (r) => r.rows[0].s.videos === 1 && r.rows[0].s.bytes_by_category.video === 5000);
await expectOk('A uploads video object', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/videos/${V}.mov') returning id`);
await expectErr('A cannot upload video into B folder', `insert into storage.objects (bucket_id, name) values ('vault-files', '${B}/videos/x.mp4')`, /row-level security/);
await expectErr('A cannot rename own object to .exe', `update storage.objects set name='${A}/videos/evil.exe' where name='${A}/videos/${V}.mov'`, /row-level security/);
await expectErr('A cannot move own object into B folder', `update storage.objects set name='${B}/videos/${V}.mov' where name='${A}/videos/${V}.mov'`, /row-level security/);
await expectErr('A cannot move own object to unknown folder', `update storage.objects set name='${A}/secret/${V}.mov' where name='${A}/videos/${V}.mov'`, /row-level security/);
await expectOk('A can overwrite own object in place', `update storage.objects set name=name where name='${A}/videos/${V}.mov' returning id`, (r) => r.rows.length === 1);

await as(B);
await expectOk('B cannot list A video (row)', `select count(*)::int n from public.files where category='video'`, (r) => r.rows[0].n === 0);
await expectOk('B cannot read A video object even with the exact path', `select count(*)::int n from storage.objects where name='${A}/videos/${V}.mov'`, (r) => r.rows[0].n === 0);
await expectOk('B cannot overwrite A video object', `update storage.objects set name='${B}/videos/stolen.mov' where name='${A}/videos/${V}.mov' returning id`, (r) => r.rows.length === 0);
await expectOk('B cannot delete A video object', `delete from storage.objects where name='${A}/videos/${V}.mov' returning id`, (r) => r.rows.length === 0);
await expectOk('B stats show no videos', `select public.vault_stats() s`, (r) => r.rows[0].s.videos === 0);

// ---- Two-step verification: a password-only (aal1) session gets nothing ----
await as(A, 'authenticated', 'aal1');
await expectOk('aal1 cannot list own files', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await expectOk('aal1 cannot read own profile', `select count(*)::int n from public.profiles`, (r) => r.rows[0].n === 0);
await expectOk('aal1 cannot see own storage objects', `select count(*)::int n from storage.objects where bucket_id='vault-files'`, (r) => r.rows[0].n === 0);
await expectOk('aal1 stats are empty', `select public.vault_stats() s`, (r) => r.rows[0].s.total_files === 0 && r.rows[0].s.quota_bytes === null);
await expectErr('aal1 cannot insert a file row', `insert into public.files (original_name, display_name, storage_path, category, size_bytes) values ('x','x','${A}/pdfs/aal1.pdf','pdf',1)`, /row-level security/);
await expectErr('aal1 cannot upload an object', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/images/aal1.jpg')`, /row-level security/);
await expectOk('aal1 cannot rename own files', `update public.files set display_name='pwned' returning id`, (r) => r.rows.length === 0);
await expectOk('aal1 cannot delete own files', `delete from public.files returning id`, (r) => r.rows.length === 0);
await expectOk('aal1 cannot delete own objects', `delete from storage.objects returning id`, (r) => r.rows.length === 0);
await expectOk('aal1 cannot change own profile', `update public.profiles set full_name='pwned' returning id`, (r) => r.rows.length === 0);
await as(A);
await expectOk('aal2 still sees own files', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 2);
await expectOk('aal2 still sees own objects', `select count(*)::int n from storage.objects`, (r) => r.rows[0].n === 3);

await as(null, 'anon');
await expectOk('anon cannot read A video object even with the exact path', `select count(*)::int n from storage.objects where name='${A}/videos/${V}.mov'`, (r) => r.rows[0].n === 0);
await expectOk('anon cannot overwrite A objects', `update storage.objects set name='x' returning id`, (r) => r.rows.length === 0);
await expectOk('anon cannot delete A objects', `delete from storage.objects returning id`, (r) => r.rows.length === 0);

await expectErr('anon cannot read files', `select * from public.files`, /permission denied/);
await expectErr('anon cannot read profiles', `select * from public.profiles`, /permission denied/);
await expectErr('anon cannot call vault_stats', `select public.vault_stats()`, /permission denied/);
await expectOk('anon sees no storage objects', `select count(*)::int n from storage.objects`, (r) => r.rows[0].n === 0);
await expectErr('anon cannot upload', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/images/anon.jpg')`, /row-level security/);

await db.exec('reset role');
await expectOk('bucket is private', `select public from storage.buckets where id='vault-files'`, (r) => r.rows[0].public === false);
await db.exec(`update storage.buckets set file_size_limit = 5368709120, public = true where id = 'vault-files'`);
await db.exec(schema);
await expectOk(
  're-running schema keeps a raised bucket size limit but forces private',
  `select public, file_size_limit from storage.buckets where id='vault-files'`,
  (r) => r.rows[0].public === false && Number(r.rows[0].file_size_limit) === 5368709120,
);

// ---- Session limit: 10 minutes after sign-in, activity does not extend it ----
// Separate sessions per scenario so A's main session stays active.
const S = {
  fresh: 'a5e55100-0000-4000-8000-0000000000a1',
  almost: 'a5e55100-0000-4000-8000-0000000000a2',
  old: 'a5e55100-0000-4000-8000-0000000000a3',
  revoked: 'a5e55100-0000-4000-8000-0000000000a4',
};
await db.exec('reset role');
await db.exec(`insert into auth.sessions (id, user_id, created_at) values
  ('${S.fresh}','${A}', now()), ('${S.almost}','${A}', now() - interval '9 minutes 50 seconds'),
  ('${S.old}','${A}', now() - interval '10 minutes 1 second'), ('${S.revoked}','${A}', now())`);

await as(A, 'authenticated', 'aal2', S.fresh);
await expectOk('session just signed in can read', `select count(*)::int n from public.files`, (r) => r.rows[0].n > 0);
await expectOk('touch_session accepts it', `select public.touch_session()`);
await expectOk('touch_session twice is fine', `select public.touch_session()`);
await db.exec('reset role');
await expectOk('first-seen time recorded once', `select count(*)::int n from public.session_activity where session_id='${S.fresh}'`, (r) => r.rows[0].n === 1);

await as(A, 'authenticated', 'aal2', S.almost);
await expectOk('session 9m50s after sign-in is still active', `select count(*)::int n from public.files`, (r) => r.rows[0].n > 0);
await expectOk('touching it adds no time', `select public.touch_session()`);
await db.exec(`reset role; update auth.sessions set created_at = now() - interval '10 minutes 1 second' where id='${S.almost}'`);
await as(A, 'authenticated', 'aal2', S.almost);
await expectOk('recent activity does not keep a 10-minute-old session alive', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await expectErr('touch_session refuses to extend it', `select public.touch_session()`, /SESSION_EXPIRED/);

await as(A, 'authenticated', 'aal2', S.old);
await expectOk('expired session reads no files', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await expectOk('expired session reads no profile', `select count(*)::int n from public.profiles`, (r) => r.rows[0].n === 0);
await expectOk('expired session gets empty stats', `select public.vault_stats() s`, (r) => r.rows[0].s.total_files === 0 && r.rows[0].s.quota_bytes === null);
await expectOk('expired session cannot update files', `update public.files set display_name='old' returning id`, (r) => r.rows.length === 0);
await expectOk('expired session cannot delete files', `delete from public.files returning id`, (r) => r.rows.length === 0);
await expectOk('expired session cannot update profile', `update public.profiles set full_name='old' returning id`, (r) => r.rows.length === 0);
await expectErr('expired session cannot insert files', `insert into public.files (original_name, display_name, storage_path, category, size_bytes) values ('i','i','${A}/pdfs/old.pdf','pdf',1)`, /row-level security/);
await expectOk('expired session sees no storage objects', `select count(*)::int n from storage.objects`, (r) => r.rows[0].n === 0);
await expectErr('expired session cannot upload', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/images/old.jpg')`, /row-level security/);
await expectOk('expired session cannot delete objects', `delete from storage.objects returning id`, (r) => r.rows.length === 0);
await expectErr('touch_session reports the expiry', `select public.touch_session()`, /SESSION_EXPIRED/);
await db.exec('reset role');
await expectOk('expired session is not recorded', `select count(*)::int n from public.session_activity where session_id='${S.old}'`, (r) => r.rows[0].n === 0);

await as(A, 'authenticated', 'aal2', S.revoked);
await expectOk('new session is active before its first touch', `select count(*)::int n from public.files`, (r) => r.rows[0].n > 0);
await db.exec(`reset role; delete from auth.sessions where id='${S.revoked}'`);
await as(A, 'authenticated', 'aal2', S.revoked);
await expectOk('signed-out session reads nothing with a still-valid JWT', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await expectErr('touch_session reports signed-out session', `select public.touch_session()`, /SESSION_REVOKED/);
await as(A, 'authenticated', 'aal2', null);
await expectOk('JWT without session_id reads nothing', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await as(B, 'authenticated', 'aal2', S.fresh);
await expectOk("another user's session id is not accepted", `select count(*)::int n from public.profiles`, (r) => r.rows[0].n === 0);

await as(B);
await expectOk('other users are unaffected by A expired sessions', `select count(*)::int n from public.profiles`, (r) => r.rows[0].n === 1);
await expectErr('session_activity is not directly readable', `select * from public.session_activity`, /permission denied/);
await expectErr('session_activity is not directly writable', `update public.session_activity set started_at = now()`, /permission denied/);
await expectErr('session_state is not callable by clients', `select public.session_state()`, /permission denied/);
await expectErr('clients cannot call the auth hook', `select public.idle_timeout_access_token_hook('{}'::jsonb)`, /permission denied/);
await as(null, 'anon');
await expectErr('anon cannot touch a session', `select public.touch_session()`, /permission denied/);

await db.exec('reset role');
const hook = (sid) => `select public.idle_timeout_access_token_hook('{"claims":{"sub":"${A}","session_id":"${sid}"}}'::jsonb) r`;
await expectOk('hook refuses a token for a session older than 10 minutes', hook(S.old), (r) => r.rows[0].r.error?.http_code === 401);
await expectOk('hook passes a fresh session through unchanged', hook(S.fresh), (r) => r.rows[0].r.claims?.session_id === S.fresh && !r.rows[0].r.error);
await expectOk('hook allows a brand-new session', hook('a5e55100-0000-4000-8000-0000000000ff'), (r) => !r.rows[0].r.error);
await expectOk('hook tolerates a missing session_id', `select public.idle_timeout_access_token_hook('{"claims":{}}'::jsonb) r`, (r) => !r.rows[0].r.error);
await db.exec('set role supabase_auth_admin');
await expectOk('supabase_auth_admin can run the hook', hook(S.fresh), (r) => !r.rows[0].r.error);
await db.exec('reset role');
await expectOk('old session_idle_limit() removed', `select to_regprocedure('public.session_idle_limit()') is null gone`, (r) => r.rows[0].gone === true);

// ---- Upgrade path: a vault created with the first schema ----
db = await freshDb();
await db.exec(schemaV1);
await db.exec(`insert into auth.users (id, email) values ('${A}','a@x.com')`);
await addSessions(db);
await db.exec(`update storage.buckets set file_size_limit = 1073741824 where id = 'vault-files'`);
await as(A);
await db.exec(
  `insert into public.files (id, original_name, display_name, storage_path, extension, category, size_bytes, tags)
   values ('aaaaaaaa-0000-0000-0000-000000000009', 'old.pdf', 'old', '${A}/pdfs/old.pdf', 'pdf', 'pdf', 10, array['keep'])`,
);
await expectErr('v1 schema rejects videos (sanity check)', `insert into public.files (original_name, display_name, storage_path, category, size_bytes) values ('v.mp4','v','${A}/videos/v.mp4','video',1)`, /check constraint/);
await db.exec('reset role');
await db.exec(schema);
await expectOk('upgrade keeps existing rows', `select tags from public.files where id='aaaaaaaa-0000-0000-0000-000000000009'`, (r) => r.rows[0]?.tags?.[0] === 'keep');
await expectOk('upgrade keeps the bucket size limit', `select file_size_limit from storage.buckets where id='vault-files'`, (r) => Number(r.rows[0].file_size_limit) === 1073741824);
await expectOk(
  'upgrade leaves exactly one category check',
  `select count(*)::int n from pg_constraint where conrelid = 'public.files'::regclass and contype = 'c' and pg_get_constraintdef(oid) like '%category%'`,
  (r) => r.rows[0].n === 1,
);
await as(A);
await expectOk(
  'upgraded vault accepts videos',
  `insert into public.files (original_name, display_name, storage_path, category, size_bytes, duration_seconds) values ('v.mp4','v','${A}/videos/v.mp4','video',1,3) returning id`,
  (r) => r.rows.length === 1,
);
await expectOk('upgraded storage policy accepts videos/', `insert into storage.objects (bucket_id, name) values ('vault-files', '${A}/videos/v.mp4') returning id`);
await expectOk('upgraded vault_stats reports videos', `select public.vault_stats() s`, (r) => r.rows[0].s.videos === 1 && r.rows[0].s.pdfs === 1);
await as(B);
await expectOk('upgraded vault still isolates users', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);

// ---- Upgrade path: the 9-minute inactivity version (what is live today) ----
db = await freshDb();
await db.exec(schemaV3Idle);
await db.exec(`insert into auth.users (id, email) values ('${A}','a@x.com'), ('${B}','b@x.com')`);
await addSessions(db);
const OLD_SID = 'a5e55100-0000-4000-8000-0000000000b1';
await db.exec(`insert into auth.sessions (id, user_id, created_at) values ('${OLD_SID}','${A}', now() - interval '20 minutes')`);
await as(A);
await db.exec(`insert into public.files (id, original_name, display_name, storage_path, extension, category, size_bytes) values ('aaaaaaaa-0000-0000-0000-0000000000c1', 'keep.pdf', 'keep', '${A}/pdfs/keep.pdf', 'pdf', 'pdf', 10)`);
await db.exec(`reset role; insert into public.session_activity (session_id, user_id, last_seen_at) values ('${OLD_SID}','${A}', now())`);
await as(A, 'authenticated', 'aal2', OLD_SID);
await expectOk('9-minute version: an active 20-minute-old session can read (sanity check)', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 1);
await db.exec('reset role');
await db.exec(schema);
await db.exec(schema);
await expectOk('upgrade renames last_seen_at to started_at and keeps rows', `select count(*)::int n from public.session_activity where session_id='${OLD_SID}' and started_at is not null`, (r) => r.rows[0].n === 1);
await expectOk('upgrade keeps files', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 1);
await as(A, 'authenticated', 'aal2', OLD_SID);
await expectOk('after upgrade a session older than 10 minutes is cut off despite recent activity', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await as(A);
await expectOk('after upgrade a fresh session works', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 1);
await expectOk('after upgrade touch_session works', `select public.touch_session()`);
await as(A, 'authenticated', 'aal1');
await expectOk('after upgrade two-step verification is still required', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);
await as(B);
await expectOk('after upgrade users stay isolated', `select count(*)::int n from public.files`, (r) => r.rows[0].n === 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
