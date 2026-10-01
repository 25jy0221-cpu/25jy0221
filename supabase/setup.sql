-- ひびノート「みんなの日記」用のセットアップSQL
-- Supabase の SQL Editor に、このファイルの内容をまるごと貼り付けて Run してください。
-- ★ 一番下の「合言葉」を、自分で決めた合言葉に書き換えてから実行すること。

-- ------------------------------------------------------------
-- 1. 拡張機能(合言葉のハッシュ化に使う)
-- ------------------------------------------------------------
create extension if not exists pgcrypto with schema extensions;

-- ------------------------------------------------------------
-- 2. テーブル
-- ------------------------------------------------------------
create table if not exists public.timeline_settings (
  id              int primary key default 1 check (id = 1),
  passphrase_hash text not null
);

create table if not exists public.posts (
  id          uuid primary key default gen_random_uuid(),
  author      text not null check (char_length(author) between 1 and 20),
  body        text not null check (char_length(body) between 1 and 1000),
  owner_hash  text not null,                      -- 投稿した端末の鍵のハッシュ(削除の本人確認用)
  created_at  timestamptz not null default now()
);
create index if not exists posts_created_at_idx on public.posts (created_at desc);

create table if not exists public.auth_failures (
  at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 3. テーブルへ直接アクセスできないようにする
--    (公開キーを持っていても、下の関数を通さない限り何も読み書きできない)
-- ------------------------------------------------------------
alter table public.timeline_settings enable row level security;
alter table public.posts             enable row level security;
alter table public.auth_failures     enable row level security;

revoke all on table public.timeline_settings from anon, authenticated;
revoke all on table public.posts             from anon, authenticated;
revoke all on table public.auth_failures     from anon, authenticated;

-- ------------------------------------------------------------
-- 4. 合言葉のチェック(内部用。外部からは呼べない)
--    10分間に30回まちがえると、いったん全員ロックされる(総当たり対策)
-- ------------------------------------------------------------
create or replace function public.hn_check(p_pass text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  ok boolean;
  fails int;
begin
  delete from auth_failures where at < now() - interval '1 hour';
  select count(*) into fails from auth_failures where at > now() - interval '10 minutes';
  if fails >= 30 then
    return 'too_many_attempts';
  end if;

  select exists (
    select 1 from timeline_settings
    where id = 1 and passphrase_hash = crypt(coalesce(p_pass, ''), passphrase_hash)
  ) into ok;

  if not ok then
    insert into auth_failures default values;
    return 'bad_passphrase';
  end if;
  return 'ok';
end;
$$;

revoke all on function public.hn_check(text) from public, anon, authenticated;

-- ------------------------------------------------------------
-- 5. 投稿を読む
-- ------------------------------------------------------------
create or replace function public.hn_get_posts(
  p_pass   text,
  p_key    text,
  p_before timestamptz default null,
  p_limit  int default 30
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  st  text;
  h   text;
  res jsonb;
begin
  st := hn_check(p_pass);
  if st <> 'ok' then
    return jsonb_build_object('ok', false, 'error', st);
  end if;

  h := case when coalesce(p_key, '') = '' then null
            else encode(digest(p_key, 'sha256'), 'hex') end;

  select coalesce(jsonb_agg(to_jsonb(x) order by x.created_at desc), '[]'::jsonb)
    into res
  from (
    select id, author, body, created_at,
           coalesce(owner_hash = h, false) as mine
    from posts
    where p_before is null or created_at < p_before
    order by created_at desc
    limit least(greatest(coalesce(p_limit, 30), 1), 100)
  ) x;

  return jsonb_build_object('ok', true, 'posts', res);
end;
$$;

-- ------------------------------------------------------------
-- 6. 投稿する(1分間に5件まで)
-- ------------------------------------------------------------
create or replace function public.hn_create_post(
  p_pass   text,
  p_author text,
  p_body   text,
  p_key    text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  st     text;
  a      text;
  b      text;
  h      text;
  recent int;
begin
  st := hn_check(p_pass);
  if st <> 'ok' then
    return jsonb_build_object('ok', false, 'error', st);
  end if;

  a := btrim(coalesce(p_author, ''));
  b := btrim(coalesce(p_body, ''));
  if char_length(a) not between 1 and 20
     or char_length(b) not between 1 and 1000
     or char_length(coalesce(p_key, '')) < 16 then
    return jsonb_build_object('ok', false, 'error', 'invalid_input');
  end if;

  h := encode(digest(p_key, 'sha256'), 'hex');

  select count(*) into recent
  from posts
  where owner_hash = h and created_at > now() - interval '1 minute';
  if recent >= 5 then
    return jsonb_build_object('ok', false, 'error', 'rate_limited');
  end if;

  insert into posts (author, body, owner_hash) values (a, b, h);
  return jsonb_build_object('ok', true);
end;
$$;

-- ------------------------------------------------------------
-- 7. 自分の投稿を削除する(投稿した端末だけが消せる)
-- ------------------------------------------------------------
create or replace function public.hn_delete_post(
  p_pass text,
  p_id   uuid,
  p_key  text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  st text;
  n  int;
begin
  st := hn_check(p_pass);
  if st <> 'ok' then
    return jsonb_build_object('ok', false, 'error', st);
  end if;

  delete from posts
  where id = p_id
    and owner_hash = encode(digest(coalesce(p_key, ''), 'sha256'), 'hex');
  get diagnostics n = row_count;

  if n = 0 then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;
  return jsonb_build_object('ok', true);
end;
$$;

-- 公開キーから呼べるのは、この3つの関数だけ
revoke all on function public.hn_get_posts(text, text, timestamptz, int) from public;
revoke all on function public.hn_create_post(text, text, text, text)     from public;
revoke all on function public.hn_delete_post(text, uuid, text)           from public;
grant execute on function public.hn_get_posts(text, text, timestamptz, int) to anon, authenticated;
grant execute on function public.hn_create_post(text, text, text, text)     to anon, authenticated;
grant execute on function public.hn_delete_post(text, uuid, text)           to anon, authenticated;

-- ------------------------------------------------------------
-- 8. ★ 合言葉を設定する ★
--    'ここに合言葉' の部分を、自分で決めた合言葉に書き換えてから実行してください。
--    合言葉を変えたいときは、書き換えてこの文だけをもう一度実行すれば上書きされます。
-- ------------------------------------------------------------
insert into public.timeline_settings (id, passphrase_hash)
values (1, extensions.crypt('たまうらかゆめ', extensions.gen_salt('bf')))
on conflict (id) do update set passphrase_hash = excluded.passphrase_hash;
