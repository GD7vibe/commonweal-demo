-- ============================================================================
-- Commonweal — demo backend for Supabase
-- Paste this whole file into the Supabase SQL Editor and press Run, once.
-- It creates the tables, locks them with RLS, and exposes a small set of
-- server-side functions that the web page calls. All entry logic runs HERE,
-- in Postgres — not in the browser.
-- ============================================================================

create extension if not exists pgcrypto with schema extensions;

-- ── Tables ──────────────────────────────────────────────────────────────────
create table if not exists public.passes (
  id              uuid primary key default gen_random_uuid(),
  display_name    text not null,
  site_scope      text not null default 'mountwise',
  status          text not null default 'active'
                  check (status in ('active','suspended','revoked')),
  suspended_until timestamptz,
  created_at      timestamptz not null default now()
);

-- Enforcement record + audit trail in one. The most sensitive table.
create table if not exists public.incidents (
  id              bigint generated always as identity primary key,
  pass_id         uuid not null references public.passes(id) on delete cascade,
  action          text not null check (action in ('warning','suspend','revoke','reinstate')),
  infraction_type text,
  note            text,
  duration_label  text,
  suspended_until timestamptz,
  created_at      timestamptz not null default now()
);

-- Demo signing key. CHANGE THIS VALUE to anything random before a real demo.
create table if not exists public.app_config (
  key   text primary key,
  value text not null
);
insert into public.app_config(key, value)
  values ('signing_key', 'CHANGE-ME-to-a-random-secret-string')
  on conflict (key) do nothing;

-- ── Row-Level Security: lock everything. Access only via the functions below ──
alter table public.passes     enable row level security;
alter table public.incidents  enable row level security;
alter table public.app_config enable row level security;
-- No policies are created, so the public/anon key cannot touch these tables
-- directly. The SECURITY DEFINER functions below run as the owner and bypass
-- RLS in a controlled way.

-- ── Helper: base64url encode (no padding) ────────────────────────────────────
create or replace function public._b64url(p_data bytea)
returns text language sql immutable as $$
  select translate(encode(p_data, 'base64'), E'+/=\n\r', '-_');
$$;

-- ── Issue a short-lived signed token for a pass (the rotating QR payload) ─────
-- The token carries NO personal data: only pass id, site scope, and expiry,
-- with an HMAC signature so it cannot be forged.
create or replace function public.issue_pass_token(p_pass_id uuid, p_ttl_seconds int default 20)
returns text language plpgsql security definer
set search_path = public, extensions as $$
declare
  v_key text; v_scope text; v_body text; v_sig text; v_payload text;
begin
  select value into v_key from public.app_config where key = 'signing_key';
  select site_scope into v_scope from public.passes where id = p_pass_id;
  if v_scope is null then raise exception 'unknown pass'; end if;

  v_payload := json_build_object(
    'pid',   p_pass_id,
    'scope', v_scope,
    'exp',   extract(epoch from now())::bigint + p_ttl_seconds
  )::text;

  v_body := public._b64url(convert_to(v_payload, 'UTF8'));
  v_sig  := public._b64url(hmac(v_body, v_key, 'sha256'));
  return v_body || '.' || v_sig;
end; $$;

-- ── Validate a scanned token at the gate (server-side, live status check) ─────
-- Mirrors §8.4 of the spec: signature -> expiry -> site scope -> live status.
-- Also auto-lifts a suspension whose clock has run out.
create or replace function public.validate_scan(p_token text, p_scanner_site text)
returns json language plpgsql security definer
set search_path = public, extensions as $$
declare
  v_key text; v_parts text[]; v_body text; v_sig text;
  v_payload json; v_pid uuid; v_scope text; v_exp bigint;
  v_pass public.passes%rowtype;
begin
  if p_token is null then return json_build_object('result','DENY','reason','no_code'); end if;

  v_parts := string_to_array(p_token, '.');
  if array_length(v_parts, 1) <> 2 then
    return json_build_object('result','DENY','reason','malformed');
  end if;
  v_body := v_parts[1]; v_sig := v_parts[2];

  select value into v_key from public.app_config where key = 'signing_key';
  if v_sig <> public._b64url(hmac(v_body, v_key, 'sha256')) then
    return json_build_object('result','DENY','reason','bad_signature');
  end if;

  begin
    v_payload := convert_from(
      decode(translate(v_body,'-_','+/') || repeat('=', (4 - (length(v_body) % 4)) % 4), 'base64'),
      'UTF8')::json;
  exception when others then
    return json_build_object('result','DENY','reason','malformed');
  end;

  v_pid   := (v_payload->>'pid')::uuid;
  v_scope := v_payload->>'scope';
  v_exp   := (v_payload->>'exp')::bigint;

  if v_exp < extract(epoch from now())::bigint then
    return json_build_object('result','DENY','reason','invalid_or_expired');
  end if;
  if v_scope <> p_scanner_site then
    return json_build_object('result','DENY','reason','wrong_site');
  end if;

  select * into v_pass from public.passes where id = v_pid;
  if not found then return json_build_object('result','DENY','reason','not_found'); end if;

  -- auto-expire a finished suspension
  if v_pass.status = 'suspended' and v_pass.suspended_until is not null
     and now() >= v_pass.suspended_until then
    update public.passes set status='active', suspended_until=null where id = v_pid;
    v_pass.status := 'active';
  end if;

  if v_pass.status <> 'active' then
    return json_build_object('result','DENY','reason',v_pass.status,
      'display_name', v_pass.display_name, 'until', v_pass.suspended_until);
  end if;

  return json_build_object('result','ALLOW','display_name', v_pass.display_name, 'pid', v_pid);
end; $$;

-- ── Apply an enforcement action (warning / suspend / revoke / reinstate) ──────
-- p_duration_seconds drives the bar length for a suspension.
create or replace function public.enforce(
  p_pass_id          uuid,
  p_action           text,
  p_infraction_type  text default null,
  p_note             text default null,
  p_duration_seconds int  default null,
  p_duration_label   text default null
) returns json language plpgsql security definer
set search_path = public as $$
declare v_until timestamptz;
begin
  if not exists (select 1 from public.passes where id = p_pass_id) then
    raise exception 'unknown pass';
  end if;

  if p_action = 'suspend' then
    if coalesce(p_duration_seconds,0) <= 0 then raise exception 'suspend needs a duration'; end if;
    v_until := now() + make_interval(secs => p_duration_seconds);
    update public.passes set status='suspended', suspended_until=v_until where id=p_pass_id;
  elsif p_action = 'revoke' then
    update public.passes set status='revoked', suspended_until=null where id=p_pass_id;
  elsif p_action = 'reinstate' then
    update public.passes set status='active', suspended_until=null where id=p_pass_id;
  elsif p_action = 'warning' then
    null; -- logged only; status unchanged
  else
    raise exception 'unknown action %', p_action;
  end if;

  insert into public.incidents(pass_id, action, infraction_type, note, duration_label, suspended_until)
  values (p_pass_id, p_action, p_infraction_type, p_note, p_duration_label, v_until);

  return json_build_object('ok', true,
    'status', (select status from public.passes where id=p_pass_id),
    'until',  v_until);
end; $$;

-- ── Read helpers for the UI ───────────────────────────────────────────────────
create or replace function public.get_pass(p_pass_id uuid)
returns json language plpgsql security definer set search_path = public as $$
declare
  v_pass public.passes%rowtype;
  v_inc  public.incidents%rowtype;
begin
  select * into v_pass from public.passes where id = p_pass_id;
  if not found then return null; end if;

  if v_pass.status = 'suspended' and v_pass.suspended_until is not null
     and now() >= v_pass.suspended_until then
    update public.passes set status='active', suspended_until=null where id = p_pass_id;
    v_pass.status := 'active'; v_pass.suspended_until := null;
  end if;

  -- when barred, fetch the most recent action that explains why
  if v_pass.status <> 'active' then
    select * into v_inc from public.incidents
      where pass_id = p_pass_id and action in ('suspend','revoke')
      order by created_at desc limit 1;
  end if;

  return json_build_object(
    'id', v_pass.id, 'display_name', v_pass.display_name,
    'status', v_pass.status, 'suspended_until', v_pass.suspended_until,
    'site_scope', v_pass.site_scope,
    'reason_infraction', v_inc.infraction_type,
    'reason_note', v_inc.note,
    'reason_since', v_inc.created_at);
end; $$;

create or replace function public.list_passes()
returns setof public.passes language sql security definer set search_path = public as $$
  select * from public.passes order by created_at limit 50;
$$;

create or replace function public.list_incidents(p_pass_id uuid)
returns setof public.incidents language sql security definer set search_path = public as $$
  select * from public.incidents where pass_id = p_pass_id order by created_at desc limit 50;
$$;

-- ── Grant execute to the public web key. (Tables stay locked.) ────────────────
-- NOTE: for the demo, enforce()/admin functions are open. In production they
-- must sit behind staff authentication (Supabase Auth + a staff role claim).
grant execute on function public.issue_pass_token(uuid,int)             to anon, authenticated;
grant execute on function public.validate_scan(text,text)               to anon, authenticated;
grant execute on function public.enforce(uuid,text,text,text,int,text)  to anon, authenticated;
grant execute on function public.get_pass(uuid)                         to anon, authenticated;
grant execute on function public.list_passes()                          to anon, authenticated;
grant execute on function public.list_incidents(uuid)                   to anon, authenticated;

-- ── Seed one demo pass ────────────────────────────────────────────────────────
insert into public.passes(display_name, site_scope, status)
select 'Sam Carter', 'mountwise', 'active'
where not exists (select 1 from public.passes where display_name = 'Sam Carter');
