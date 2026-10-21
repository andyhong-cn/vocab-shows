create extension if not exists pgcrypto with schema extensions;

create table if not exists public.learner_progress (
  nickname text primary key,
  pin_hash text not null,
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  constraint learner_progress_nick_len check (char_length(nickname) between 1 and 30)
);

alter table public.learner_progress enable row level security;

revoke all on table public.learner_progress from public, anon, authenticated;

create or replace function public.valid_nick(nick text)
returns boolean
language sql
immutable
as $$
  select nick is not null
    and char_length(btrim(nick)) between 1 and 30
    and btrim(nick) ~ '^[0-9A-Za-z_\-一-鿿]+$';
$$;

create or replace function public.load_progress(p_nick text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  nick text := btrim(p_nick);
  row public.learner_progress;
begin
  if not public.valid_nick(nick) then
    return jsonb_build_object('error', 'nick');
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then
    return jsonb_build_object('error', 'pin');
  end if;
  select * into row from public.learner_progress where nickname = nick;
  if not found then
    return jsonb_build_object('error', 'new');
  end if;
  if row.pin_hash is distinct from extensions.crypt(p_pin, row.pin_hash) then
    return jsonb_build_object('error', 'pin');
  end if;
  return jsonb_build_object('ok', true, 'payload', row.payload);
end;
$$;

create or replace function public.save_progress(p_nick text, p_pin text, p_payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  nick text := btrim(p_nick);
  row public.learner_progress;
  merged_statuses jsonb;
  remote_statuses jsonb;
  incoming_statuses jsonb;
  status_key text;
  incoming_row jsonb;
  remote_row jsonb;
  incoming_at bigint;
  remote_at bigint;
  incoming_shows jsonb;
  remote_shows jsonb;
  show_id text;
  incoming_show jsonb;
  remote_show jsonb;
  incoming_view bigint;
  remote_view bigint;
  merged_shows jsonb;
  result jsonb;
  top_at bigint;
  remote_top bigint;
begin
  if not public.valid_nick(nick) then
    return jsonb_build_object('error', 'nick');
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then
    return jsonb_build_object('error', 'pin');
  end if;
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
    return jsonb_build_object('error', 'payload');
  end if;
  if octet_length(p_payload::text) > 400000 then
    return jsonb_build_object('error', 'payload');
  end if;

  select * into row from public.learner_progress where nickname = nick for update;

  if not found then
    begin
      insert into public.learner_progress (nickname, pin_hash, payload)
      values (nick, extensions.crypt(p_pin, extensions.gen_salt('bf')), p_payload);
      return jsonb_build_object('ok', true, 'payload', p_payload);
    exception
      when unique_violation then
        select * into row from public.learner_progress where nickname = nick for update;
    end;
  end if;

  if row.pin_hash is distinct from extensions.crypt(p_pin, row.pin_hash) then
    return jsonb_build_object('error', 'pin');
  end if;

  remote_statuses := coalesce(row.payload -> 'statuses', '{}'::jsonb);
  if jsonb_typeof(remote_statuses) <> 'object' then
    remote_statuses := '{}'::jsonb;
  end if;
  incoming_statuses := coalesce(p_payload -> 'statuses', '{}'::jsonb);
  if jsonb_typeof(incoming_statuses) <> 'object' then
    incoming_statuses := '{}'::jsonb;
  end if;
  merged_statuses := remote_statuses;

  for status_key, incoming_row in
    select e.key, e.value from jsonb_each(incoming_statuses) as e
  loop
    if status_key !~ '^[a-z0-9]+:s[0-9]{2}e[0-9]{2}:[a-z0-9]+$' then
      continue;
    end if;
    if jsonb_typeof(incoming_row) <> 'object' then
      continue;
    end if;
    if (incoming_row ->> 'status') not in ('known', 'fuzzy', 'new') then
      continue;
    end if;
    begin
      incoming_at := coalesce((incoming_row ->> 'updatedAt')::bigint, 0);
    exception
      when others then
        continue;
    end;
    remote_row := merged_statuses -> status_key;
    remote_at := 0;
    if remote_row is not null then
      begin
        remote_at := coalesce((remote_row ->> 'updatedAt')::bigint, 0);
      exception
        when others then
          remote_at := 0;
      end;
    end if;
    if remote_row is null or incoming_at >= remote_at then
      merged_statuses := jsonb_set(
        merged_statuses,
        array[status_key],
        jsonb_build_object('status', incoming_row ->> 'status', 'updatedAt', incoming_at),
        true
      );
    end if;
  end loop;

  remote_shows := coalesce(row.payload -> 'shows', '{}'::jsonb);
  if jsonb_typeof(remote_shows) <> 'object' then
    remote_shows := '{}'::jsonb;
  end if;
  incoming_shows := coalesce(p_payload -> 'shows', '{}'::jsonb);
  if jsonb_typeof(incoming_shows) <> 'object' then
    incoming_shows := '{}'::jsonb;
  end if;
  merged_shows := remote_shows;

  for show_id, incoming_show in
    select e.key, e.value from jsonb_each(incoming_shows) as e
  loop
    if show_id !~ '^[a-z0-9]+$' then
      continue;
    end if;
    if jsonb_typeof(incoming_show) <> 'object' then
      continue;
    end if;
    begin
      incoming_view := coalesce((incoming_show ->> 'viewUpdatedAt')::bigint, 0);
    exception
      when others then
        continue;
    end;
    remote_show := merged_shows -> show_id;
    remote_view := 0;
    if remote_show is not null then
      begin
        remote_view := coalesce((remote_show ->> 'viewUpdatedAt')::bigint, 0);
      exception
        when others then
          remote_view := 0;
      end;
    end if;
    if remote_show is null or incoming_view >= remote_view then
      merged_shows := jsonb_set(merged_shows, array[show_id], incoming_show, true);
    end if;
  end loop;

  begin
    top_at := coalesce((p_payload ->> 'viewUpdatedAt')::bigint, 0);
  exception
    when others then
      top_at := 0;
  end;
  begin
    remote_top := coalesce((row.payload ->> 'viewUpdatedAt')::bigint, 0);
  exception
    when others then
      remote_top := 0;
  end;

  if top_at >= remote_top then
    result := p_payload;
  else
    result := row.payload;
  end if;
  result := jsonb_set(result, '{statuses}', merged_statuses, true);
  result := jsonb_set(result, '{shows}', merged_shows, true);

  update public.learner_progress
  set payload = result, updated_at = now()
  where nickname = nick;

  return jsonb_build_object('ok', true, 'payload', result);
end;
$$;

revoke all on function public.load_progress(text, text) from public;
revoke all on function public.save_progress(text, text, jsonb) from public;
revoke all on function public.valid_nick(text) from public;

grant execute on function public.load_progress(text, text) to anon, authenticated;
grant execute on function public.save_progress(text, text, jsonb) to anon, authenticated;
