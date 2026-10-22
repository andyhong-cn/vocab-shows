create table if not exists public.friendships (
  from_nick text not null,
  to_nick text not null,
  status text not null,
  created_at timestamptz not null default now(),
  primary key (from_nick, to_nick),
  constraint friendships_status check (status in ('pending', 'accepted')),
  constraint friendships_distinct check (from_nick <> to_nick)
);

alter table public.friendships enable row level security;

revoke all on table public.friendships from public, anon, authenticated;

create or replace function public.authed_nick(p_nick text, p_pin text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  nick text := btrim(p_nick);
  row public.learner_progress;
begin
  if not public.valid_nick(nick) then
    return null;
  end if;
  if p_pin is null or char_length(p_pin) < 4 or char_length(p_pin) > 64 or p_pin ~ '[[:space:]]' then
    return null;
  end if;
  select * into row from public.learner_progress where nickname = nick;
  if not found then
    return null;
  end if;
  if row.pin_hash is distinct from extensions.crypt(p_pin, row.pin_hash) then
    return null;
  end if;
  return nick;
end;
$$;

create or replace function public.learner_face(p_nick text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  row public.learner_progress;
  avatar text := 'cowboy';
  points int := 0;
begin
  select * into row from public.learner_progress where nickname = p_nick;
  if not found then
    return jsonb_build_object('nick', p_nick, 'avatar', 'cowboy', 'points', 0);
  end if;
  avatar := coalesce(row.payload ->> 'avatar', 'cowboy');
  if avatar !~ '^(cowboy|ranger|cowgirl|dino|piggy|potato|springdog|alien|soldier|bear|robot|duck|car)$' then
    avatar := 'cowboy';
  end if;
  begin
    points := coalesce((row.payload -> 'score' ->> 'points')::int, 0);
  exception
    when others then
      points := 0;
  end;
  if points < 0 then
    points := 0;
  elsif points > 1000000 then
    points := 1000000;
  end if;
  return jsonb_build_object('nick', p_nick, 'avatar', avatar, 'points', points);
end;
$$;

create or replace function public.friend_request(p_nick text, p_pin text, p_friend text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  nick text;
  friend text := btrim(p_friend);
  reverse_status text;
  mine_status text;
begin
  nick := public.authed_nick(p_nick, p_pin);
  if nick is null then
    return jsonb_build_object('error', 'pin');
  end if;
  if not public.valid_nick(friend) then
    return jsonb_build_object('error', 'nick');
  end if;
  if friend = nick then
    return jsonb_build_object('error', 'self');
  end if;
  if not exists (select 1 from public.learner_progress where nickname = friend) then
    return jsonb_build_object('error', 'missing');
  end if;

  select status into reverse_status
  from public.friendships
  where from_nick = friend and to_nick = nick;

  select status into mine_status
  from public.friendships
  where from_nick = nick and to_nick = friend;

  if reverse_status = 'accepted' or mine_status = 'accepted' then
    return jsonb_build_object('error', 'already');
  end if;

  if reverse_status = 'pending' then
    update public.friendships
    set status = 'accepted'
    where from_nick = friend and to_nick = nick;
    insert into public.friendships (from_nick, to_nick, status)
    values (nick, friend, 'accepted')
    on conflict (from_nick, to_nick) do update set status = 'accepted';
    return jsonb_build_object('ok', true, 'status', 'accepted');
  end if;

  if mine_status = 'pending' then
    return jsonb_build_object('error', 'pending');
  end if;

  insert into public.friendships (from_nick, to_nick, status)
  values (nick, friend, 'pending');
  return jsonb_build_object('ok', true, 'status', 'pending');
end;
$$;

create or replace function public.friend_respond(p_nick text, p_pin text, p_friend text, p_accept boolean)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  nick text;
  friend text := btrim(p_friend);
  updated int := 0;
begin
  nick := public.authed_nick(p_nick, p_pin);
  if nick is null then
    return jsonb_build_object('error', 'pin');
  end if;
  if not public.valid_nick(friend) then
    return jsonb_build_object('error', 'nick');
  end if;

  if p_accept is true then
    update public.friendships
    set status = 'accepted'
    where from_nick = friend and to_nick = nick and status = 'pending';
    get diagnostics updated = row_count;
    if updated = 0 then
      return jsonb_build_object('error', 'missing');
    end if;
    insert into public.friendships (from_nick, to_nick, status)
    values (nick, friend, 'accepted')
    on conflict (from_nick, to_nick) do update set status = 'accepted';
    return jsonb_build_object('ok', true, 'status', 'accepted');
  end if;

  delete from public.friendships
  where from_nick = friend and to_nick = nick and status = 'pending';
  return jsonb_build_object('ok', true, 'status', 'declined');
end;
$$;

create or replace function public.friend_board(p_nick text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  nick text;
  friend_nicks text[];
  incoming jsonb;
  outgoing jsonb;
  friends jsonb;
begin
  nick := public.authed_nick(p_nick, p_pin);
  if nick is null then
    return jsonb_build_object('error', 'pin');
  end if;

  select coalesce(array_agg(distinct other_nick), '{}')
  into friend_nicks
  from (
    select case when from_nick = nick then to_nick else from_nick end as other_nick
    from public.friendships
    where status = 'accepted' and (from_nick = nick or to_nick = nick)
  ) accepted_rows;

  select coalesce(jsonb_agg(public.learner_face(friend_nick)), '[]'::jsonb)
  into friends
  from unnest(friend_nicks) as friend_nick;

  select coalesce(jsonb_agg(public.learner_face(from_nick) order by created_at), '[]'::jsonb)
  into incoming
  from public.friendships
  where to_nick = nick and status = 'pending';

  select coalesce(jsonb_agg(jsonb_build_object('nick', to_nick) order by created_at), '[]'::jsonb)
  into outgoing
  from public.friendships
  where from_nick = nick and status = 'pending';

  return jsonb_build_object(
    'ok', true,
    'me', public.learner_face(nick),
    'friends', friends,
    'incoming', incoming,
    'outgoing', outgoing
  );
end;
$$;

revoke all on function public.authed_nick(text, text) from public, anon, authenticated;
revoke all on function public.learner_face(text) from public, anon, authenticated;
revoke all on function public.friend_request(text, text, text) from public;
revoke all on function public.friend_respond(text, text, text, boolean) from public;
revoke all on function public.friend_board(text, text) from public;

grant execute on function public.friend_request(text, text, text) to anon, authenticated;
grant execute on function public.friend_respond(text, text, text, boolean) to anon, authenticated;
grant execute on function public.friend_board(text, text) to anon, authenticated;
