-- Run once in a NEW Supabase project (SQL Editor, as postgres).
-- No passwords or secret keys belong in this file.
begin;
create table public.academy_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null unique check (display_name in ('Neda','Boris')),
  share_progress boolean not null default false
);
create table public.academy_progress (
  user_id uuid not null references public.academy_profiles(user_id) on delete cascade,
  day date not null check (day between date '2026-11-25' and date '2027-11-24'),
  status text not null default 'not-started' check (status in ('not-started','in-progress','done','review')),
  seconds integer not null default 0 check (seconds between 0 and 1800),
  notes text not null default '' check (char_length(notes)<=100000),
  solution text not null default '' check (char_length(solution)<=100000),
  custom_task text not null default '' check (char_length(custom_task)<=10000),
  primary key(user_id,day),
  constraint rest_day_limit check (extract(isodow from day) <> 7 or (seconds=0 and status='not-started'))
);
alter table public.academy_profiles enable row level security;
alter table public.academy_progress enable row level security;
revoke all on public.academy_profiles, public.academy_progress from anon, authenticated;
grant select on public.academy_profiles to authenticated;
grant update(share_progress) on public.academy_profiles to authenticated;
grant select,insert,update on public.academy_progress to authenticated;
create policy own_profile_read on public.academy_profiles for select to authenticated using (user_id=(select auth.uid()));
create policy own_profile_sharing on public.academy_profiles for update to authenticated using (user_id=(select auth.uid())) with check(user_id=(select auth.uid()));
create policy own_progress_read on public.academy_progress for select to authenticated using (user_id=(select auth.uid()) and exists(select 1 from public.academy_profiles p where p.user_id=(select auth.uid())));
create policy own_progress_insert on public.academy_progress for insert to authenticated with check(user_id=(select auth.uid()) and exists(select 1 from public.academy_profiles p where p.user_id=(select auth.uid())));
create policy own_progress_update on public.academy_progress for update to authenticated using(user_id=(select auth.uid()) and exists(select 1 from public.academy_profiles p where p.user_id=(select auth.uid()))) with check(user_id=(select auth.uid()) and exists(select 1 from public.academy_profiles p where p.user_id=(select auth.uid())));

-- Atomic per-field updates: two devices editing DIFFERENT fields on a day do not overwrite each other.
-- Same field: last successfully committed edit wins. Invoker security means RLS remains active.
create function public.academy_patch_day(p_user uuid,p_day date,p_patch jsonb) returns void
language plpgsql security invoker set search_path = '' as $$
declare uid uuid := auth.uid();
begin
  if uid is null or uid is distinct from p_user or not exists(select 1 from public.academy_profiles p where p.user_id=uid) then raise exception 'Not an academy member'; end if;
  if p_patch is null or jsonb_typeof(p_patch) <> 'object' or (p_patch - array['status','seconds','notes','solution','custom_task']) <> '{}'::jsonb then raise exception 'Invalid patch'; end if;
  insert into public.academy_progress(user_id,day) values(uid,p_day) on conflict do nothing;
  update public.academy_progress set
    status=case when p_patch ? 'status' then p_patch->>'status' else status end,
    seconds=case when p_patch ? 'seconds' then (p_patch->>'seconds')::integer else seconds end,
    notes=case when p_patch ? 'notes' then p_patch->>'notes' else notes end,
    solution=case when p_patch ? 'solution' then p_patch->>'solution' else solution end,
    custom_task=case when p_patch ? 'custom_task' then p_patch->>'custom_task' else custom_task end
  where user_id=uid and day=p_day;
end; $$;
revoke all on function public.academy_patch_day(uuid,date,jsonb) from public,anon,authenticated;
grant execute on function public.academy_patch_day(uuid,date,jsonb) to authenticated;

-- A narrow privileged RPC returns ONLY names and explicitly shared aggregates.
-- No raw rows, emails, journals, solutions or custom tasks are returned.
create function public.academy_partner_stats()
returns table(display_name text,is_me boolean,completed bigint,total_seconds bigint,week_completed bigint)
language plpgsql stable security definer set search_path = '' as $$
declare uid uuid := auth.uid();
week_start date := (now() at time zone 'Europe/Sofia')::date - (extract(isodow from (now() at time zone 'Europe/Sofia')::date)::int - 1);
begin
  if uid is null or not exists(select 1 from public.academy_profiles p where p.user_id=uid) then raise exception 'Not an academy member'; end if;
  return query select p.display_name, p.user_id=uid,
    case when p.user_id=uid or p.share_progress then count(a.day) filter(where a.status='done') else null end,
    case when p.user_id=uid or p.share_progress then coalesce(sum(a.seconds),0) else null end,
    case when p.user_id=uid or p.share_progress then count(a.day) filter(where a.status='done' and a.day>=week_start and a.day<week_start+7) else null end
  from public.academy_profiles p left join public.academy_progress a on a.user_id=p.user_id
  group by p.user_id,p.display_name,p.share_progress order by p.display_name;
end; $$;
revoke all on function public.academy_partner_stats() from public,anon,authenticated;
grant execute on function public.academy_partner_stats() to authenticated;
commit;
