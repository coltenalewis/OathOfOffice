-- Profiles table with admin flags, gold, subscription, and ban state
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text,
  role text default 'Wandering Traveler',
  household text default 'Traveler',
  gold integer not null default 0,
  has_subscription boolean not null default false,
  is_admin boolean not null default false,
  is_banned boolean not null default false,
  last_ip inet,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.user_ip_logs (
  id bigserial primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  ip_address inet not null,
  created_at timestamptz not null default now()
);

create table if not exists public.admin_audit_logs (
  id bigserial primary key,
  admin_id uuid not null references auth.users (id) on delete cascade,
  target_user_id uuid not null references auth.users (id) on delete cascade,
  action text not null,
  amount integer,
  notes text,
  created_at timestamptz not null default now()
);

create or replace function public.handle_user_update()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger handle_profiles_updated
before update on public.profiles
for each row execute function public.handle_user_update();

-- IP tracking helper (call on login or session refresh from your app)
create or replace function public.log_user_ip(p_user_id uuid, p_ip inet)
returns void
language plpgsql
security definer
as $$
begin
  update public.profiles
  set last_ip = p_ip
  where id = p_user_id;

  insert into public.user_ip_logs (user_id, ip_address)
  values (p_user_id, p_ip);
end;
$$;

-- Admin helper functions (require RLS policies for admin role)
create or replace function public.admin_grant_gold(
  p_admin_id uuid,
  p_target_user uuid,
  p_amount integer,
  p_notes text default null
) returns void
language plpgsql
security definer
as $$
begin
  update public.profiles
  set gold = gold + p_amount
  where id = p_target_user;

  insert into public.admin_audit_logs (admin_id, target_user_id, action, amount, notes)
  values (p_admin_id, p_target_user, 'grant_gold', p_amount, p_notes);
end;
$$;

create or replace function public.admin_set_subscription(
  p_admin_id uuid,
  p_target_user uuid,
  p_enabled boolean,
  p_notes text default null
) returns void
language plpgsql
security definer
as $$
begin
  update public.profiles
  set has_subscription = p_enabled
  where id = p_target_user;

  insert into public.admin_audit_logs (admin_id, target_user_id, action, notes)
  values (p_admin_id, p_target_user, 'set_subscription', p_notes);
end;
$$;

create or replace function public.admin_set_ban(
  p_admin_id uuid,
  p_target_user uuid,
  p_banned boolean,
  p_notes text default null
) returns void
language plpgsql
security definer
as $$
begin
  update public.profiles
  set is_banned = p_banned
  where id = p_target_user;

  insert into public.admin_audit_logs (admin_id, target_user_id, action, notes)
  values (p_admin_id, p_target_user, 'set_ban', p_notes);
end;
$$;

-- Basic RLS
alter table public.profiles enable row level security;
alter table public.user_ip_logs enable row level security;
alter table public.admin_audit_logs enable row level security;

-- Allow users to read/update their own profile
create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);

create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = id);

-- Allow admins to read all profiles
create policy "profiles_select_admin" on public.profiles
  for select using (
    exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin = true)
  );

-- IP logs: only admins can read
create policy "ip_logs_select_admin" on public.user_ip_logs
  for select using (
    exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin = true)
  );

-- Audit logs: only admins can read
create policy "audit_logs_select_admin" on public.admin_audit_logs
  for select using (
    exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin = true)
  );
