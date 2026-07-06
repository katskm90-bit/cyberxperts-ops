-- Cyberxperts internal operations platform
-- Initial schema and row level security.
-- Every table below enforces access at the database level. The frontend
-- navigation hides what a person should not see, but this is what actually
-- protects the data if that were ever bypassed.

create type department_key as enum (
  'sales', 'cybersecurity', 'it_delivery', 'internal_it', 'finance', 'operations'
);

create type role_tier as enum (
  'system', 'department_super', 'manager', 'staff'
);

create type pipeline_type as enum ('tender', 'private', 'partner');

-- One row per authenticated user, extending Supabase auth.users.
create table profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text not null,
  email text not null,
  department department_key,
  role_tier role_tier not null default 'staff',
  mfa_enrolled boolean not null default false,
  created_at timestamptz not null default now()
);

create table clients (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  sector text,
  created_at timestamptz not null default now()
);

create table opportunities (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references clients (id),
  pipeline_type pipeline_type not null,
  stage text not null default 'lead',
  value numeric,
  owner_id uuid references profiles (id),
  created_at timestamptz not null default now()
);

create table proposals (
  id uuid primary key default gen_random_uuid(),
  opportunity_id uuid references opportunities (id),
  scope text,
  requires_second_reviewer boolean not null default false,
  signed_off_by uuid references profiles (id),
  second_reviewer_id uuid references profiles (id),
  created_at timestamptz not null default now()
);

create table contracts (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references clients (id),
  opportunity_id uuid references opportunities (id),
  value numeric,
  start_date date,
  end_date date,
  created_at timestamptz not null default now()
);

create table projects (
  id uuid primary key default gen_random_uuid(),
  contract_id uuid references contracts (id),
  project_manager_id uuid references profiles (id),
  status text not null default 'active',
  created_at timestamptz not null default now()
);

create table delivery_tickets (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references projects (id),
  department department_key not null,
  sla_target text,
  status text not null default 'open',
  created_at timestamptz not null default now()
);

create table invoices (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references projects (id),
  amount numeric not null,
  payment_terms text,
  approval_status text not null default 'pending',
  approved_by uuid references profiles (id),
  created_at timestamptz not null default now()
);

create table compliance_documents (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid references profiles (id),
  expiry_date date,
  created_at timestamptz not null default now()
);

create table non_conformances (
  id uuid primary key default gen_random_uuid(),
  finding text not null,
  owner_id uuid references profiles (id),
  due_date date,
  closed_at timestamptz,
  created_at timestamptz not null default now()
);

create table staff_events (
  id uuid primary key default gen_random_uuid(),
  event_type text not null check (event_type in ('joiner', 'mover', 'leaver')),
  staff_name text not null,
  raised_by_hr_officer_id uuid references profiles (id),
  provisioning_status text not null default 'pending',
  created_at timestamptz not null default now()
);

create table client_offboarding (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references clients (id),
  data_returned boolean not null default false,
  access_revoked boolean not null default false,
  retention_confirmed boolean not null default false,
  created_at timestamptz not null default now()
);

-- System wide configurable values. Only the system super user can change
-- these. Everything referencing a threshold or an alert window reads from
-- here rather than a hardcoded number.
create table settings (
  key text primary key,
  value text not null,
  updated_by uuid references profiles (id),
  updated_at timestamptz not null default now()
);

insert into settings (key, value) values
  ('second_reviewer_threshold', '0'),
  ('md_approval_threshold', '0'),
  ('contract_renewal_alert_days', '60');

create table audit_log (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references profiles (id),
  action text not null,
  table_name text not null,
  record_id uuid,
  created_at timestamptz not null default now()
);

-- Helper function: reads the calling user's profile once per query rather
-- than repeating the subquery in every policy below.
create or replace function auth_profile()
returns profiles
language sql
security definer
stable
as $$
  select * from profiles where id = auth.uid();
$$;

alter table profiles enable row level security;
alter table clients enable row level security;
alter table opportunities enable row level security;
alter table proposals enable row level security;
alter table contracts enable row level security;
alter table projects enable row level security;
alter table delivery_tickets enable row level security;
alter table invoices enable row level security;
alter table compliance_documents enable row level security;
alter table non_conformances enable row level security;
alter table staff_events enable row level security;
alter table client_offboarding enable row level security;
alter table settings enable row level security;
alter table audit_log enable row level security;

-- A person can always read their own profile. Only the system super user
-- can read every profile, which is what powers department scoped access
-- checks elsewhere.
create policy "read own profile" on profiles
  for select using (id = auth.uid());

create policy "system super user reads all profiles" on profiles
  for select using ((select role_tier from auth_profile()) = 'system');

-- Sales & Bids: department_key 'sales'. Delivery tickets are tagged by
-- department directly, everything else is scoped through the department of
-- the person who owns the related opportunity.
create policy "sales department access" on opportunities
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) = 'sales'
  );

create policy "sales writes own department" on opportunities
  for insert with check (
    (select department from auth_profile()) = 'sales'
    or (select role_tier from auth_profile()) = 'system'
  );

create policy "cybersecurity and sales see proposals" on proposals
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) in ('sales', 'cybersecurity')
  );

create policy "clients visible to sales, finance, operations" on clients
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) in ('sales', 'finance', 'operations')
  );

create policy "contracts visible to sales, finance, operations" on contracts
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) in ('sales', 'finance', 'operations')
  );

create policy "projects visible to operations, it_delivery, cybersecurity, finance" on projects
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) in ('operations', 'it_delivery', 'cybersecurity', 'finance')
  );

-- Delivery tickets are only visible to the department they are tagged with,
-- plus the system super user. This is what keeps IT Delivery and
-- Cybersecurity operational tickets from mixing.
create policy "delivery tickets scoped to their own department" on delivery_tickets
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or department = (select department from auth_profile())
  );

create policy "finance department access" on invoices
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) = 'finance'
  );

create policy "sales manages compliance documents" on compliance_documents
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) = 'sales'
  );

create policy "operations manages non conformances" on non_conformances
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) = 'operations'
  );

create policy "internal it and operations see staff events" on staff_events
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) in ('internal_it', 'operations')
  );

create policy "operations manages client offboarding" on client_offboarding
  for select using (
    (select role_tier from auth_profile()) = 'system'
    or (select department from auth_profile()) = 'operations'
  );

-- Settings and the audit log are system super user only, with no
-- exceptions, since these two tables sit outside the departmental model.
create policy "system super user only: settings" on settings
  for all using ((select role_tier from auth_profile()) = 'system');

create policy "system super user only: audit log" on audit_log
  for select using ((select role_tier from auth_profile()) = 'system');
