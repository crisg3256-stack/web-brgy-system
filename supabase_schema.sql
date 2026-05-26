create extension if not exists pgcrypto;

create table if not exists admins (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  full_name text,
  role text default 'Administrator',
  password_hash text not null,
  created_at timestamptz default now()
);

-- Main table for the "Request Now" form.
-- Matches these fields:
-- full_name, address, contact_number, email,
-- certificate_type, purpose, valid_id_url
create table if not exists certificate_requests (
  id uuid primary key default gen_random_uuid(),
  request_id text unique not null,
  full_name text not null,
  address text not null,
  contact_number text not null,
  email text not null,
  certificate_type text not null,
  purpose text not null,
  status text not null default 'pending',
  valid_id_url text,
  created_at timestamptz default now(),
  constraint certificate_requests_status_check
    check (status in ('pending', 'processing', 'ready', 'rejected', 'claimed')),
  constraint certificate_requests_certificate_type_check
    check (
      certificate_type in (
        'Barangay Clearance',
        'Certificate of Residency',
        'Certificate of Indigency',
        'Business Permit',
        'Community Tax Certificate',
        'Certificate of Good Moral',
        'Certificate of Employment'
      )
    )
);

create index if not exists idx_certificate_requests_request_id on certificate_requests (request_id);
create index if not exists idx_certificate_requests_email on certificate_requests (email);
create index if not exists idx_certificate_requests_status on certificate_requests (status);

-- Optional sample admin account row.
-- Replace the password_hash with a real hashed password before production use.
insert into admins (username, full_name, role, password_hash)
values ('admin', 'Barangay Admin', 'Administrator', 'admin123')
on conflict (username) do nothing;
