-- ANALYZER V11 - DOSYA PAYLASIMI ALICI ERISIM ONARIMI
-- Bu yama tekrar calistirilabilir (idempotent).
-- Amaç: gönderenin oluşturduğu paylaşımın alıcı kullanıcı tarafından
-- Bildirimler > Gelen Paylaşımlar bölümünde görülmesini ve dosyanın açılmasını sağlamak.

grant usage on schema public to authenticated;

grant select, insert, update, delete
on table public.file_shares
to authenticated;

grant select, insert, update, delete
on table public.schematics
to authenticated;

grant select, insert, update, delete
on table public.schematic_scans
to authenticated;

alter table public.file_shares enable row level security;
alter table public.schematics enable row level security;
alter table public.schematic_scans enable row level security;

-- Gönderen kendi paylaşımlarını yönetebilir.
drop policy if exists "shares owner manage" on public.file_shares;
create policy "shares owner manage"
on public.file_shares
for all
to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

-- Alıcı, kendisine gönderilmiş ve süresi dolmamış paylaşımı okuyabilir.
drop policy if exists "shares recipient read" on public.file_shares;
create policy "shares recipient read"
on public.file_shares
for select
to authenticated
using (
  recipient_id = auth.uid()
  and expires_at > now()
);

-- Dosya meta bilgisi sahibi veya aktif alıcı tarafından okunabilir.
drop policy if exists "schematics owner/shared read" on public.schematics;
create policy "schematics owner/shared read"
on public.schematics
for select
to authenticated
using (
  owner_id = auth.uid()
  or exists (
    select 1
    from public.file_shares s
    where s.file_id = schematics.id
      and s.recipient_id = auth.uid()
      and s.expires_at > now()
  )
);

-- Tarama/analiz verisi sahibi veya aktif alıcı tarafından okunabilir.
drop policy if exists "scan owner/shared read" on public.schematic_scans;
create policy "scan owner/shared read"
on public.schematic_scans
for select
to authenticated
using (
  exists (
    select 1
    from public.schematics f
    where f.id = schematic_scans.file_id
      and (
        f.owner_id = auth.uid()
        or exists (
          select 1
          from public.file_shares s
          where s.file_id = f.id
            and s.recipient_id = auth.uid()
            and s.expires_at > now()
        )
      )
  )
);

-- Storage: paylaşılan PDF alıcı tarafından indirilebilsin.
drop policy if exists "storage shared read" on storage.objects;
create policy "storage shared read"
on storage.objects
for select
to authenticated
using (
  bucket_id = 'schematics'
  and exists (
    select 1
    from public.schematics f
    join public.file_shares sh on sh.file_id = f.id
    where f.storage_path = storage.objects.name
      and sh.recipient_id = auth.uid()
      and sh.expires_at > now()
  )
);

-- KONTROL 1: Aktif paylaşım gerçekten hangi kullanıcıya gidiyor?
select
  fs.id,
  po.username as gonderen,
  po.email as gonderen_email,
  pr.username as alici,
  pr.email as alici_email,
  s.name as dosya,
  fs.created_at,
  fs.expires_at,
  (fs.expires_at > now()) as aktif
from public.file_shares fs
join public.profiles po on po.id = fs.owner_id
join public.profiles pr on pr.id = fs.recipient_id
left join public.schematics s on s.id = fs.file_id
order by fs.created_at desc;

-- KONTROL 2: Kritik RLS politikaları mevcut mu?
select
  schemaname,
  tablename,
  policyname,
  roles,
  cmd
from pg_policies
where (schemaname = 'public' and tablename in ('file_shares','schematics','schematic_scans'))
   or (schemaname = 'storage' and tablename = 'objects')
order by schemaname, tablename, policyname;
