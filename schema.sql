-- Учёт продуктов для кафе.
-- Вставить целиком в Supabase -> SQL Editor -> New query -> Run.
-- Можно запускать повторно, ничего не сломается.

-- ============ ТАБЛИЦЫ ============

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  role text not null default 'pending'
    check (role in ('pending','worker','admin','owner','blocked')),
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  unit text not null default 'шт',
  qty numeric not null default 0 check (qty >= 0),
  min_qty numeric not null default 0 check (min_qty >= 0),
  expires_on date,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  at timestamptz not null default now(),
  user_id uuid,
  user_name text,
  action text not null,
  product_name text,
  old_qty numeric,
  new_qty numeric,
  note text
);
create index if not exists audit_log_at_idx on public.audit_log (at desc);

create table if not exists public.shifts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  day date not null,
  start_time time not null,
  end_time time not null,
  note text
);
create index if not exists shifts_day_idx on public.shifts (day);

-- ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

create or replace function public.my_role()
returns text language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.role_ru(r text)
returns text language sql immutable as $$
  select case r
    when 'pending' then 'ждёт подтверждения'
    when 'worker'  then 'работник'
    when 'admin'   then 'админ'
    when 'owner'   then 'владелец'
    when 'blocked' then 'заблокирован'
    else r end
$$;

-- ============ НОВЫЙ ПОЛЬЗОВАТЕЛЬ ============
-- Самый первый зарегистрированный становится владельцем.
-- Все остальные ждут, пока админ их подтвердит.

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name, role)
  values (
    new.id,
    coalesce(nullif(trim(new.raw_user_meta_data->>'name'), ''), split_part(new.email, '@', 1)),
    case when exists (select 1 from public.profiles) then 'pending' else 'owner' end
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============ ПРАВА ДОСТУПА (RLS) ============

alter table public.profiles  enable row level security;
alter table public.products  enable row level security;
alter table public.audit_log enable row level security;
alter table public.shifts    enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() in ('admin','owner'));

drop policy if exists products_select on public.products;
create policy products_select on public.products for select to authenticated
  using (public.my_role() in ('worker','admin','owner'));

drop policy if exists log_select on public.audit_log;
create policy log_select on public.audit_log for select to authenticated
  using (
    public.my_role() in ('admin','owner')
    or (public.my_role() = 'worker' and user_id = auth.uid())
  );

drop policy if exists shifts_select on public.shifts;
create policy shifts_select on public.shifts for select to authenticated
  using (
    public.my_role() in ('admin','owner')
    or (public.my_role() = 'worker' and user_id = auth.uid())
  );

drop policy if exists shifts_write on public.shifts;
create policy shifts_write on public.shifts for all to authenticated
  using (public.my_role() in ('admin','owner'))
  with check (public.my_role() in ('admin','owner'));

-- Остатки, журнал и роли меняются только через функции ниже,
-- напрямую в эти таблицы писать нельзя. Поэтому журнал не обойти.

-- ============ ОСТАТКИ ============

create or replace function public.change_stock(
  p_product uuid, p_kind text, p_amount numeric,
  p_reason text default null, p_expires date default null)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.products;
  newq numeric;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then
    raise exception 'Нет доступа';
  end if;
  if p_amount is null or p_amount < 0 or (p_amount = 0 and p_kind <> 'set') then
    raise exception 'Введите количество больше нуля';
  end if;

  select * into r from public.products where id = p_product for update;
  if not found then raise exception 'Продукт не найден'; end if;

  if p_kind = 'restock' then
    newq := r.qty + p_amount;
  elsif p_kind = 'writeoff' then
    newq := r.qty - p_amount;
    if newq < 0 then raise exception 'Нельзя списать больше, чем есть (сейчас %)', r.qty; end if;
  elsif p_kind = 'set' then
    newq := p_amount;
  else
    raise exception 'Неизвестное действие';
  end if;

  update public.products
     set qty = newq,
         expires_on = case when p_kind = 'restock' and p_expires is not null then p_expires else expires_on end
   where id = r.id;

  insert into public.audit_log (user_id, user_name, action, product_name, old_qty, new_qty, note)
  values (me.id, me.name, p_kind, r.name, r.qty, newq,
          nullif(trim(coalesce(p_reason, '')), ''));
end $$;

create or replace function public.save_product(
  p_id uuid, p_name text, p_unit text, p_min numeric, p_qty numeric, p_expires date)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.products;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('admin','owner') then
    raise exception 'Только админ может менять список продуктов';
  end if;
  if p_name is null or trim(p_name) = '' then raise exception 'Введите название'; end if;

  if p_id is null then
    insert into public.products (name, unit, qty, min_qty, expires_on)
    values (trim(p_name), coalesce(p_unit, 'шт'), coalesce(p_qty, 0), coalesce(p_min, 0), p_expires);
    insert into public.audit_log (user_id, user_name, action, product_name, new_qty)
    values (me.id, me.name, 'add_product', trim(p_name), coalesce(p_qty, 0));
  else
    select * into r from public.products where id = p_id for update;
    if not found then raise exception 'Продукт не найден'; end if;
    update public.products
       set name = trim(p_name), unit = coalesce(p_unit, 'шт'),
           min_qty = coalesce(p_min, 0), expires_on = p_expires
     where id = p_id;
    insert into public.audit_log (user_id, user_name, action, product_name, note)
    values (me.id, me.name, 'edit_product', trim(p_name),
            'было: ' || r.name || ', ' || r.unit || ', минимум ' || r.min_qty
            || ', срок ' || coalesce(to_char(r.expires_on, 'DD.MM.YYYY'), 'нет'));
  end if;
end $$;

create or replace function public.delete_product(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.products;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('admin','owner') then
    raise exception 'Только админ может удалять продукты';
  end if;
  select * into r from public.products where id = p_id for update;
  if not found then raise exception 'Продукт не найден'; end if;
  delete from public.products where id = p_id;
  insert into public.audit_log (user_id, user_name, action, product_name, old_qty)
  values (me.id, me.name, 'delete_product', r.name, r.qty);
end $$;

-- ============ РОЛИ ============
-- Админ может принимать и блокировать работников.
-- Назначать админов и владельцев может только владелец.

create or replace function public.set_role(p_user uuid, p_role text)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  t  public.profiles;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('admin','owner') then
    raise exception 'Нет доступа';
  end if;
  if p_role not in ('pending','worker','admin','owner','blocked') then
    raise exception 'Неверная роль';
  end if;
  select * into t from public.profiles where id = p_user;
  if not found then raise exception 'Пользователь не найден'; end if;
  if t.id = me.id then raise exception 'Свою роль менять нельзя'; end if;
  if me.role = 'admin' and (t.role in ('admin','owner') or p_role in ('admin','owner')) then
    raise exception 'Админов и владельцев назначает только владелец';
  end if;

  update public.profiles set role = p_role where id = p_user;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'role',
          t.name || ': ' || public.role_ru(t.role) || ' → ' || public.role_ru(p_role));
end $$;

-- ============ ЖУРНАЛ СМЕН ============

create or replace function public.log_shift()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  s public.shifts;
  act text;
  wname text;
  me_name text;
begin
  if tg_op = 'DELETE' then
    s := old; act := 'shift_del';
  else
    s := new;
    act := case when tg_op = 'INSERT' then 'shift_add' else 'shift_edit' end;
  end if;
  select name into wname   from public.profiles where id = s.user_id;
  select name into me_name from public.profiles where id = auth.uid();
  insert into public.audit_log (user_id, user_name, action, note)
  values (auth.uid(), coalesce(me_name, '?'), act,
          coalesce(wname, '?') || ': ' || to_char(s.day, 'DD.MM') || ' '
          || to_char(s.start_time, 'HH24:MI') || '-' || to_char(s.end_time, 'HH24:MI'));
  return null;
end $$;

drop trigger if exists shifts_log on public.shifts;
create trigger shifts_log
  after insert or update or delete on public.shifts
  for each row execute function public.log_shift();

-- ============ ПРАВА НА ВЫЗОВ ============

grant usage on schema public to anon, authenticated;
grant select on public.profiles, public.products, public.audit_log to authenticated;
grant select, insert, update, delete on public.shifts to authenticated;

revoke execute on function public.change_stock(uuid, text, numeric, text, date) from public, anon;
revoke execute on function public.save_product(uuid, text, text, numeric, numeric, date) from public, anon;
revoke execute on function public.delete_product(uuid) from public, anon;
revoke execute on function public.set_role(uuid, text) from public, anon;
grant execute on function public.change_stock(uuid, text, numeric, text, date) to authenticated;
grant execute on function public.save_product(uuid, text, text, numeric, numeric, date) to authenticated;
grant execute on function public.delete_product(uuid) to authenticated;
grant execute on function public.set_role(uuid, text) to authenticated;
grant execute on function public.my_role() to authenticated;

-- ============================================================
-- ДНЕВНОЙ ОТЧЁТ (списания, обеды) И СПИСОК "ЗАКОНЧИЛОСЬ"
-- ============================================================

create table if not exists public.report_items (
  id uuid primary key default gen_random_uuid(),
  day date not null,
  kind text not null check (kind in ('writeoff','lunch')),
  name text not null,
  qty numeric,
  note text,
  user_id uuid references public.profiles(id) on delete set null,
  user_name text,
  created_at timestamptz not null default now()
);
create index if not exists report_items_day_idx on public.report_items (day);

create table if not exists public.need_items (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  status text not null default 'out' check (status in ('out','low')),
  note text,
  created_by text,
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  resolved_by text
);
create index if not exists need_items_open_idx on public.need_items (resolved_at);

alter table public.report_items enable row level security;
alter table public.need_items   enable row level security;

drop policy if exists report_select on public.report_items;
create policy report_select on public.report_items for select to authenticated
  using (public.my_role() in ('worker','admin','owner'));

drop policy if exists need_select on public.need_items;
create policy need_select on public.need_items for select to authenticated
  using (public.my_role() in ('worker','admin','owner'));

-- Добавить записи в отчёт за день. p_items: [{"name":"запеканка","qty":2,"note":""}]
-- Работники могут писать за последние 3 дня, админы за любую дату.
create or replace function public.add_report_items(p_day date, p_kind text, p_items jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  it jsonb;
  nm text;
  q numeric;
  summary text := '';
  n int := 0;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if p_kind not in ('writeoff','lunch') then raise exception 'Неверный раздел'; end if;
  if p_day is null then raise exception 'Не указана дата'; end if;
  if me.role = 'worker' and (p_day < current_date - 3 or p_day > current_date + 1) then
    raise exception 'Для этой даты отчёт закрыт, обратитесь к админу';
  end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) > 60 then
    raise exception 'Слишком много строк за раз';
  end if;

  for it in select * from jsonb_array_elements(p_items) loop
    nm := nullif(trim(it->>'name'), '');
    continue when nm is null;
    q := case when jsonb_typeof(it->'qty') = 'number' then (it->>'qty')::numeric else null end;
    insert into public.report_items (day, kind, name, qty, note, user_id, user_name)
    values (p_day, p_kind, left(nm, 120), q,
            nullif(left(trim(coalesce(it->>'note', '')), 200), ''), me.id, me.name);
    summary := summary || case when n > 0 then ', ' else '' end
               || coalesce(trim_scale(q)::text || ' ', '') || left(nm, 120);
    n := n + 1;
  end loop;
  if n = 0 then raise exception 'Нечего добавлять'; end if;

  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'report_add',
          to_char(p_day, 'DD.MM') || ' ' || case p_kind when 'writeoff' then 'списания' else 'обеды' end
          || ': ' || left(summary, 300));
end $$;

create or replace function public.edit_report_item(p_id uuid, p_name text, p_qty numeric, p_note text)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.report_items;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  select * into r from public.report_items where id = p_id for update;
  if not found then raise exception 'Запись не найдена'; end if;
  if me.role = 'worker' and r.day < current_date - 3 then
    raise exception 'Эту запись уже нельзя менять, обратитесь к админу';
  end if;
  if p_name is null or trim(p_name) = '' then raise exception 'Введите название'; end if;

  update public.report_items
     set name = left(trim(p_name), 120), qty = p_qty,
         note = nullif(left(trim(coalesce(p_note, '')), 200), '')
   where id = p_id;

  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'report_edit',
          to_char(r.day, 'DD.MM') || ': ' || coalesce(trim_scale(r.qty)::text || ' ', '') || r.name
          || ' → ' || coalesce(trim_scale(p_qty)::text || ' ', '') || left(trim(p_name), 120));
end $$;

create or replace function public.delete_report_item(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.report_items;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  select * into r from public.report_items where id = p_id for update;
  if not found then raise exception 'Запись не найдена'; end if;
  if me.role = 'worker' and r.day < current_date - 3 then
    raise exception 'Эту запись уже нельзя удалить, обратитесь к админу';
  end if;
  delete from public.report_items where id = p_id;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'report_del',
          to_char(r.day, 'DD.MM') || ' ' || case r.kind when 'writeoff' then 'списания' else 'обеды' end
          || ': ' || coalesce(trim_scale(r.qty)::text || ' ', '') || r.name);
end $$;

-- Список "закончилось / заканчивается". Висит, пока кто-то не нажмёт "Привезли".
-- p_items: [{"name":"крышки большие","status":"out","note":""}]
create or replace function public.add_needs(p_items jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  it jsonb;
  nm text;
  st text;
  nt text;
  summary text := '';
  n int := 0;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) > 60 then
    raise exception 'Слишком много строк за раз';
  end if;

  for it in select * from jsonb_array_elements(p_items) loop
    nm := nullif(trim(it->>'name'), '');
    continue when nm is null;
    nm := left(nm, 120);
    st := case when it->>'status' = 'low' then 'low' else 'out' end;
    nt := nullif(left(trim(coalesce(it->>'note', '')), 200), '');
    if exists (select 1 from public.need_items where resolved_at is null and lower(name) = lower(nm)) then
      update public.need_items
         set status = st, note = coalesce(nt, note)
       where resolved_at is null and lower(name) = lower(nm);
    else
      insert into public.need_items (name, status, note, created_by) values (nm, st, nt, me.name);
    end if;
    summary := summary || case when n > 0 then ', ' else '' end || nm
               || ' (' || case st when 'low' then 'заканчивается' else 'закончилось' end || ')';
    n := n + 1;
  end loop;
  if n = 0 then raise exception 'Нечего добавлять'; end if;

  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'need_add', left(summary, 300));
end $$;

create or replace function public.set_need(p_id uuid, p_status text)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.need_items;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if p_status not in ('out','low') then raise exception 'Неверный статус'; end if;
  select * into r from public.need_items where id = p_id and resolved_at is null for update;
  if not found then raise exception 'Запись не найдена'; end if;
  update public.need_items set status = p_status where id = p_id;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'need_edit',
          r.name || ': ' || case p_status when 'low' then 'заканчивается' else 'закончилось' end);
end $$;

create or replace function public.resolve_need(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.need_items;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  select * into r from public.need_items where id = p_id and resolved_at is null for update;
  if not found then raise exception 'Запись не найдена'; end if;
  update public.need_items set resolved_at = now(), resolved_by = me.name where id = p_id;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'need_done', r.name);
end $$;

create or replace function public.delete_need(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.need_items;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  select * into r from public.need_items where id = p_id for update;
  if not found then raise exception 'Запись не найдена'; end if;
  delete from public.need_items where id = p_id;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'need_del', r.name);
end $$;

grant select on public.report_items, public.need_items to authenticated;
revoke execute on function public.add_report_items(date, text, jsonb) from public, anon;
revoke execute on function public.edit_report_item(uuid, text, numeric, text) from public, anon;
revoke execute on function public.delete_report_item(uuid) from public, anon;
revoke execute on function public.add_needs(jsonb) from public, anon;
revoke execute on function public.set_need(uuid, text) from public, anon;
revoke execute on function public.resolve_need(uuid) from public, anon;
revoke execute on function public.delete_need(uuid) from public, anon;
grant execute on function public.add_report_items(date, text, jsonb) to authenticated;
grant execute on function public.edit_report_item(uuid, text, numeric, text) to authenticated;
grant execute on function public.delete_report_item(uuid) to authenticated;
grant execute on function public.add_needs(jsonb) to authenticated;
grant execute on function public.set_need(uuid, text) to authenticated;
grant execute on function public.resolve_need(uuid) to authenticated;
grant execute on function public.delete_need(uuid) to authenticated;

-- ============================================================
-- БЫСТРЫЕ СЧЁТЧИКИ: плитка в отчёте, +1 / -1 одним касанием
-- ============================================================
-- Если за день уже есть строка с таким названием, меняется её количество,
-- иначе создаётся новая. В списаниях строка исчезает, когда дошла до нуля,
-- в обедах остаётся с нулём (это значит "порций не осталось").
create or replace function public.bump_report_item(p_day date, p_kind text, p_name text, p_delta numeric)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.report_items;
  nm text;
  newq numeric;
  kind_ru text;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if p_kind not in ('writeoff','lunch') then raise exception 'Неверный раздел'; end if;
  if p_day is null then raise exception 'Не указана дата'; end if;
  if p_delta is null or p_delta = 0 or abs(p_delta) > 1000 then raise exception 'Неверное количество'; end if;
  if me.role = 'worker' and (p_day < current_date - 3 or p_day > current_date + 1) then
    raise exception 'Для этой даты отчёт закрыт, обратитесь к админу';
  end if;
  nm := left(trim(coalesce(p_name, '')), 120);
  if nm = '' then raise exception 'Введите название'; end if;
  kind_ru := case p_kind when 'writeoff' then 'списания' else 'обеды' end;

  select * into r from public.report_items
   where day = p_day and kind = p_kind and lower(name) = lower(nm)
   order by created_at limit 1 for update;

  if not found then
    if p_delta < 0 then return; end if;
    insert into public.report_items (day, kind, name, qty, user_id, user_name)
    values (p_day, p_kind, nm, p_delta, me.id, me.name);
    insert into public.audit_log (user_id, user_name, action, note)
    values (me.id, me.name, 'report_add',
            to_char(p_day, 'DD.MM') || ' ' || kind_ru || ': ' || trim_scale(p_delta)::text || ' ' || nm);
  else
    newq := greatest(coalesce(r.qty, 0) + p_delta, 0);
    if newq = coalesce(r.qty, 0) then return; end if;
    if newq = 0 and p_kind = 'writeoff' then
      delete from public.report_items where id = r.id;
    else
      update public.report_items set qty = newq where id = r.id;
    end if;
    insert into public.audit_log (user_id, user_name, action, note)
    values (me.id, me.name, 'report_edit',
            to_char(p_day, 'DD.MM') || ' ' || kind_ru || ': ' || r.name || ' '
            || trim_scale(coalesce(r.qty, 0))::text || ' → ' || trim_scale(newq)::text);
  end if;
end $$;

revoke execute on function public.bump_report_item(date, text, text, numeric) from public, anon;
grant execute on function public.bump_report_item(date, text, text, numeric) to authenticated;

-- ============================================================
-- ОБНОВЛЕНИЕ 3: быстрые счётчики и статус "отчёт сдан"
-- ============================================================

alter table public.report_items add column if not exists updated_at timestamptz not null default now();

create table if not exists public.day_reports (
  day date primary key,
  submitted_at timestamptz not null default now(),
  submitted_by text
);
alter table public.day_reports enable row level security;
drop policy if exists day_reports_select on public.day_reports;
create policy day_reports_select on public.day_reports for select to authenticated
  using (public.my_role() in ('worker','admin','owner'));

-- +1 / -1 / задать число для позиции отчёта. Одна строка на день, раздел и название.
-- Списания: меняется на дельту, при нуле строка исчезает. Обеды: p_set = true задаёт число.
create or replace function public.change_report_item(
  p_day date, p_kind text, p_name text, p_delta numeric, p_set boolean default false)
returns numeric language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.report_items;
  nm text;
  newq numeric;
  kind_ru text;
  what text;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if p_kind not in ('writeoff','lunch') then raise exception 'Неверный раздел'; end if;
  if p_day is null or p_delta is null then raise exception 'Неверные данные'; end if;
  if me.role = 'worker' and (p_day < current_date - 3 or p_day > current_date + 1) then
    raise exception 'Для этой даты отчёт закрыт, обратитесь к админу';
  end if;
  nm := left(trim(coalesce(p_name, '')), 120);
  if nm = '' then raise exception 'Введите название'; end if;
  kind_ru := case p_kind when 'writeoff' then 'списания' else 'обеды' end;

  select * into r from public.report_items
   where day = p_day and kind = p_kind and lower(name) = lower(nm)
   order by created_at limit 1 for update;

  if not found then
    newq := greatest(p_delta, 0);
    if p_kind = 'writeoff' and newq <= 0 then return 0; end if;
    insert into public.report_items (day, kind, name, qty, user_id, user_name)
    values (p_day, p_kind, nm, newq, me.id, me.name);
  else
    newq := greatest(case when p_set then p_delta else coalesce(r.qty, 0) + p_delta end, 0);
    if p_kind = 'writeoff' and newq <= 0 then
      delete from public.report_items where id = r.id;
    else
      update public.report_items
         set qty = newq, user_id = me.id, user_name = me.name, updated_at = now()
       where id = r.id;
    end if;
  end if;

  what := case
    when p_set then '= ' || trim_scale(newq)::text
    when p_delta >= 0 then '+' || trim_scale(p_delta)::text || ' (всего ' || trim_scale(newq)::text || ')'
    else trim_scale(p_delta)::text || ' (всего ' || trim_scale(newq)::text || ')' end;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'report_add', to_char(p_day, 'DD.MM') || ' ' || kind_ru || ': ' || nm || ' ' || what);
  return newq;
end $$;

-- Вставка списком теперь тоже складывает в одну строку на название.
create or replace function public.add_report_items(p_day date, p_kind text, p_items jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.report_items;
  it jsonb;
  nm text;
  q numeric;
  summary text := '';
  n int := 0;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if p_kind not in ('writeoff','lunch') then raise exception 'Неверный раздел'; end if;
  if p_day is null then raise exception 'Не указана дата'; end if;
  if me.role = 'worker' and (p_day < current_date - 3 or p_day > current_date + 1) then
    raise exception 'Для этой даты отчёт закрыт, обратитесь к админу';
  end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) > 60 then
    raise exception 'Слишком много строк за раз';
  end if;

  for it in select * from jsonb_array_elements(p_items) loop
    nm := left(nullif(trim(it->>'name'), ''), 120);
    continue when nm is null;
    q := case when jsonb_typeof(it->'qty') = 'number' then (it->>'qty')::numeric else null end;
    select * into r from public.report_items
     where day = p_day and kind = p_kind and lower(name) = lower(nm)
     order by created_at limit 1 for update;
    if found then
      update public.report_items
         set qty = case when p_kind = 'writeoff' then coalesce(r.qty, 0) + coalesce(q, 0) else coalesce(q, r.qty) end,
             user_id = me.id, user_name = me.name, updated_at = now(),
             note = coalesce(nullif(left(trim(coalesce(it->>'note', '')), 200), ''), r.note)
       where id = r.id;
    else
      insert into public.report_items (day, kind, name, qty, note, user_id, user_name)
      values (p_day, p_kind, nm, q, nullif(left(trim(coalesce(it->>'note', '')), 200), ''), me.id, me.name);
    end if;
    summary := summary || case when n > 0 then ', ' else '' end
               || coalesce(trim_scale(q)::text || ' ', '') || nm;
    n := n + 1;
  end loop;
  if n = 0 then raise exception 'Нечего добавлять'; end if;

  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'report_add',
          to_char(p_day, 'DD.MM') || ' ' || case p_kind when 'writeoff' then 'списания' else 'обеды' end
          || ': ' || left(summary, 300));
end $$;

create or replace function public.submit_report(p_day date)
returns void language plpgsql security definer set search_path = public as $$
declare me public.profiles;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if me.role = 'worker' and (p_day < current_date - 3 or p_day > current_date + 1) then
    raise exception 'Для этой даты отчёт закрыт, обратитесь к админу';
  end if;
  insert into public.day_reports (day, submitted_at, submitted_by) values (p_day, now(), me.name)
  on conflict (day) do update set submitted_at = now(), submitted_by = me.name;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'report_submit', to_char(p_day, 'DD.MM') || ' отчёт сдан');
end $$;

create or replace function public.reopen_report(p_day date)
returns void language plpgsql security definer set search_path = public as $$
declare me public.profiles;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if me.role = 'worker' and (p_day < current_date - 3 or p_day > current_date + 1) then
    raise exception 'Для этой даты отчёт закрыт, обратитесь к админу';
  end if;
  delete from public.day_reports where day = p_day;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'report_reopen', to_char(p_day, 'DD.MM') || ' отчёт открыт снова');
end $$;

grant select on public.day_reports to authenticated;
revoke execute on function public.change_report_item(date, text, text, numeric, boolean) from public, anon;
revoke execute on function public.submit_report(date) from public, anon;
revoke execute on function public.reopen_report(date) from public, anon;
revoke execute on function public.add_report_items(date, text, jsonb) from public, anon;
grant execute on function public.change_report_item(date, text, text, numeric, boolean) to authenticated;
grant execute on function public.submit_report(date) to authenticated;
grant execute on function public.reopen_report(date) to authenticated;
grant execute on function public.add_report_items(date, text, jsonb) to authenticated;

-- ============================================================
-- ОБНОВЛЕНИЕ 4: общий график смен, источник прихода (Смузи),
-- заметки смены (покупки по чеку, поломки), поставщики товаров
-- ============================================================

-- ---------- Общий график: работники видят смены всех ----------
drop policy if exists shifts_select on public.shifts;
create policy shifts_select on public.shifts for select to authenticated
  using (public.my_role() in ('worker','admin','owner'));

-- Чтобы в графике были видны имена коллег, работнику видны профили сотрудников.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (
    id = auth.uid()
    or public.my_role() in ('admin','owner')
    or (public.my_role() = 'worker' and role in ('worker','admin','owner'))
  );

-- ---------- Поставщик у товара ----------
alter table public.products add column if not exists supplier text;

drop function if exists public.save_product(uuid, text, text, numeric, numeric, date);
create or replace function public.save_product(
  p_id uuid, p_name text, p_unit text, p_min numeric, p_qty numeric, p_expires date,
  p_supplier text default null)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.products;
  sup text := nullif(left(trim(coalesce(p_supplier, '')), 80), '');
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('admin','owner') then
    raise exception 'Только админ может менять список продуктов';
  end if;
  if p_name is null or trim(p_name) = '' then raise exception 'Введите название'; end if;

  if p_id is null then
    insert into public.products (name, unit, qty, min_qty, expires_on, supplier)
    values (trim(p_name), coalesce(p_unit, 'шт'), coalesce(p_qty, 0), coalesce(p_min, 0), p_expires, sup);
    insert into public.audit_log (user_id, user_name, action, product_name, new_qty, note)
    values (me.id, me.name, 'add_product', trim(p_name), coalesce(p_qty, 0),
            case when sup is not null then 'поставщик: ' || sup end);
  else
    select * into r from public.products where id = p_id for update;
    if not found then raise exception 'Продукт не найден'; end if;
    update public.products
       set name = trim(p_name), unit = coalesce(p_unit, 'шт'),
           min_qty = coalesce(p_min, 0), expires_on = p_expires, supplier = sup
     where id = p_id;
    insert into public.audit_log (user_id, user_name, action, product_name, note)
    values (me.id, me.name, 'edit_product', trim(p_name),
            'было: ' || r.name || ', ' || r.unit || ', минимум ' || r.min_qty
            || ', срок ' || coalesce(to_char(r.expires_on, 'DD.MM.YYYY'), 'нет')
            || ', поставщик ' || coalesce(r.supplier, 'нет'));
  end if;
end $$;

-- ---------- Приход: от поставщика или взяли из «Смузи» ----------
drop function if exists public.change_stock(uuid, text, numeric, text, date);
create or replace function public.change_stock(
  p_product uuid, p_kind text, p_amount numeric,
  p_reason text default null, p_expires date default null, p_source text default null)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.products;
  newq numeric;
  nt text := nullif(trim(coalesce(p_reason, '')), '');
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then
    raise exception 'Нет доступа';
  end if;
  if p_amount is null or p_amount < 0 or (p_amount = 0 and p_kind <> 'set') then
    raise exception 'Введите количество больше нуля';
  end if;

  select * into r from public.products where id = p_product for update;
  if not found then raise exception 'Продукт не найден'; end if;

  if p_kind = 'restock' then
    newq := r.qty + p_amount;
    if p_source = 'smoothie' then
      nt := 'взяли из «Смузи»' || coalesce(': ' || nt, '');
    else
      nt := 'от поставщика' || coalesce(' ' || r.supplier, '') || coalesce(': ' || nt, '');
    end if;
  elsif p_kind = 'writeoff' then
    newq := r.qty - p_amount;
    if newq < 0 then raise exception 'Нельзя списать больше, чем есть (сейчас %)', r.qty; end if;
  elsif p_kind = 'set' then
    newq := p_amount;
  else
    raise exception 'Неизвестное действие';
  end if;

  update public.products
     set qty = newq,
         expires_on = case when p_kind = 'restock' and p_expires is not null then p_expires else expires_on end
   where id = r.id;

  insert into public.audit_log (user_id, user_name, action, product_name, old_qty, new_qty, note)
  values (me.id, me.name, p_kind, r.name, r.qty, newq, left(nt, 300));
end $$;

-- ---------- Заметки смены: покупки по чеку и поломки ----------
create table if not exists public.shift_notes (
  id uuid primary key default gen_random_uuid(),
  day date not null,
  kind text not null check (kind in ('purchase','issue')),
  text text not null,
  amount numeric check (amount is null or amount >= 0),
  paid_from text check (paid_from in ('cash','own')),
  user_id uuid references public.profiles(id) on delete set null,
  user_name text,
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  resolved_by text
);
create index if not exists shift_notes_day_idx on public.shift_notes (day);
create index if not exists shift_notes_open_idx on public.shift_notes (resolved_at);

alter table public.shift_notes enable row level security;
drop policy if exists shift_notes_select on public.shift_notes;
create policy shift_notes_select on public.shift_notes for select to authenticated
  using (public.my_role() in ('worker','admin','owner'));

create or replace function public.add_shift_note(
  p_day date, p_kind text, p_text text, p_amount numeric default null, p_paid text default null)
returns uuid language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  t text := left(trim(coalesce(p_text, '')), 300);
  pf text;
  nid uuid;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  if p_kind not in ('purchase','issue') then raise exception 'Неверный раздел'; end if;
  if p_day is null then raise exception 'Не указана дата'; end if;
  if me.role = 'worker' and (p_day < current_date - 3 or p_day > current_date + 1) then
    raise exception 'Для этой даты отчёт закрыт, обратитесь к админу';
  end if;
  if t = '' then raise exception 'Напишите, что случилось'; end if;
  if p_kind = 'purchase' then
    if p_amount is null or p_amount <= 0 or p_amount > 1000000 then raise exception 'Укажите сумму по чеку'; end if;
    pf := case when p_paid = 'own' then 'own' else 'cash' end;
  end if;

  insert into public.shift_notes (day, kind, text, amount, paid_from, user_id, user_name)
  values (p_day, p_kind, t, case when p_kind = 'purchase' then p_amount end, pf, me.id, me.name)
  returning id into nid;

  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'note_add',
          to_char(p_day, 'DD.MM') || ' '
          || case when p_kind = 'purchase'
               then 'покупка: ' || t || ', ' || trim_scale(p_amount)::text || ' ₽ '
                    || case pf when 'own' then '(свои деньги)' else '(из кассы)' end
               else 'заметка: ' || t end);
  return nid;
end $$;

-- Отметить «учтено» (покупка) или «решено» (поломка). Только админ и владелец.
create or replace function public.resolve_shift_note(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.shift_notes;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('admin','owner') then raise exception 'Только админ может закрывать заметки'; end if;
  select * into r from public.shift_notes where id = p_id and resolved_at is null for update;
  if not found then raise exception 'Заметка не найдена'; end if;
  update public.shift_notes set resolved_at = now(), resolved_by = me.name where id = p_id;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'note_done',
          to_char(r.day, 'DD.MM') || ' ' || r.text
          || coalesce(', ' || trim_scale(r.amount)::text || ' ₽', ''));
end $$;

-- Удалить: автор в течение 3 дней или админ.
create or replace function public.delete_shift_note(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  me public.profiles;
  r  public.shift_notes;
begin
  select * into me from public.profiles where id = auth.uid();
  if coalesce(me.role, 'none') not in ('worker','admin','owner') then raise exception 'Нет доступа'; end if;
  select * into r from public.shift_notes where id = p_id for update;
  if not found then raise exception 'Заметка не найдена'; end if;
  if me.role = 'worker' and (r.user_id is distinct from me.id or r.day < current_date - 3 or r.resolved_at is not null) then
    raise exception 'Эту заметку может убрать только админ';
  end if;
  delete from public.shift_notes where id = p_id;
  insert into public.audit_log (user_id, user_name, action, note)
  values (me.id, me.name, 'note_del',
          to_char(r.day, 'DD.MM') || ' ' || r.text
          || coalesce(', ' || trim_scale(r.amount)::text || ' ₽', ''));
end $$;

grant select on public.shift_notes to authenticated;
revoke execute on function public.save_product(uuid, text, text, numeric, numeric, date, text) from public, anon;
revoke execute on function public.change_stock(uuid, text, numeric, text, date, text) from public, anon;
revoke execute on function public.add_shift_note(date, text, text, numeric, text) from public, anon;
revoke execute on function public.resolve_shift_note(uuid) from public, anon;
revoke execute on function public.delete_shift_note(uuid) from public, anon;
grant execute on function public.save_product(uuid, text, text, numeric, numeric, date, text) to authenticated;
grant execute on function public.change_stock(uuid, text, numeric, text, date, text) to authenticated;
grant execute on function public.add_shift_note(date, text, text, numeric, text) to authenticated;
grant execute on function public.resolve_shift_note(uuid) to authenticated;
grant execute on function public.delete_shift_note(uuid) to authenticated;
