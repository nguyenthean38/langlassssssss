-- Web xem do nhieu VPS (buoc 1). Chay 1 lan tren Supabase SQL Editor.
--
-- Bang KHONG cho doc/ghi truc tiep bang anon key (anon key nam trong client).
-- Moi truy cap di qua RPC, kiem tra ma bi mat (secret) cua chu:
--   lt_push(secret, vps, rows)  agent tren tung VPS day du lieu len
--   lt_list(secret)             trang web doc ve
-- Chi secret da dang ky trong lt_owner moi day/doc duoc (chong nguoi la spam).
--
-- SAU KHI CHAY: dang ky secret cua ban (it nhat 12 ky tu, KHONG chia se):
--   INSERT INTO lt_owner(owner_hash, note) VALUES (lt_hash('MA-BI-MAT-CUA-BAN'), 'chu');

CREATE OR REPLACE FUNCTION lt_hash(p_secret text)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT encode(sha256(convert_to(p_secret, 'UTF8')), 'hex');
$$;

CREATE TABLE IF NOT EXISTS lt_owner (
  owner_hash text PRIMARY KEY,
  note       text,
  created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS lt_acc_snapshot (
  owner_hash text        NOT NULL REFERENCES lt_owner(owner_hash) ON DELETE CASCADE,
  vps        text        NOT NULL,
  acc_id     text        NOT NULL,
  char_name  text,
  online     boolean     NOT NULL DEFAULT false,
  map        int,
  khu        int,
  vk         int,
  gear_avg   real,
  bac        bigint,
  bac_khoa   bigint,
  items      jsonb       NOT NULL DEFAULT '[]'::jsonb,
  equips     jsonb       NOT NULL DEFAULT '[]'::jsonb,
  seen_at    bigint,                                   -- updatedAt cua client (ms)
  updated_at timestamptz NOT NULL DEFAULT NOW(),
  PRIMARY KEY (owner_hash, vps, acc_id)
);

ALTER TABLE lt_owner        ENABLE ROW LEVEL SECURITY;
ALTER TABLE lt_acc_snapshot ENABLE ROW LEVEL SECURITY;
-- Khong tao policy nao => anon/authenticated khong doc ghi bang truc tiep duoc.
REVOKE ALL ON lt_owner, lt_acc_snapshot FROM anon, authenticated;

CREATE OR REPLACE FUNCTION lt_push(p_secret text, p_vps text, p_rows jsonb)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  h text;
  n int;
BEGIN
  IF p_secret IS NULL OR length(p_secret) < 12 THEN
    RAISE EXCEPTION 'secret qua ngan';
  END IF;
  h := lt_hash(p_secret);
  IF NOT EXISTS (SELECT 1 FROM lt_owner WHERE owner_hash = h) THEN
    RAISE EXCEPTION 'secret chua dang ky';
  END IF;
  IF p_vps IS NULL OR length(p_vps) = 0 OR length(p_vps) > 40 THEN
    RAISE EXCEPTION 'ten vps khong hop le';
  END IF;
  IF jsonb_typeof(p_rows) <> 'array' OR jsonb_array_length(p_rows) > 100 THEN
    RAISE EXCEPTION 'rows phai la mang toi da 100 acc';
  END IF;

  INSERT INTO lt_acc_snapshot AS s
    (owner_hash, vps, acc_id, char_name, online, map, khu, vk, gear_avg,
     bac, bac_khoa, items, equips, seen_at, updated_at)
  SELECT h, p_vps, r->>'acc_id', r->>'char_name', COALESCE((r->>'online')::boolean, false),
         (r->>'map')::int, (r->>'khu')::int, (r->>'vk')::int, (r->>'gear_avg')::real,
         (r->>'bac')::bigint, (r->>'bac_khoa')::bigint,
         COALESCE(r->'items', '[]'::jsonb), COALESCE(r->'equips', '[]'::jsonb),
         (r->>'seen_at')::bigint, NOW()
  FROM jsonb_array_elements(p_rows) r
  WHERE COALESCE(r->>'acc_id', '') <> ''
  ON CONFLICT (owner_hash, vps, acc_id) DO UPDATE SET
    char_name = EXCLUDED.char_name, online = EXCLUDED.online, map = EXCLUDED.map,
    khu = EXCLUDED.khu, vk = EXCLUDED.vk, gear_avg = EXCLUDED.gear_avg,
    bac = EXCLUDED.bac, bac_khoa = EXCLUDED.bac_khoa, items = EXCLUDED.items,
    equips = EXCLUDED.equips, seen_at = EXCLUDED.seen_at, updated_at = NOW();
  GET DIAGNOSTICS n = ROW_COUNT;

  -- Acc da xoa khoi VPS nay -> xoa luon tren web.
  DELETE FROM lt_acc_snapshot
  WHERE owner_hash = h AND vps = p_vps
    AND acc_id NOT IN (SELECT r->>'acc_id' FROM jsonb_array_elements(p_rows) r);
  RETURN n;
END;
$$;

CREATE OR REPLACE FUNCTION lt_list(p_secret text)
RETURNS TABLE(vps text, acc_id text, char_name text, online boolean, map int, khu int,
              vk int, gear_avg real, bac bigint, bac_khoa bigint, items jsonb, equips jsonb,
              seen_at bigint, updated_at timestamptz)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT s.vps, s.acc_id, s.char_name, s.online, s.map, s.khu, s.vk, s.gear_avg,
         s.bac, s.bac_khoa, s.items, s.equips, s.seen_at, s.updated_at
  FROM lt_acc_snapshot s
  WHERE s.owner_hash = lt_hash(p_secret)
  ORDER BY s.vps, s.acc_id;
$$;

REVOKE ALL ON FUNCTION lt_push(text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION lt_list(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lt_push(text, text, jsonb) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION lt_list(text) TO anon, authenticated;

-- Test (sau khi dang ky secret):
-- SELECT lt_push('MA-BI-MAT-CUA-BAN', 'TEST', '[{"acc_id":"acc01","char_name":"x","online":true}]');
-- SELECT * FROM lt_list('MA-BI-MAT-CUA-BAN');
-- SELECT * FROM lt_list('sai-ma-bi-mat');   -- phai ra 0 dong
