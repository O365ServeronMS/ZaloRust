# Shadow DB — chế độ mật khẩu di động ("Option A", batch 18)

> Bổ sung cho `docs/shadow-architecture.md` (A1–A8). Trạng thái: đã cài
> (batch 18); thiết kế do user chốt: kho phải khóa được bằng mật khẩu
> do USER chọn, để `default.db` + mật khẩu mở được trên BẤT KỲ máy nào.

## 1. Hai chế độ khóa của một thư mục store

| Chế độ | Khóa | Tệp liên quan | Mở ở máy khác? |
|---|---|---|---|
| `raw` (mặc định, như trước batch 18) | 32 byte random, DPAPI-wrapped theo CurrentUser | `default.db`, `default.key` | KHÔNG — key chỉ unwrap được trên máy tạo ra nó |
| `passphrase` | Mật khẩu do user chọn, SQLCipher 4 mặc định (PBKDF2-HMAC-SHA512, 256.000 vòng, salt trong header DB) | `default.db` (+ tùy chọn `default.pass.dpapi`, marker `default.keymode.json`) | CÓ — chỉ cần mật khẩu |

- Marker chế độ là JSON **plaintext, không chứa bí mật**:
  `default.keymode.json` = `{"mode":"passphrase","kdf":"sqlcipher4-default","since_ms":…}`.
  Không có marker + có `default.key` = `raw` (backward compatible 100%).
- Chế độ passphrase KHÔNG đặt `kdf_iter`/`cipher_*` nào — cố ý: SQLCipher 4
  mặc định chính là "format di động", để DB Browser for SQLCipher (hoặc
  `sqlite3` shell có SQLCipher) mở bằng đúng mật khẩu + cài đặt mặc định.
- "Nhớ trên máy này" (tùy chọn tiện lợi): `default.pass.dpapi` = DPAPI
  (CurrentUser, entropy label riêng `zalors.shadow.pass` — khác với key
  file cũ vốn KHÔNG có entropy) wrap của mật khẩu. Xóa tệp này chỉ có
  nghĩa là app hỏi lại mật khẩu ở lần chạy sau; không mất dữ liệu gì.

## 2. Vòng đời mật khẩu

- **Đặt mật khẩu** (Settings → "Đặt mật khẩu DB", tối thiểu 12 ký tự):
  chạy trên flusher thread (single writer A5). Thứ tự: backup trước bằng
  key RAW cũ (`pre-passphrase-backups/` — bản này MỚI ĐÓ chỉ mở được trên
  máy), kiểm tra journal THẬT SỰ rời WAL (xem `store-busy` bên dưới),
  `PRAGMA rekey` sang mật khẩu (qua quoting của rusqlite, không bao giờ
  `format!()`), mở lại bằng CHỈ mật khẩu + `PRAGMA integrity_check` +
  so row counts, mới ghi marker, rồi đổi tên `default.key` →
  `default.key.pre-passphrase` (giữ lại, KHÔNG xóa — UI báo user có thể
  xóa sau). Nếu một file `default.key.pre-passphrase` từ lần chuyển ĐÃ
  CÓ sẵn: nó được đổi tên sang `default.key.pre-passphrase.<ms>` (ms =
  `since_ms` của marker cũ nếu còn đọc được, nếu không thì mtime của
  chính file đó, thêm số thứ tự nếu trùng) rồi mới đổi tên key mới vào
  chỗ — KHÔNG BAO GIỜ xóa (xem §7: mỗi đời key mở đúng một bản backup).
- **Đổi mật khẩu**: cần mật khẩu cũ (chứng minh bằng cách mở DB trước
  khi rekey; sai thì chỉ nhận thông báo chung + rate-limit 5 lần rồi
  khóa 30 giây). Remember file được cập nhật/xóa đồng thời với khóa.
- **Bỏ mật khẩu**: sinh 32 byte random MỚI, lưu DPAPI vào `default.key`
  (trước khi rekey), rekey sang nó, verify, xóa marker + remember file.
- **`store-busy`** (F1): `PRAGMA journal_mode = DELETE` KHÔNG hỏng rõ
  ràng khi còn connection khác đang mở store (cửa sổ Lưu trữ, công cụ
  ngoài): hoặc chỉ trả về `wal` (không lỗi), hoặc — như bản SQLCipher
  vendored của build này — báo SQLITE_BUSY ngay trên câu lệnh. Engine
  đọc kết quả và TỪ CHỐI với lỗi `store-busy` TRƯỚC khi rekey: không
  đổi key, không ghi marker, không đụng remember file (bản pre-backup
  đã kịp tạo thì để lại — vô hại). UI dịch: "đóng cửa sổ Lưu trữ rồi
  thử lại; chưa thay đổi gì".
- **Mọi lỗi sau khi rekey** (F3): cờ `rekey_landed` đặt ngay khi rekey
  trả về OK; MỌI lỗi sau đó (verify, ghi/xóa marker, injection test) đều
  rekey-back — set → key raw cũ, change → mật khẩu cũ, remove → mật khẩu
  hiện tại (và xóa `default.key` mới sinh, kèm verify rekey-back thành
  công trước khi xóa — vì `sqlite3_rekey_v2` trong bản SQLCipher vendored
  có thể rollback khi busy mà vẫn trả SQLITE_OK). Không bao giờ có trạng
  thái "khóa bằng key không tồn tại ở đâu".
- **Sau mỗi lần set/change/remove** (F2): flusher publish key mới vào
  "key cell" dùng chung của tiến trình (epoch tăng lên). Media thread mở
  connection TỪNG CYCLE bằng giá trị cell hiện tại; cửa sổ Lưu trữ drop
  connection cache khi epoch đổi và mở lại bằng key mới (cell trước,
  remember file sau). Không cần restart app như trước.

## 3. Khởi động + unlock (R2)

- `raw`: như trước, không đổi.
- `passphrase`: app đọc `default.pass.dpapi`; unwrap + mở được thì
  pipeline chạy bình thường (flusher giữ mật khẩu trong RAM, zeroize khi
  thoát). Nếu KHÔNG có remember file (hoặc file đó đã lỗi thời): pipeline
  KHÔNG chạy, log ghi đúng dòng
  `shadow: store locked (passphrase mode) — waiting for unlock`, và cửa
  sổ prompt (giống pattern cửa sổ app-lock) hiện ra hỏi mật khẩu +
  ô "Nhớ trên máy này". Lệnh `shadow_unlock` chỉ được cấp cho đúng cửa
  sổ đó (capability riêng); sai mật khẩu → lỗi chung, đếm vào rate-limit.
  **Capture trong lúc khoá bị DROP** (không có DB để ghi) — đã duyệt là
  chấp nhận được.

## 4. Mọi đường khác mở store (R4)

Archive window, probe/maint tools, `import --apply --target`,
`--shadow-copy`: chế độ passphrase chỉ mở qua `default.pass.dpapi`.
Không có remember file → từ chối với thông báo rõ ("kho được bảo vệ bằng
mật khẩu; bật 'Nhớ trên máy này' trong app, hoặc mở DB bằng mật khẩu
bằng công cụ ngoài"). **Không bao giờ** nhận mật khẩu qua argv/env.

Ngoại lệ (F2, cùng tiến trình với pipeline): cửa sổ Lưu trữ và media
thread mở bằng "key cell" (giá trị RAM flusher publish) TRƯỚC, remember
file sau — nên unlock mà KHÔNG bật "Nhớ" thì cửa sổ Lưu trữ vẫn mở
được; probe/maint/CLI là tiến trình riêng nên vẫn chỉ remember file.

Backup trong chế độ passphrase: export qua `ATTACH … KEY ?` (bound
parameter) nên bản backup mở bằng đúng mật khẩu trên máy nào; manifest
ghi `mode: passphrase` (không có bí mật); `verify_backup` đọc được cả
hai chế độ.

## 5. Chuyển máy — copy gì?

Muốn chuyển store sang máy khác (chế độ `passphrase`):

1. `default.db` (tự nó đã là toàn bộ DB; đề nghị checkpoint WAL trước
   khi copy khi app đang chạy — hoặc copy khi app đã thoát).
2. Thư mục media store (`D:\Zalo Data\ab\cd\<sha256>…`) **riêng**, nếu
   muốn cả ảnh/video đã tải.
3. Mật khẩu (user tự nhớ/ghi).

KHÔNG cần: `default.key` (đã đổi tên thành `default.key.pre-passphrase`,
chỉ dùng trên máy cũ), `default.pass.dpapi` (chỉ tiện lợi trên máy cũ),
`default.keymode.json` (app tự nhận dạng raw/passphrase qua việc thử
mở — nhưng copy theo cũng vô hại vì không có bí mật).

Chế độ `raw` KHÔNG chuyển máy được theo cách này: key bị buộc vào DPAPI
của máy cũ. Muốn chuyển, hãy đặt mật khẩu trước (chính là mục đích của
batch này), hoặc xuất bản backup trên máy cũ rồi restore bằng mật khẩu.

## 6. Quên mật khẩu thì mất gì?

**Mất toàn bộ dữ liệu trong DB.** Không có backdoor: SQLCipher 4 KDF
256.000 vòng không thể "đặt lại"; key không nằm ở bất kỳ đâu ngoài mật
khẩu trong đầu user (và remember file trên máy đã từng bật "Nhớ"). Đây
là lý do UI buộc cảnh báo rõ ràng và bắt xác nhận trước khi đặt. Backup
`pre-passphrase-backups/` (máy-cục-bộ, mở bằng key raw cũ) là phương án
cứu cuối — nếu máy đó còn nguyên `default.key.pre-passphrase`.

## 7. Backup cũ (chế độ raw) vẫn khóa theo máy

Mọi bản backup `shadow-<stamp>.db` tạo TRƯỚC khi đặt mật khẩu là export
bằng key raw → chỉ mở được trên máy đã tạo (DPAPI). Sau khi đặt mật khẩu,
các bản backup mới (`mode: passphrase` trong manifest) mới là bản di
động được. Đây là điểm đã ghi rõ trong manifest để tránh nhầm lẫn.

### 7b. Key nào mở bản `pre-passphrase-backups/` nào (F4)

Mỗi lần "Đặt mật khẩu" tạo đúng MỘT bản backup trước-khi-rekey trong
`pre-passphrase-backups/`, mở bằng đúng key RAW của thời điểm đó:

| Thời điểm set | Key mở bản backup của nó | File trên đĩa |
|---|---|---|
| Lần set gần nhất | Key raw đúng trước lần set đó | `default.key.pre-passphrase` |
| Các lần set TRƯỚC đó | Key raw của thời điểm đó | `default.key.pre-passphrase.<ms>` (ms = `since_ms` marker cũ hoặc mtime file; thêm `.1`, `.2`… nếu trùng) |

Ví dụ set → remove → set: key của LẦN ĐẦU vẫn nằm ở
`default.key.pre-passphrase.<ms>` và là key duy nhất mở được bản
backup đầu tiên; key của lần thứ hai nằm ở tên chuẩn. Các file này
KHÔNG bao giờ bị app xóa — chỉ user mới được xóa, và xóa thì mất luôn
khả năng mở bản backup tương ứng (nên giữ lại).

## 8. D7 (key import Zalo Desktop) KHÔNG liên quan

Mật khẩu store này chỉ để mở **shadow DB của app này**. Nó không liên
quan gì đến:

- key import Zalo Desktop (D7: blob DPAPI không-entropy, passphrase 32
  ký tự của Zalo Desktop, mở `Index.db`/`Message\*.db` trong snapshot);
- mật khẩu app-lock (Argon2 hash trong `app-lock.json`, khóa giao diện
  app chứ không khóa DB);
- WS/REST decode key của pipeline (chỉ RAM, batch 4).

Ba lớp khóa này độc lập hoàn toàn; quên một cái không động đến hai cái
còn lại.
