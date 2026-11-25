# Shadow DB Architecture — ZaloRust

> Trạng thái: **CHỐT** (user-approved 2026-11-19). Thay đổi bất kỳ nguyên tắc
> nào dưới đây cần một quyết định mới có ghi nhận.
> Chi tiết audit/evidence: `D:\.opencode\zalo-audit-handoff-2026-11-19.md`.

## 1. Mô hình tổng thể — capture MỘT CHIỀU

```
[Điện thoại] ⇄ [Zalo server] ⇄ [Zalo Web (WebView2 trong ZaloRust)]
                                       │
                                       ├─ HIỂN THỊ REALTIME: bản web nguyên bản.
                                       │   (chat live vốn tự chạy; không đụng)
                                       │
                                       ├─ CAPTURE song song (đọc, không ghi page):
                                       │   ├─ CDP Network: WS frames + REST bodies
                                       │   │    → Rust decode (AES-128-GCM n16 /
                                       │   │      AES-128-CBC IV=0 / gzip)
                                       │   ├─ Bridge tap: E2EE plaintext lấy tại
                                       │   │    nguồn (page tự decrypt), không tự
                                       │   │    giải Signal protocol
                                       │   └─ Media mới → auto-download rate-limited
                                       ▼
                          ┌──────────────────────────────┐
                          │ SHADOW DB (kho riêng, dài hạn) │
                          │ • SQLCipher, key DPAPI-wrap     │
                          │ • messages/conversations/...    │
                          │ • raw_events ring 7 ngày       │
                          ├──────────────────────────────┤
                          │ MEDIA STORE (content-addressed)│
                          │ • D:\ZaloRust Data\ab\cd\<sha>  │
                          └──────────────┬─────────────────┘
                                         ▲
            (P2) import 1 lần kho Desktop 50GB (media = hardlink)
                                         │
                                         │ XEM KHO
                          ┌──────────────┴─────────────────┐
                          │ MÀN HÌNH "LƯU TRỮ" (P3)          │
                          │ • window native RIÊNG của app    │
                          │ • FTS5 full-text search          │
                          │ • KHÔNG render ngược vào web UI  │
                          └──────────────┬─────────────────┘
                                         │
                          (P4) BACKUP ra ổ user chọn
                          (VACUUM INTO + manifest sha256)
```

## 2. Nguyên tắc kiến trúc (A1-A8)

| # | Nguyên tắc | Hệ quả |
|---|-----------|--------|
| A1 | **Bản web = realtime client + nguồn capture.** Dữ liệu lưu trữ KHÔNG được render ngược vào giao diện web | web UI không bao giờ bị ZaloRust ghi đè nội dung; không rủi ro vỡ layout khi Zalo update bundle |
| A2 | **Capture 1 chiều, read-only với page** (CDP + prototype tap chỉ đọc giá trị page tự sản xuất) | page hành vi như browser thường; tap re-throw lỗi gốc, không đổi flow |
| A3 | **Kho riêng mã hoá**: SQLCipher (key random 32B, DPAPI CurrentUser, no-entropy legacy-compat) + media content-addressed sha256 (dedupe tự nhiên, không plaintext-keyed path) | chỉ user đó đọc được; file trùng lưu 1 lần |
| A4 | **Xem kho = màn hình Lưu trữ native riêng** (window của app, đọc shadow DB trực tiếp + FTS5) | tách bạch hoàn toàn "đang chat" (web) và "lịch sử lưu trữ" (native) |
| A5 | **Single-writer DB**: flusher thread là owner duy nhất mọi domain write; media thread chỉ UPDATE attachments; import qua cùng writer guards | không lock contention, không write race |
| A6 | **Key hygiene**: WS key (mỗi connection), REST key, own-uid → chỉ RAM, redact trước khi vào raw_events, không bao giờ log giá trị | transcript/log không lộ key kể cả khi debug |
| A7 | **Import Desktop (P2) = merge 1 chiều vào kho**: `source='import'`, không đè capture plaintext (writer guard), media Desktop hardlink (D9, cùng volume D:) | kho Web + kho Desktop thành MỘT lịch sử duy nhất |
| A8 | **Backup (P4) cuối pipeline**: VACUUM INTO + manifest sha256/counts, 6h + on-exit, 7 daily + 4 weekly (D3), media incremental theo sha256 filename | backup luôn phản ánh kho đã ổn định |

**A2 sau batch 30 (25/11/2026): vẫn read-only.** Batch 30 chỉ GIẢI MÃ THÊM những gì Zalo Web đã nhận (WS `encrypt=3`, reaction, sự kiện nhóm, `getLoginInfo`, 5 endpoint REST danh bạ/nhóm). Không gửi request nào, không ghi gì vào page. Khóa của `getLoginInfo` suy ra trong RAM từ `zcid`/`zcid_ext` nằm trong URL request mà CDP đã báo; không khóa, `zcid`, cookie, uid hay URL nào được lưu hoặc log (A6). Việc "đọc nhẹ chủ động" qua trang (nới A2) là batch 33 và chưa làm.

### 2.1 Bảng WS cmd (batch 30)

Nguồn: zca-js v2.4.0 `src/apis/listen.ts` (MIT, xem `docs/third-party-notices.md`). Code: `shadow/ws_events.rs` (`classify_cmd`).

| cmd | Nội dung | Phân loại | Kết quả |
|---|---|---|---|
| 501 510 511 521 551 | tin nhắn (đường cũ `msgs`/`groupMsgs`/...) | giải mã | `Write::Message` như trước |
| 601 | `controls[]`: `group`, `fr`, `transfer_sync2`, `file_done` | giải mã | sự kiện nhóm -> `groups`/`conversations`/`contacts`/`participants` + dòng hệ thống (`messages.type=10`); `fr`, `transfer_sync2`, `file_done` chỉ đếm |
| 610 611 612 | reaction (lịch sử, nhóm, trực tiếp) | giải mã | `Write::Reaction` (thêm/gỡ), đích có thể chưa có trong `messages` |
| 502 522 | đã nhận / đã xem | chỉ đếm | số frame + số phần tử mỗi mảng, không lưu |
| 602 | đang gõ | chỉ đếm | số frame + số phần tử |
| 3000 | đăng nhập trùng | chỉ đếm | bộ đếm + 1 dòng log mỗi giờ: `ws: session replaced elsewhere (cmd 3000)` |
| 1 2 | khóa / ping | bỏ qua | chỉ bộ đếm frame |
| khác | chưa phân loại | chưa biết | `frames.unclassified` (nhóm "lạ" duy nhất còn lại) |

`encrypt=3` (batch 30 M1): AES-GCM giống `encrypt=2` (cùng khóa, cùng bố cục `[IV 16][AAD 16][ct+tag]`) nhưng KHÔNG gzip.

Quy ước dữ liệu từ sự kiện nhóm: dòng hệ thống có `msg_id = sys:<groupId>:<time>:<act>:<hash8 member id>` (replay idempotent), `source='capture'`, `payload_json = {"sys":"group","act","actor","members":[ids]}` chỉ chứa id. `participants.role`: 0 thành viên, 1 phó nhóm. Số thành viên ở màn Lưu trữ lấy nguồn LỚN NHẤT trong `participants`/`members_json`/`totalMember` (vì `participants` chỉ có từng phần từ sự kiện).

## 3. Thành phần as-built (đường dẫn ngắn; chi tiết trong audit handoff §3)

| Thành phần | File | Trạng thái 19-Nov |
|-----------|------|-------------------|
| DPAPI + SQLCipher open | `src/migrate/sqlcipher.rs` | ✅ live (mở DB thật) |
| WS/REST decode | `src/shadow/wire.rs` | ✅ live (WS key armed; REST key armed) |
| Envelope → domain rows | `src/shadow/normalize.rs` | ✅ golden 68/68 |
| Upsert + guards | `src/shadow/writer.rs` | ✅ tests |
| Batching (200ms/500) | `src/shadow/pipeline.rs` | ✅ live |
| Flusher + keys RAM | `src/shadow/runtime.rs` | ✅ live |
| CDP capture | `src/shadow/capture.rs` | ✅ live |
| Bridge taps (E2EE + handshake + inventory) | `resources/bridge.js` §0b | ✅ live (4 tin E2EE thật) |
| IPC commands + ACL | `src/commands.rs`, `capabilities/`, `permissions/` | ✅ live |
| Media downloader | `src/shadow/media.rs` | ✅ armed, chờ file đầu |
| Import CLI skeleton | `src/shadow/{cli,import}.rs` | ⏳ fail-closed, `--apply` chưa wire |
| Lưu trữ UI (P3) | — | ❌ chưa bắt đầu |
| Backup (P4) | — | ❌ chưa bắt đầu |
| Probes/oracle | `src/shadow/{golden,probe_*}.rs` | ✅ giữ làm regression gate |

## 4. Thứ tự phase — CHỐT LẠI bởi user (2026-11-19)

> D17 giữ nguyên + user khẳng định lại: **P3 là "bước sau", P4 là "sau cùng".**

| Phase | Nội dung | Acceptance criteria (runtime) |
|-------|----------|-------------------------------|
| **0 — done** | Capture core + verify | golden 68/68; E2EE plaintext=4 live; 218 tests |
| **1 — đang chạy** | Soak 24h + P1b hoàn tất: E2EE photo mapping (KQ1), own-uid (KQ2), chứng minh 1 file media thật land (V8) | probe_e2ee không mất event sau 24h; `D:\ZaloRust Data` có ≥1 file sha256; attachments ≥1 downloaded |
| **2 (P2)** | Import Desktop: cold snapshot (user thoát Zalo Desktop) → verify key D7 mở Index.db (93 tables) → map schema 93 bảng + `g*.db` → `--dry-run` 0-ghi (mtime) → `--apply` → media hardlink → re-import delta (D16) | ≥99% msg_id khớp nguồn trên 20 hội thoại mẫu; dry-run 0 ghi; import idempotent |
| **3 (P3)** | **Màn hình Lưu trữ riêng** (native window + FTS5) — *user: "bước sau"* | xem được lịch sử shadow + search FTS5 <1s trên 100k msgs |
| **4 (P4)** | **Backup + cảnh báo dung lượng** — *user: "sau cùng"* | backup/restore integrity ok, counts khớp manifest, kill giữa ghi không corrupt |

## 5. Non-goals / giới hạn cố ý (đừng "fix" khi chưa có quyết định)

- ❌ KHÔNG inject dữ liệu lưu trữ vào web UI (A1/A4).
- ❌ KHÔNG tự giải Signal/E2EE — chỉ tap plaintext page đã decrypt.
- ❌ KHÔNG backfill chủ động lịch sử server (D14: chỉ catch-up khi user cuộn).
- ❌ KHÔNG multi-account (D18) đến khi có nhu cầu thật.
- ❌ KHÔNG lưu plaintext key/cookie ở bất kỳ đâu ngoài RAM (A6).
- ⚠️ DPAPI no-entropy là legacy-compat có chủ đích (hardening: re-wrap có entropy + migration 1 lần — cần quyết định mới).

## 6. Lệnh verify nhanh (regression gate mỗi phiên)

```powershell
$env:PATH = "$env:LOCALAPPDATA\Temp\opencode\strawberry-perl\perl\bin;$env:LOCALAPPDATA\Temp\opencode\strawberry-perl\c\bin;$env:USERPROFILE\.cargo\bin;$env:PATH"
Set-Location D:\ZaloRust\src-tauri
cargo test --lib                                         # ~218+ pass, 0 fail
cargo test --lib golden_replay -- --ignored --nocapture  # GOLDEN: PASS 68/68 (known-diffs ≤2/≤2)
cargo test --lib probe_e2ee   -- --ignored --nocapture   # counts phải TĂNG khi soak
```
