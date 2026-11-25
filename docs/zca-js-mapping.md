> Lô 30 (25/11/2026) đã triển khai: mục 1 (WS `encrypt=3`, reaction 610/611/612, sự kiện nhóm 601, phân loại 502/522/602/3000/`fr`/`transfer_sync2`, `getLoginInfo`, 5 normalizer REST, bảng `cliMsgType`) và mục 5 (ghi công). Chưa làm: mục 2 (đồng bộ điện thoại), mục 3 (đọc nhẹ chủ động), mục 4 các lô 31-33. Phần còn lại của tài liệu giữ nguyên như bản đã duyệt.

# zca-js → ZaloRust: áp dụng gì, ở đâu, theo thứ tự nào

Nguồn: [RFS-ADRENO/zca-js](https://github.com/RFS-ADRENO/zca-js) v2.4.0 (MIT, 23/11/2026). Commit `602ff32`, đã clone (chỉ đọc) vào `D:\.opencode\zca-js-v2.4.0`.

Phạm vi bạn đã chốt ngày 25/11:
- Giải mã thụ động: có.
- Đọc nhẹ: có, nhưng phải đi qua chính trang Zalo Web, có giới hạn tốc độ và có công tắc tắt.
- Lịch sử cũ: chỉ lấy qua lần đồng bộ từ điện thoại do bạn tự bấm.
- Gửi tin hoặc thao tác thay bạn: chưa làm, chỉ ghi lại kiến thức.
- Cách làm: port sang Rust, ghi công MIT, không chạy Node.

## 1. ZaloRust đang có gì và zca-js bổ sung được gì

| Mảng | zca-js (file) | ZaloRust hiện tại | Việc cần làm | Mức |
|---|---|---|---|---|
| Khung WS `[ver][cmd u16 LE][subCmd]` + `{data, encrypt}` | `apis/listen.ts`, `utils.ts decodeEventData` | Có (`wire.rs`) cho `encrypt` 0, 1, 2 | **Thêm `encrypt=3`**: AES-GCM, KHÔNG gzip. ZaloRust đang để nguyên data của loại này. | Thụ động |
| Tin nhắn `msgs`/`groupMsgs` (cmd 501/521, 510/511 trang cũ) | `models/Message.ts` | Có (`normalize.rs`); `uidFrom "0"` = mình đã đúng | Đối chiếu thêm các trường `quote`, `mentions`, `propertyExt`, `realMsgId` | Thụ động |
| **Reaction** (cmd 610/611/612: `reacts`/`reactGroups`) | `models/Reaction.ts` (bảng ~50 mã `rIcon`), `listen.ts` | Có biến thể `Write::Reaction` trong `mod.rs` nhưng **normalizer chưa bao giờ sinh ra**, nên bảng `reactions` đang rỗng | Giải mã `content.rMsg[].gMsgID` (tin bị thả), `rIcon`, `uidFrom`; `rIcon ""` = gỡ reaction | Thụ động |
| Thu hồi (undo) | `models/Undo.ts` (`content.globalMsgId`) | Có (họ recall, type 8) | Đối chiếu `globalMsgId` ↔ `realMsgId` | Thụ động |
| **Sự kiện nhóm** (cmd 601, `controls[].content.act_type="group"`) | `models/GroupEvent.ts`, `utils.getGroupEventType` (~22 loại) | Chưa có | Cập nhật tên nhóm, avatar (`avt`), thành viên (`updateMembers[].dName`, `avatar`) vào `groups`/`participants`/`contacts`. Đây là nguồn tên và avatar **miễn phí, không cần gọi API**. Tùy chọn: dòng hệ thống "A đã thêm B" | Thụ động |
| Sự kiện bạn bè (`act_type="fr"`) | `utils.getFriendEventType` | Chưa có | Chỉ đếm (thêm/xóa/chặn); có thể cập nhật contacts | Thụ động |
| Đã nhận / đã xem (cmd 502/522: `delivereds`, `seens`, `groupSeens`) | `models/DeliveredMessage.ts`, `SeenMessage.ts` | Chưa phân loại | Chỉ phân loại và đếm, không lưu. Giải thích được một phần "deliveredv2 opaque". | Thụ động |
| Đang gõ (602), đăng nhập trùng (3000), `file_done` | `listen.ts` | — | Bỏ qua có chủ đích; 3000 thì ghi log, chỉ đếm | Thụ động |
| **`getLoginInfo` đang lỗi `bad_padding`** | `utils.ParamsEncryptor` + `apis/login.ts` | Drain báo `bad_padding=1` | Khóa của response = `even(MD5(zcid_ext).upper())[0..8] + even(zcid)[0..12] + reverse(odd(zcid))[0..12]`, mà `zcid`, `zcid_ext` đều nằm **ngay trong URL request**. Rust giải được thụ động và lấy ra `uid` + `zpw_service_map_v3` (các host API). Mọi khóa chỉ nằm trong RAM (A6). | Thụ động |
| REST danh bạ, nhóm (Zalo Web tự gọi) | `getAllFriends` (`/api/social/friend/getfriends`), `getAllGroups` (`/api/group/getlg/v4`), `getGroupMembersInfo` (`/api/social/group/members`), `getMiniProfiles`, `getAvatarUrlProfile` | Đã có `getmg-v2`, `getprofiles` | Thêm normalizer cho 5 endpoint còn lại → `contacts`/`groups`/`participants` | Thụ động |
| Mã loại tin dạng số (`cliMsgType`: 1 text, 31 voice, 32 ảnh, 36 sticker, 37 doodle, 38 link, 43 vị trí, 44 video, 46 file, 49 gif) | `utils.getClientMessageType` | Chỉ có mã chuỗi | Bảng ánh xạ số → mã ZaloRust, cần cho dữ liệu đồng bộ (mục 2) và trích dẫn | Thụ động |
| **Đồng bộ từ điện thoại** (sync v2) | `sync/session.ts`, `proto.ts`, `zproto.ts`, `zstd.ts`, `apis/syncMessages.ts` | Chưa có | Xem mục 2: cần **thăm dò khả thi** trước | Thụ động, bạn bấm |
| Đọc nhẹ chủ động (tên/avatar còn thiếu) | `getMiniProfiles`, `getUserInfo` (`getprofiles/v2`), `getGroupInfo` (`getmg-v2`), tải ảnh avatar CDN | Chưa có | Xem mục 3 | Đọc nhẹ |
| Gửi tin, reaction, sửa nhóm… (~150 API) | `apis/send*.ts`, `addReaction.ts`, `undo.ts`… | — | **Chỉ ghi tài liệu**, không làm | — |

## 2. Đồng bộ từ điện thoại: zca-js cho biết gì và vì sao cần thăm dò

zca-js cho biết luồng như sau:
- Zalo Web gửi `cmd 590` (yêu cầu đồng bộ) kèm khóa công khai sinh bởi WASM `libzproto`.
- Điện thoại báo trạng thái qua `cmd 601`, `act_type="transfer_sync2"` (`transfer_status`, `upload_batch`), rồi tải các batch lên dưới dạng URL `msgUrl`.
- Mỗi file là nhiều chunk `[u32 LE len][chunk mã hóa]`. Chunk được giải mã bằng phiên kiểu Signal (identity key + ephemeral key nằm trong WASM), sau đó giải nén zstd và decode protobuf `Sync2.Conversation/Message.SyncChunk`. Schema đầy đủ có trong `proto.ts`.
- id trong dữ liệu đồng bộ là **id đã "noise"**. Zalo Web tự gọi `/api/gid/decrypt` (endpoint `profile`) để đổi sang uid/groupId thật. ZaloRust bắt được response đó một cách thụ động.

**Vướng mắc:** khóa giải mã nằm trong bộ nhớ WASM của trang. Kiến trúc ZaloRust cấm tự giải giao thức Signal/E2EE, chỉ cho phép lấy bản rõ mà trang đã tự giải. Có 2 hướng lấy bản rõ thụ động, cần thăm dò xem hướng nào được:
- **(a) Đọc IndexedDB của Zalo Web qua CDP (chỉ đọc)** sau khi đồng bộ xong, nếu Zalo Web lưu tin ở đó mà không mã hóa thêm.
- **(b) Bridge tap** tại điểm trang đã giải mã xong (sau zstd/protobuf), giống cách ZaloRust đang lấy bản rõ E2EE.

Phần đã chắc chắn dùng được ngay: bộ decode protobuf (port từ `proto.ts`), bảng `cliMsgType`, cơ chế đổi id qua `gid/decrypt`, và các mã trạng thái thiết bị (`SyncDeviceStatus` 1..10).

## 3. Đọc nhẹ qua trang Zalo Web (chủ động, có giới hạn)

- Đường đi: Rust mã hóa `params` bằng khóa REST đã có trong RAM (AES-CBC IV=0, giống `utils.encodeAES`), rồi nhờ trang gọi `fetch(url, {credentials:'include'})` qua CDP `Runtime.evaluate`. Response mã hóa trả về Rust giải. Cookie không rời trang, Rust không tự ký request.
- Host lấy từ `zpw_service_map_v3`, có được nhờ giải `getLoginInfo` (mục 1).
- Chỉ dùng: `getminiprofiles` (tên/avatar theo lô id), `getmg-v2` (thông tin nhóm), `group/members`, và tải ảnh avatar từ CDN vào kho media để màn Lưu trữ hiện avatar mà vẫn giữ nguyên CSP.
- Chỉ gọi cho những id **còn thiếu tên/avatar sau khi đã khai thác hết nguồn thụ động**.
- Giới hạn: mặc định ≤ 1 request / 3 giây, ≤ 300 request / ngày, theo lô 50 id, dừng ngay khi gặp lỗi lạ. Có công tắc trong Cài đặt.
- Việc này nới lỏng nguyên tắc A2 ("read-only với page"). Cần cập nhật `docs/shadow-architecture.md` bằng quyết định ngày 25/11.

## 4. Kế hoạch theo lô (giao Sonnet medium, mình review và chạy trên dữ liệu thật)

| Lô | Nội dung | Phụ thuộc |
|---|---|---|
| **29a** (đang chạy) | API Lưu trữ, đã bổ sung `uidFrom "0"` và bảng mã reaction | — |
| **30** | Giải mã thụ động: `encrypt=3`, reaction (610/611/612), sự kiện nhóm (601 → tên/avatar/thành viên), phân loại 502/522/602/3000, giải `getLoginInfo` (khóa từ `zcid`), normalizer cho `getfriends`/`getlg/v4`/`group/members`/`getminiprofiles`/`avatar-url`, bảng `cliMsgType`. Ghi công MIT. | 29a commit |
| **31** | Thăm dò đồng bộ điện thoại (chỉ đọc, chỉ đếm): khi bạn bấm đồng bộ, ghi nhận các frame 590/591/592/601, `gid/decrypt`, các request tải batch có nhìn thấy được không, và hướng (a) IndexedDB hay (b) tap có lấy được bản rõ không | 30 |
| **32** | Nạp dữ liệu đồng bộ: port decoder protobuf, đổi id noise, `source='sync'`, chống trùng với capture/import | kết quả 31 |
| **33** | Đọc nhẹ qua trang: bổ sung tên/avatar còn thiếu, cache avatar, công tắc, giới hạn tốc độ, cập nhật A2 | 30 |
| 29b | Giao diện kiểu Zalo, dùng thêm avatar và reaction từ 30/33 | 29a (tốt nhất sau 30) |

## 5. Ghi công

Mọi bảng hay thuật toán port từ zca-js đều ghi chú `// Port từ zca-js <file> (MIT, © RFS-ADRENO và cộng sự)`. Thêm mục "Third-party notices" trích nguyên văn LICENSE MIT của zca-js vào `docs/`.
