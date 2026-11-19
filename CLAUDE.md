# CLAUDE.md

Toàn bộ quy tắc của dự án nằm trong AGENTS.md. Đọc và tuân theo file đó:

@AGENTS.md

## Bổ sung khi chạy trong Claude Code (kể cả khi model là GLM)

- **REA qua MCP:** server MCP `rea` đã được đăng ký ở cấp người dùng. Khi nghiên cứu Zalo desktop, gọi tool MCP
  của REA thay vì tự viết script giải nén `app.asar` hay tự gọi Ghidra. Nếu không thấy tool `rea`, khởi động lại
  Claude Code; vẫn không có thì dùng lệnh `rea` trong terminal (cùng chức năng).
- **Skill `reverse-engineer-anything`:** nạp skill này trước khi bắt đầu một phiên nghiên cứu bằng REA.
- **Hỏi người dùng** (không tự quyết) trước khi: gắn Frida vào tiến trình Zalo, cài thêm phần mềm,
  push / tag / mở PR, hoặc mở rộng quyền trong `src-tauri/capabilities/`.
- **Worktree:** nếu đang ở trong `.claude/worktrees/<tên>`, chạy mọi lệnh từ thư mục đó, không `cd` về gốc repo.
- Lệnh shell trên máy này: Windows, ưu tiên PowerShell. `cargo` ở `%USERPROFILE%\.cargo\bin`.
