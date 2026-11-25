# Third-party notices

## zca-js (MIT)

Source: https://github.com/RFS-ADRENO/zca-js (v2.4.0), read only; its code is not copied into this repository and is never run.

Ported to Rust in batch 30: the WS `encrypt=3` frame layout, the reaction / group-event / friend-event / receipt wire shapes and act vocabularies (`listen.ts`, `Reaction.ts`, `GroupEvent.ts`, `getGroupEventType`, `getFriendEventType`), the numeric client message type table (`getClientMessageType`), the `getLoginInfo` response key derivation and AES-256-CBC decryption (`ParamsEncryptor.createEncryptKey`, `decryptResp`), and the response field names of the friend / group / member / mini-profile / avatar endpoints.

Each ported table or algorithm carries the comment `// Ported from zca-js <path> (MIT, (c) RFS-ADRENO and contributors)` in the source.

### License text

```text
MIT License

Copyright (c) 2024 - 2025 RFS-ADRENO, truong9c2208, JustKemForFun

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
