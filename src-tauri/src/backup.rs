//! Encrypted export/import of the account list and settings.
//!
//! A backup carries `accounts.json`, `settings.json` (without the machine-bound
//! items: download folder and proxy) and the custom app icon. It does NOT carry
//! the login session: Chromium/WebView2 encrypts cookies with a key bound to the
//! Windows user and machine, so a copied profile would not sign in elsewhere.
//! After restoring on a new machine every account asks for the Zalo QR login again.
//!
//! File format: `ZRSBAK01` | salt(16) | nonce(12) | ChaCha20-Poly1305 ciphertext.
//! Key = Argon2id(passphrase, salt). The magic is authenticated as AAD.

use crate::accounts::AccountsFile;
use crate::settings::Settings;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::Aead, aead::Payload, ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 8] = b"ZRSBAK01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
pub const MIN_PASSPHRASE: usize = 8;
const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_ACCOUNTS: usize = 50;

#[derive(Serialize, Deserialize)]
pub struct BackupFile {
    pub format: u32,
    pub created: u64,
    pub accounts: AccountsFile,
    pub settings: Settings,
    /// Custom app icon PNG, base64.
    pub icon_png: Option<String>,
}

fn kdf(pass: &str, salt: &[u8], m_kib: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m_kib, 3, 1, Some(32)).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

const KDF_MEM_KIB: u32 = 64 * 1024;

pub fn encrypt(plain: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    encrypt_with(plain, pass, KDF_MEM_KIB)
}

fn encrypt_with(plain: &[u8], pass: &str, m_kib: u32) -> Result<Vec<u8>, String> {
    if pass.chars().count() < MIN_PASSPHRASE {
        return Err(crate::i18n::trf(
            "A senha precisa ter pelo menos {0} caracteres.",
            &[&MIN_PASSPHRASE],
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let key = kdf(pass, &salt, m_kib)?;
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: MAGIC,
            },
        )
        .map_err(|_| "encrypt".to_string())?;
    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(file: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    decrypt_with(file, pass, KDF_MEM_KIB)
}

fn decrypt_with(file: &[u8], pass: &str, m_kib: u32) -> Result<Vec<u8>, String> {
    use crate::i18n::tr;
    let head = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if file.len() <= head + 16 || &file[..MAGIC.len()] != MAGIC {
        return Err(tr("Este arquivo não é um backup do Zalo.").into_owned());
    }
    let salt = &file[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce = &file[MAGIC.len() + SALT_LEN..head];
    let key = kdf(pass, salt, m_kib)?;
    ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &file[head..],
                aad: MAGIC,
            },
        )
        .map_err(|_| tr("Senha incorreta ou arquivo corrompido.").into_owned())
}

/// Only ids this app itself generates: they become folder names under `profiles\`.
fn valid_id(id: &str) -> bool {
    id == "default"
        || id
            .strip_prefix("acct-")
            .is_some_and(|n| !n.is_empty() && n.len() <= 9 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Check and normalise an imported account list. Never trust a file that could
/// have been edited: ids are paths, names are shown in the UI.
pub fn validate_accounts(mut f: AccountsFile) -> Result<AccountsFile, String> {
    use crate::i18n::tr;
    let bad = || tr("O backup contém uma lista de contas inválida.").into_owned();
    if f.accounts.is_empty() || f.accounts.len() > MAX_ACCOUNTS {
        return Err(bad());
    }
    let mut seen = std::collections::HashSet::new();
    for a in &mut f.accounts {
        if !valid_id(&a.id) || !seen.insert(a.id.clone()) {
            return Err(bad());
        }
        a.name = a.name.trim().chars().take(60).collect();
        if a.name.is_empty() {
            a.name = a.id.clone();
        }
    }
    if let Some(s) = &f.startup_account {
        if !seen.contains(s) {
            f.startup_account = None;
        }
    }
    let max_seq = f
        .accounts
        .iter()
        .filter_map(|a| a.id.strip_prefix("acct-")?.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    f.next_seq = f.next_seq.max(max_seq.saturating_add(1)).max(1);
    Ok(f)
}

/// Settings from a backup, with the items that belong to this machine kept local.
pub fn merge_settings(imported: Settings, local: &Settings) -> Settings {
    let mut s = imported;
    s.download_dir = local.download_dir.clone();
    s.proxy_mode = local.proxy_mode.clone();
    s.proxy_host = local.proxy_host.clone();
    s.proxy_port = local.proxy_port;
    s.sanitized()
}

pub fn build(app: &tauri::AppHandle) -> Result<BackupFile, String> {
    let mut settings = crate::settings::load(app);
    settings.download_dir = None;
    settings.proxy_mode = crate::proxy::MODE_OFF.to_string();
    settings.proxy_host.clear();
    settings.proxy_port = 0;
    let icon_png = if settings.custom_icon {
        crate::appicon::custom_bytes(app).map(|b| B64.encode(b))
    } else {
        None
    };
    settings.custom_icon = icon_png.is_some();
    Ok(BackupFile {
        format: 1,
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        accounts: crate::accounts::load(app),
        settings,
        icon_png,
    })
}

pub fn export_bytes(app: &tauri::AppHandle, pass: &str) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(&build(app)?).map_err(|e| e.to_string())?;
    encrypt(&json, pass)
}

/// Decrypt, validate and apply. The caller restarts the app afterwards.
pub fn import_bytes(app: &tauri::AppHandle, file: &[u8], pass: &str) -> Result<(), String> {
    use crate::i18n::tr;
    if file.len() > MAX_FILE {
        return Err(tr("Este arquivo não é um backup do Zalo.").into_owned());
    }
    let plain = decrypt(file, pass)?;
    let p: BackupFile = serde_json::from_slice(&plain)
        .map_err(|_| tr("Este arquivo não é um backup do Zalo.").into_owned())?;
    if p.format != 1 {
        return Err(tr("Backup de uma versão mais nova do Zalo.").into_owned());
    }
    let accounts = validate_accounts(p.accounts)?;
    // Validate the icon before touching anything on disk.
    let icon = match p.icon_png {
        Some(b) => {
            let bytes = B64.decode(b).map_err(|e| e.to_string())?;
            crate::appicon::validate(&bytes)?;
            Some(bytes)
        }
        None => None,
    };
    let _guard = crate::accounts::lock_mutations();
    let local = crate::settings::load(app);
    let mut settings = merge_settings(p.settings, &local);
    match icon {
        Some(bytes) => {
            crate::appicon::set_custom(app, &bytes)?;
            settings.custom_icon = true;
        }
        None => {
            crate::appicon::clear_custom(app);
            settings.custom_icon = false;
        }
    }
    crate::accounts::save(app, &accounts).map_err(|e| e.to_string())?;
    crate::settings::save(app, &settings).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Account;

    // Small memory cost keeps the tests fast; production uses KDF_MEM_KIB.
    const M: u32 = 256;

    #[test]
    fn round_trip_and_wrong_password() {
        let ct = encrypt_with(b"hello", "correct horse", M).unwrap();
        assert_eq!(decrypt_with(&ct, "correct horse", M).unwrap(), b"hello");
        assert!(decrypt_with(&ct, "wrong password", M).is_err());
    }

    #[test]
    fn tampering_and_foreign_files_are_rejected() {
        let mut ct = encrypt_with(b"hello", "correct horse", M).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(decrypt_with(&ct, "correct horse", M).is_err());
        assert!(decrypt_with(b"not a backup at all, definitely not", "x", M).is_err());
        let mut hdr = encrypt_with(b"hello", "correct horse", M).unwrap();
        hdr[0] = b'X';
        assert!(decrypt_with(&hdr, "correct horse", M).is_err());
    }

    #[test]
    fn short_passwords_are_refused_and_each_file_is_unique() {
        assert!(encrypt_with(b"x", "short", M).is_err());
        let a = encrypt_with(b"x", "long enough pw", M).unwrap();
        let b = encrypt_with(b"x", "long enough pw", M).unwrap();
        assert_ne!(a, b);
    }

    fn acct(id: &str, name: &str) -> Account {
        Account {
            id: id.into(),
            name: name.into(),
            order: 0,
            store_uuid: None,
        }
    }

    #[test]
    fn account_ids_cannot_escape_the_profiles_folder() {
        for id in [
            "../x",
            "acct-",
            "acct-1/../..",
            "acct-a",
            "a\\b",
            "",
            "Default",
            "acct-12345678901",
        ] {
            let f = AccountsFile {
                accounts: vec![acct(id, "n")],
                next_seq: 1,
                startup_account: None,
            };
            assert!(validate_accounts(f).is_err(), "{id}");
        }
        let dup = AccountsFile {
            accounts: vec![acct("default", "a"), acct("default", "b")],
            next_seq: 1,
            startup_account: None,
        };
        assert!(validate_accounts(dup).is_err());
    }

    #[test]
    fn valid_accounts_are_normalised() {
        let f = AccountsFile {
            accounts: vec![acct("default", "  Zalo  "), acct("acct-7", "")],
            next_seq: 1,
            startup_account: Some("gone".into()),
        };
        let v = validate_accounts(f).unwrap();
        assert_eq!(v.accounts[0].name, "Zalo");
        assert_eq!(v.accounts[1].name, "acct-7");
        assert_eq!(v.startup_account, None);
        assert_eq!(v.next_seq, 8);
    }

    #[test]
    fn machine_bound_settings_stay_local() {
        let local = Settings {
            download_dir: Some("D:\\dl".into()),
            proxy_mode: "http".into(),
            proxy_host: "10.0.0.1".into(),
            proxy_port: 8080,
            ..Settings::default()
        };
        let imported = Settings {
            zoom: 1.25,
            ..Settings::default()
        };
        let m = merge_settings(imported, &local);
        assert_eq!(m.download_dir.as_deref(), Some("D:\\dl"));
        assert_eq!((m.proxy_mode.as_str(), m.proxy_port), ("http", 8080));
        assert_eq!(m.zoom, 1.25);
    }
}
