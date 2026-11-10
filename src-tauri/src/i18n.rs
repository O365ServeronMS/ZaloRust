//! User-interface language: Vietnamese (default) or English. Every user-visible
//! string in the code is written in Portuguese, which is only the lookup key
//! (the original project's source language) and is never shown on purpose: `tr`
//! maps it to English through `EN_TABLE`, and to Vietnamese through
//! `settings-ui/vi.json`, which is keyed by the English text. A string with no
//! entry falls back to English, then to the key, so a missing translation can
//! never blank the UI (`every_literal_has_an_english_entry` and
//! `every_english_text_has_a_vietnamese_entry` fail the tests instead).
//!
//! The language lives in `settings.json` (`language`); `set` mirrors it into a
//! process-wide atomic so lookups never touch the disk.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Vi,
    En,
}

pub const VI: &str = "vi";
pub const EN: &str = "en";

impl Lang {
    /// `en`, `en-US`, `en_GB.UTF-8`... mean English; anything else, including an
    /// empty code or the retired `pt-BR`, means Vietnamese.
    pub fn from_code(code: &str) -> Lang {
        let code = code.trim().to_ascii_lowercase();
        if code == "en" || code.starts_with("en-") || code.starts_with("en_") {
            Lang::En
        } else {
            Lang::Vi
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::Vi => VI,
            Lang::En => EN,
        }
    }
}

/// Normalise any stored value to one of the supported codes.
pub fn sanitize_code(code: &str) -> String {
    Lang::from_code(code).code().to_string()
}

/// Default for a fresh install or a settings.json written before the language
/// setting existed: Vietnamese.
pub fn system_default() -> &'static str {
    VI
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set(lang: Lang) {
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

pub fn current() -> Lang {
    if CURRENT.load(Ordering::Relaxed) == Lang::En as u8 {
        Lang::En
    } else {
        Lang::Vi
    }
}

fn english(s: &str) -> Option<&'static str> {
    EN_TABLE.iter().find(|(pt, _)| *pt == s).map(|(_, en)| *en)
}

/// Vietnamese text for an English one (`settings-ui/vi.json`, shared with the pages).
fn vietnamese(en: &str) -> Option<&'static str> {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static VI_TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    VI_TABLE
        .get_or_init(|| {
            serde_json::from_str(include_str!("../../settings-ui/vi.json")).unwrap_or_default()
        })
        .get(en)
        .map(String::as_str)
}

/// Translate a Portuguese source string into the current language.
pub fn tr(s: &str) -> Cow<'_, str> {
    tr_in(current(), s)
}

pub fn tr_in(lang: Lang, s: &str) -> Cow<'_, str> {
    match lang {
        Lang::En => english(s).map_or(Cow::Borrowed(s), Cow::Borrowed),
        Lang::Vi => match english(s) {
            Some(en) => vietnamese(en).map_or(Cow::Borrowed(en), Cow::Borrowed),
            None => Cow::Borrowed(s),
        },
    }
}

/// Translate a pattern containing `{0}`, `{1}`... placeholders, then fill them.
pub fn trf(pattern: &str, args: &[&dyn std::fmt::Display]) -> String {
    trf_in(current(), pattern, args)
}

pub fn trf_in(lang: Lang, pattern: &str, args: &[&dyn std::fmt::Display]) -> String {
    let mut out = tr_in(lang, pattern).into_owned();
    for (i, a) in args.iter().enumerate() {
        out = out.replace(&format!("{{{i}}}"), &a.to_string());
    }
    out
}

/// Re-apply the language everywhere it is already on screen: open pages, the
/// tray menu and tooltip, the native window menus and the settings title.
pub fn refresh(app: &tauri::AppHandle) {
    use tauri::Manager;
    for (_, wv) in app.webviews() {
        let _ = wv.eval(switch_script());
    }
    if let Some(w) = app.get_webview_window("settings") {
        let _ = w.set_title(&tr("Zalo — Configurações"));
    }
    crate::tray::rebuild_menu(app);
    let total = app
        .try_state::<crate::accounts::UnreadMap>()
        .map(|m| crate::accounts::aggregate_unread(&crate::lock::guard(&m)))
        .unwrap_or(0);
    crate::tray::update_badge(app, total);
    #[cfg(windows)]
    crate::sessions::refresh_menus(app);
}

/// Script run in every local page before its own scripts: tells `i18n.js` the
/// language to start in.
pub fn init_script() -> String {
    format!("window.__WR_LANG={:?};", current().code())
}

/// Script that switches an already-open page.
pub fn switch_script() -> String {
    format!(
        "window.__WR_LANG={:?};window.I18n&&I18n.setLang({:?});window.__wrRelang&&window.__wrRelang();",
        current().code(),
        current().code()
    )
}

/// English text for each Portuguese source string. Placeholders are `{0}`, `{1}`.
static EN_TABLE: &[(&str, &str)] = &[
    // download folder and app icon
    ("A pasta não existe.", "The folder does not exist."),
    ("Não é possível gravar nessa pasta.", "That folder is not writable."),
    ("Pasta de downloads", "Download folder"),
    ("Ícone do aplicativo", "App icon"),
    ("A imagem tem mais de 5 MB.", "The image is larger than 5 MB."),
    ("O arquivo não é uma imagem PNG.", "The file is not a PNG image."),
    ("A imagem precisa ser quadrada.", "The image must be square."),
    ("A imagem é grande demais (máximo {0} px).", "The image is too large (maximum {0} px)."),
    ("A imagem é pequena demais (mínimo {0} px).", "The image is too small (minimum {0} px)."),
    ("Não foi possível ler a imagem PNG.", "The PNG image could not be read."),
    // accounts
    ("Não é possível remover a última conta.", "The last account cannot be removed."),
    ("Conta não encontrada: {0}", "Account not found: {0}"),
    ("Conta não encontrada", "Account not found"),
    ("A ordem deve conter todas as contas uma única vez", "The order must contain every account exactly once"),
    ("Conta não está aberta", "The account is not open"),
    ("{0}; e não foi possível restaurar a conta: {1}", "{0}; and the account could not be restored: {1}"),
    // lock / password
    ("As senhas não coincidem.", "The passwords do not match."),
    ("A senha deve ter pelo menos {0} caracteres.", "The password must be at least {0} characters long."),
    ("O bloqueio já está ativado.", "The lock is already on."),
    ("O bloqueio não está ativado.", "The lock is not on."),
    ("A senha atual está incorreta.", "The current password is incorrect."),
    ("Defina uma senha de bloqueio primeiro.", "Set a lock password first."),
    ("A autenticação biométrica não está disponível neste dispositivo.", "Biometric authentication is not available on this device."),
    ("Ativar desbloqueio por biometria no Zalo", "Turn on biometric unlock in Zalo"),
    ("Desbloquear o Zalo", "Unlock Zalo"),
    ("Não foi possível confirmar a biometria.", "Biometrics could not be confirmed."),
    ("O desbloqueio por biometria não está ativado.", "Biometric unlock is not on."),
    ("O tempo para confirmar a biometria terminou.", "Time to confirm biometrics ran out."),
    ("A redefinição precisa ser confirmada.", "The reset must be confirmed."),
    ("Endereço do proxy inválido. Use um nome de host ou um endereço IP, sem http://, usuário ou senha.", "Invalid proxy address. Use a host name or an IP address, without http://, user name or password."),
    ("Tipo de proxy inválido.", "Invalid proxy type."),
    ("A porta do proxy deve estar entre 1 e 65535.", "The proxy port must be between 1 and 65535."),
    ("Endereço do proxy inválido.", "Invalid proxy address."),
    ("O proxy exige macOS 14 (Sonoma) ou superior. Desative o proxy nas configurações.", "The proxy needs macOS 14 (Sonoma) or later. Turn the proxy off in settings."),
    ("O proxy exige macOS 14 (Sonoma) ou superior.", "The proxy needs macOS 14 (Sonoma) or later."),
    ("Não foi possível concluir a redefinição. Feche outras instâncias do Zalo e tente novamente.", "The reset could not be completed. Close other instances of Zalo and try again."),
    ("Zalo — Bloqueado", "Zalo — Locked"),
    // downloads / files
    ("Download não encontrado", "Download not found"),
    ("Download concluído", "Download complete"),
    ("Falha no download", "Download failed"),
    ("A senha precisa ter pelo menos {0} caracteres.", "The password must be at least {0} characters."),
    ("Este arquivo não é um backup do Zalo.", "This file is not a Zalo backup."),
    ("Senha incorreta ou arquivo corrompido.", "Wrong password or corrupted file."),
    ("O backup contém uma lista de contas inválida.", "The backup contains an invalid account list."),
    ("Backup de uma versão mais nova do Zalo.", "Backup from a newer version of Zalo."),
    ("Exportar backup", "Export backup"),
    ("Importar backup", "Import backup"),
    ("Todos os arquivos", "All files"),
    ("Salvar arquivo", "Save file"),
    ("{0} — salvo no local escolhido.", "{0} — saved to the chosen location."),
    ("Arquivo salvo no local escolhido.", "File saved to the chosen location."),
    ("Não foi possível baixar o arquivo. Tente novamente.", "The file could not be downloaded. Try again."),
    ("Não foi possível abrir o link", "Could not open the link"),
    ("Não foi possível iniciar o navegador. Copie o link e abra-o no navegador.", "Could not start the browser. Copy the link and open it in your browser."),
    ("Não foi possível abrir o arquivo", "Could not open the file"),
    ("Abra o arquivo pela pasta em que ele foi salvo.", "Open the file from the folder where it was saved."),
    // drag and drop
    ("Nenhum arquivo foi anexado", "No file was attached"),
    ("Não é possível arrastar esse item diretamente. Arraste o arquivo pelo Explorador de Arquivos ou use o botão de anexo (+).", "This item cannot be dragged directly. Drag the file from File Explorer or use the attach button (+)."),
    ("Arquivos não anexados", "Files not attached"),
    ("Não foi possível processar os arquivos. Tente novamente.", "The files could not be processed. Try again."),
    ("Não foi possível enviar os arquivos ao Zalo. Tente novamente.", "The files could not be sent to Zalo. Try again."),
    ("O Zalo ainda não estava pronto para receber os arquivos. Tente novamente.", "Zalo was not ready to receive the files. Try again."),
    ("Alguns arquivos não foram anexados", "Some files were not attached"),
    ("arquivo", "file"),
    ("arquivos", "files"),
    ("{0} {1} acima do limite de 500 MB", "{0} {1} over the 500 MB limit"),
    ("{0} {1} acima do total de 500 MB por envio", "{0} {1} over the 500 MB total per upload"),
    ("{0} {1} acima do limite de 200 arquivos", "{0} {1} over the limit of 200 files"),
    ("pastas ou arquivos especiais: {0}", "folders or special files: {0}"),
    ("{0} {1} sem permissão de leitura", "{0} {1} without read permission"),
    ("{0} {1} alterados durante a leitura", "{0} {1} changed while reading"),
    ("Não anexados: {0}.", "Not attached: {0}."),
    // notifications
    ("Nova mensagem", "New message"),
    ("Você tem uma nova mensagem.", "You have a new message."),
    ("Você tem novas mensagens em {0} conversas.", "You have new messages in {0} chats."),
    ("Você recebeu uma mensagem no Zalo.", "You received a message on Zalo."),
    ("Teste do Zalo", "Zalo test"),
    ("Se você está vendo este aviso, o Windows exibiu o teste.", "If you can see this notice, Windows displayed the test."),
    ("Ative as notificações antes do teste.", "Turn on notifications before the test."),
    ("Teste solicitado. Confira o banner e a central do Windows; aceitação não confirma exibição.", "Test requested. Check the banner and the Windows notification center; acceptance does not confirm it was shown."),
    ("Não foi possível abrir as configurações do Windows", "Could not open the Windows settings"),
    ("Disponível no Windows", "Available on Windows"),
    // settings side effects
    ("Não foi possível atualizar a inicialização automática: {0}", "Could not update automatic startup: {0}"),
    ("Não foi possível registrar o atalho (ele pode estar em uso): {0}", "Could not register the shortcut (it may be in use): {0}"),
    ("O atalho para desfocar não pode ser igual ao atalho de mostrar/ocultar: {0}", "The blur shortcut can't be the same as the show/hide shortcut: {0}"),
    // tray and menus
    ("Contas…", "Accounts…"),
    ("Contas", "Accounts"),
    ("Configurações", "Settings"),
    ("Recarregar", "Reload"),
    ("Sair", "Quit"),
    ("Bloquear agora", "Lock now"),
    ("Bloquear", "Lock"),
    ("{0} conversas não lidas — Zalo", "{0} unread chats — Zalo"),
    ("Configurações do Zalo", "Zalo settings"),
    ("Voltar ao Zalo", "Back to Zalo"),
    ("Recarregar conta", "Reload account"),
    ("Sair do Zalo", "Quit Zalo"),
    // updates
    ("Instalador do Windows (NSIS)", "Windows installer (NSIS)"),
    ("Instalador do Windows (MSI)", "Windows installer (MSI)"),
    ("Aplicativo do macOS", "macOS app"),
    ("Compilado do código-fonte", "Built from source"),
    ("Outro tipo de instalação", "Other install type"),
    ("Compilado do código-fonte: atualize o código e compile de novo, ou instale uma versão publicada.", "Built from source: pull the latest code and rebuild, or install a published release."),
    ("Esta instalação não pode ser atualizada pelo Zalo. Baixe a nova versão na página de lançamentos ou use o gerenciador de pacotes.", "Zalo cannot update this installation. Download the new version from the releases page or use your package manager."),
    ("Proxy inválido: {0}", "Invalid proxy: {0}"),
    ("Falha de rede: {0}", "Network error: {0}"),
    (
        "Não foi possível acessar as versões publicadas (HTTP {0}). O repositório pode ser privado.",
        "Cannot reach the published releases (HTTP {0}). The repository may be private.",
    ),
    ("Resposta inesperada do GitHub: {0}", "Unexpected answer from GitHub: {0}"),
    ("Nenhuma versão publicada encontrada.", "No published release found."),
    ("Download interrompido: {0}", "Download interrupted: {0}"),
    ("Download incompleto ({0} de {1} bytes).", "Download incomplete ({0} of {1} bytes)."),
    ("Esta versão não tem o arquivo SHA256SUMS; nada foi alterado.", "This release has no SHA256SUMS file; nothing was changed."),
    ("O SHA256SUMS não lista {0}; nada foi alterado.", "SHA256SUMS does not list {0}; nothing was changed."),
    ("Esta versão não tem um arquivo para o seu tipo de instalação ({0}).", "This release has no file for your install type ({0})."),
    ("Caminho do AppImage inválido.", "Invalid AppImage path."),
    ("Caminho do aplicativo inválido.", "Invalid app path."),
    ("O endereço do arquivo não pertence às versões oficiais do Zalo.", "The file address is not one of the official Zalo releases."),
    ("Não foi possível criar uma pasta temporária: {0}", "Could not create a temporary folder: {0}"),
    ("{0} está danificado (a soma de verificação não confere); nada foi alterado.", "{0} is damaged (the checksum does not match); nothing was changed."),
    ("Não foi possível substituir {0}: {1}", "Could not replace {0}: {1}"),
    ("Não foi possível instalar a nova versão: {0}{1}", "Could not install the new version: {0}{1}"),
    ("Não foi possível descompactar a atualização.", "Could not unpack the update."),
    ("A atualização não contém um aplicativo.", "The update does not contain an app."),
    ("A atualização não contém um aplicativo válido.", "The update does not contain a valid app."),
    ("A instalação foi cancelada.", "The installation was cancelled."),
    ("O dpkg não conseguiu instalar o pacote ({0}).", "dpkg could not install the package ({0})."),
    ("O pkexec não foi encontrado. O pacote verificado está em {0}; instale com: sudo dpkg -i {0}", "pkexec was not found. The verified package is at {0}; install it with: sudo dpkg -i {0}"),
    ("Não foi possível iniciar o instalador: {0}", "Could not start the installer: {0}"),
    ("Zalo {0} está disponível", "Zalo {0} is available"),
    ("Abra Configurações → Atualizações para ver as novidades e instalar.", "Open Settings → Updates to see what's new and install it."),
    ("Zalo {0} foi instalado", "Zalo {0} was installed"),
    ("Reinicie o Zalo para usar a nova versão (Configurações → Atualizações).", "Restart Zalo to use the new version (Settings → Updates)."),
    ("Zalo {0} está pronto para instalar", "Zalo {0} is ready to install"),
    ("Abra Configurações → Atualizações e clique em Reiniciar e instalar.", "Open Settings → Updates and click Restart and install."),
    ("Não há atualização instalada para reiniciar.", "There is no installed update to restart into."),
    ("Não foi possível reiniciar o Zalo. Abra-o manualmente.", "Could not restart Zalo. Please open it yourself."),
    ("Atualizar para {0}", "Update to {0}"),
    // window titles
    ("Zalo — Configurações", "Zalo — Settings"),
    ("Zalo — Conta destacada", "Zalo — Detached account"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vietnamese_translates_and_falls_back_to_the_key() {
        assert_eq!(tr_in(Lang::Vi, "Sair"), "Thoát");
        assert_eq!(tr_in(Lang::Vi, "texto sem tradução"), "texto sem tradução");
    }

    #[test]
    fn english_translates_and_falls_back() {
        assert_eq!(tr_in(Lang::En, "Sair"), "Quit");
        assert_eq!(tr_in(Lang::En, "texto sem tradução"), "texto sem tradução");
    }

    #[test]
    fn placeholders_are_filled_after_translation() {
        assert_eq!(
            trf_in(Lang::En, "Conta não encontrada: {0}", &[&"acct-1"]),
            "Account not found: acct-1"
        );
        assert_eq!(
            trf_in(Lang::Vi, "Conta não encontrada: {0}", &[&"acct-1"]),
            "Không tìm thấy tài khoản: acct-1"
        );
    }

    #[test]
    fn codes_round_trip_and_unknown_means_vietnamese() {
        assert_eq!(Lang::from_code("en"), Lang::En);
        assert_eq!(Lang::from_code("EN-us"), Lang::En);
        assert_eq!(Lang::from_code("en_US.UTF-8"), Lang::En);
        assert_eq!(Lang::from_code("vi"), Lang::Vi);
        assert_eq!(Lang::from_code("pt-BR"), Lang::Vi);
        assert_eq!(Lang::from_code("fr"), Lang::Vi);
        assert_eq!(Lang::from_code(""), Lang::Vi);
        assert_eq!(sanitize_code("zz"), VI);
        assert_eq!(sanitize_code("pt-BR"), VI);
        assert_eq!(sanitize_code("en"), EN);
    }

    #[test]
    fn every_english_text_has_a_vietnamese_entry() {
        for (pt, en) in EN_TABLE {
            let vi = vietnamese(en).unwrap_or_else(|| panic!("no Vietnamese for {en:?}"));
            for n in 0..4 {
                let ph = format!("{{{n}}}");
                assert_eq!(
                    en.contains(&ph),
                    vi.contains(&ph),
                    "placeholder {ph} in {pt}"
                );
            }
        }
    }

    #[test]
    fn the_table_has_no_duplicate_keys_and_keeps_placeholders() {
        for (i, (pt, en)) in EN_TABLE.iter().enumerate() {
            assert!(
                EN_TABLE[i + 1..].iter().all(|(other, _)| other != pt),
                "duplicate key {pt}"
            );
            for n in 0..4 {
                let ph = format!("{{{n}}}");
                assert_eq!(
                    pt.contains(&ph),
                    en.contains(&ph),
                    "placeholder {ph} in {pt}"
                );
            }
        }
    }

    /// Every `tr("…")` / `trf("…", …)` literal in the sources must have an English
    /// entry, so adding a string without translating it fails here.
    #[test]
    fn every_literal_has_an_english_entry() {
        let sources = [
            include_str!("accounts.rs"),
            include_str!("applock.rs"),
            include_str!("backup.rs"),
            include_str!("commands.rs"),
            include_str!("integration.rs"),
            include_str!("lock.rs"),
            include_str!("notify.rs"),
            include_str!("opener.rs"),
            include_str!("sessions.rs"),
            include_str!("settings.rs"),
            include_str!("tray.rs"),
            include_str!("update_service.rs"),
            include_str!("updater.rs"),
            include_str!("window.rs"),
            include_str!("biometric/macos.rs"),
        ];
        let mut missing = Vec::new();
        let mut found = 0;
        for src in sources {
            let mut rest = src;
            while let Some(i) = [rest.find("tr(\""), rest.find("trf(\"")]
                .into_iter()
                .flatten()
                .min()
            {
                let after = &rest[i..];
                let start = after.find('"').unwrap() + 1;
                let body = &after[start..];
                // Skip escaped quotes.
                let mut end = 0;
                let bytes = body.as_bytes();
                while end < bytes.len()
                    && !(bytes[end] == b'"' && (end == 0 || bytes[end - 1] != b'\\'))
                {
                    end += 1;
                }
                let lit = body[..end].replace("\\u{2026}", "…").replace("\\\"", "\"");
                // Only standalone calls: `tr(`/`trf(` not part of a longer identifier.
                let before = rest[..i].chars().last().unwrap_or(' ');
                if !(before.is_alphanumeric() || before == '_') {
                    found += 1;
                    if english(&lit).is_none() {
                        missing.push(lit);
                    }
                }
                rest = &after[start + end..];
            }
        }
        assert!(found > 20, "scanner found only {found} literals");
        assert!(missing.is_empty(), "no English entry for: {missing:#?}");
    }
}
