fn main() {
    // An app permission manifest: every Zalo command gets `allow-<command>` /
    // `deny-<command>` permissions, and the files in `capabilities/` grant each
    // window exactly the commands it uses. Without it no capability could grant
    // a command to the remote Zalo page, and Tauri rejects every custom
    // command from a remote origin — which silently killed notifications and
    // the unread badge (issues #3, #32). See src/ipc_acl_tests.rs.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            // Zalo page (bridge.js)
            "integration_state",
            "report_integration",
            "report_message_signal",
            "open_app_panel",
            "close_app_panel",
            "detach_account",
            "attach_account",
            "reorder_accounts",
            "notification_diagnostics",
            "test_notification",
            "open_notification_settings",
            "notify",
            "set_unread",
            "dlog",
            "open_download",
            "reveal_download",
            "switcher_accounts",
            "switch_account",
            "zoom_step",
            // shadow DB bridge taps (resources/bridge.js §0b)
            "shadow_e2ee_message",
            "shadow_handshake",
            // settings window
            "get_settings",
            "set_settings",
            "restart_app",
            "open_settings",
            "pick_download_dir",
            "choose_app_icon",
            "reset_app_icon",
            "list_accounts",
            "add_account",
            "remove_account",
            "rename_account",
            "open_account",
            "set_default_account",
            "set_app_lock_password",
            "change_app_lock_password",
            "disable_app_lock",
            "set_app_lock_options",
            "set_biometric_enabled",
            "lock_app",
            "get_update_status",
            "check_for_updates",
            "install_update",
            "restart_to_update",
            "open_release_page",
            // settings window and lock screen
            "get_lock_status",
            // lock screen
            "unlock_password",
            "unlock_biometric",
            "reset_app_lock",
            // Lưu trữ (archive) window (audit §4 Phase 3 item 3.2)
            "archive_list_conversations",
            "archive_list_messages",
            "archive_search",
            "archive_open",
            // batch 29a: the Zalo-like archive window's read API + the two
            // user-initiated actions (open a link, save an attachment)
            "archive_conv_media",
            "archive_conv_media_counts",
            "archive_conv_info",
            "archive_open_link",
            "archive_save_attachment",
            // shadow DB passphrase mode (batch 18): settings window +
            // the shadow-unlock prompt
            "shadow_password_status",
            "shadow_set_password",
            "shadow_change_password",
            "shadow_remove_password",
            "shadow_set_remember",
            "shadow_unlock",
        ]),
    ))
    .expect("failed to run tauri-build");
}
