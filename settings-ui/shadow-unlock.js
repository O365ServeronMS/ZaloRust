// Shadow store unlock prompt (batch 18, brief R2): the app-lock
// window's shape, for the STORE password. One command,
// `shadow_unlock(password, remember)`; its capability lives in
// capabilities/shadow-unlock.json and Rust re-checks the label.
// Closing the window (the "skip" button / Escape) is allowed: the
// capture pipeline simply stays off until the next unlock.
const invoke = window.__TAURI__.core.invoke;
const pwd = document.getElementById("password");
const errEl = document.getElementById("error");
const remember = document.getElementById("remember");

let busy = false;

function skip() {
  // The window is undecorated; this is its only way out besides a
  // successful unlock. The pipeline stays off — nothing is lost except
  // the capture until the next unlock.
  window.__TAURI__.window.getCurrentWindow().close();
}

async function tryUnlock() {
  if (busy) return;
  const password = pwd.value;
  // Every user-visible string goes through t() (batch-18 review F5).
  if (!password) { errEl.textContent = t("Digite a senha."); return; }
  busy = true;
  document.getElementById("unlock").disabled = true;
  document.getElementById("skip").disabled = true;
  errEl.textContent = "";
  try {
    const ok = await invoke("shadow_unlock", { password, remember: remember.checked });
    if (!ok) {
      errEl.textContent = t("Senha incorreta. Tente novamente.");
      pwd.value = "";
      pwd.focus();
    }
    // On ok the Rust side closes this window after the reply lands.
  } catch (e) {
    const wait = /^throttled:(\d+)$/.exec(String(e));
    errEl.textContent = wait
      ? t("Muitas tentativas. Tente de novo em {0}s.", [wait[1]])
      : t("Não foi possível desbloquear. Tente novamente.");
  } finally {
    busy = false;
    document.getElementById("unlock").disabled = false;
    document.getElementById("skip").disabled = false;
  }
}

async function init() {
  document.getElementById("unlock").addEventListener("click", tryUnlock);
  pwd.addEventListener("keydown", (e) => { if (e.key === "Enter") tryUnlock(); });
  document.getElementById("skip").addEventListener("click", skip);
  window.addEventListener("keydown", (e) => { if (e.key === "Escape") skip(); });
  pwd.focus();
}

window.addEventListener("DOMContentLoaded", init);
