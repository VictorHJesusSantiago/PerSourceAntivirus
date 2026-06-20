// Content script — injected into every page at document_start
// Checks the current URL via the background service worker and shows a warning banner if flagged
(function () {
  if (window.top !== window) return; // main frame only

  const url = location.href;
  if (!url.startsWith("http")) return;

  chrome.runtime.sendMessage({ type: "check_url", url }, response => {
    if (chrome.runtime.lastError) return;
    if (response && response.blocked) {
      showBlockedBanner(response.reason);
    }
  });

  function showBlockedBanner(reason) {
    const banner = document.createElement("div");
    banner.style.cssText = [
      "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
      "background:#c0392b", "color:#fff", "font:bold 14px/1 sans-serif",
      "padding:10px 16px", "display:flex", "align-items:center", "gap:12px",
      "box-shadow:0 2px 6px rgba(0,0,0,.4)"
    ].join(";");

    const msg = document.createElement("span");
    msg.textContent = "⚠️ PerSource Antivirus bloqueou esta página" +
      (reason ? ": " + reason : ".");
    msg.style.flex = "1";

    const btn = document.createElement("button");
    btn.textContent = "Prosseguir mesmo assim";
    btn.style.cssText = "background:#fff;color:#c0392b;border:none;padding:4px 10px;cursor:pointer;border-radius:3px;font-size:12px";
    btn.onclick = () => banner.remove();

    banner.appendChild(msg);
    banner.appendChild(btn);

    const attach = () => document.body
      ? document.body.insertBefore(banner, document.body.firstChild)
      : document.documentElement.appendChild(banner);

    if (document.body) attach();
    else document.addEventListener("DOMContentLoaded", attach, { once: true });
  }
})();
