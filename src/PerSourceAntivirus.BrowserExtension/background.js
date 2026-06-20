// Native messaging host app ID — registered in Windows registry by the C# host installer
const NATIVE_HOST = "com.persource.antivirus";

let nativePort = null;
const checkCache = new Map(); // url -> { blocked, reason, ts }
const CACHE_TTL_MS = 60_000;

function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);
    nativePort.onMessage.addListener(onNativeMessage);
    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
      setTimeout(connectNative, 10_000);
    });
  } catch {
    setTimeout(connectNative, 10_000);
  }
}

function onNativeMessage(msg) {
  if (msg.type !== "check_url_result") return;
  const { url, blocked, reason } = msg;
  checkCache.set(url, { blocked, reason, ts: Date.now() });
  if (blocked) {
    chrome.tabs.query({}, tabs => {
      for (const tab of tabs) {
        if (tab.url && tab.url.startsWith(url)) {
          const blockedPage = chrome.runtime.getURL("blocked.html") +
            "?url=" + encodeURIComponent(url) +
            "&reason=" + encodeURIComponent(reason ?? "");
          chrome.tabs.update(tab.id, { url: blockedPage });
        }
      }
    });
  }
}

function getCached(url) {
  const entry = checkCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) { checkCache.delete(url); return null; }
  return entry;
}

function sendCheck(url) {
  if (nativePort) nativePort.postMessage({ type: "check_url", url });
}

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;
  const { url, tabId } = details;
  if (!url || !url.startsWith("http")) return;

  const cached = getCached(url);
  if (cached) {
    if (cached.blocked) {
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL("blocked.html") +
             "?url=" + encodeURIComponent(url) +
             "&reason=" + encodeURIComponent(cached.reason ?? "")
      });
    }
    return;
  }
  sendCheck(url);
}, { url: [{ schemes: ["http", "https"] }] });

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "check_url") {
    const cached = getCached(msg.url);
    sendResponse(cached ?? { blocked: false, reason: null });
    if (!cached) sendCheck(msg.url);
    return true;
  }
  if (msg.type === "get_status") {
    sendResponse({ connected: nativePort !== null });
    return true;
  }
});

connectNative();
