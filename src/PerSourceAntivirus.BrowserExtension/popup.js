// popup.js — runs in the popup context (not the service worker)

const agentDot    = document.getElementById("agentDot");
const agentStatus = document.getElementById("agentStatus");
const urlBox      = document.getElementById("currentUrl");
const checkBtn    = document.getElementById("checkBtn");
const dashBtn     = document.getElementById("openDashboard");

function setAgentStatus(connected) {
  if (connected) {
    agentDot.classList.add("ok");
    agentStatus.textContent = "Agente conectado";
  } else {
    agentDot.classList.remove("ok");
    agentStatus.textContent = "Agente desconectado";
  }
}

// Get current tab URL and show it
chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  const tab = tabs[0];
  const url = tab?.url ?? "";
  urlBox.textContent = url.length > 60 ? url.slice(0, 57) + "..." : url;
  urlBox.title = url;

  // Check connection status
  chrome.runtime.sendMessage({ type: "get_status" }, res => {
    if (chrome.runtime.lastError) { setAgentStatus(false); return; }
    setAgentStatus(res?.connected ?? false);
  });

  checkBtn.addEventListener("click", () => {
    if (!url || !url.startsWith("http")) return;
    checkBtn.textContent = "Verificando...";
    checkBtn.disabled = true;
    chrome.runtime.sendMessage({ type: "check_url", url }, response => {
      checkBtn.disabled = false;
      if (chrome.runtime.lastError || !response) {
        checkBtn.textContent = "Erro na verificacao";
        return;
      }
      if (response.blocked) {
        checkBtn.textContent = "URL BLOQUEADA";
        checkBtn.style.background = "#c0392b";
        agentStatus.textContent = "Ameaca: " + (response.reason ?? "URL maliciosa");
      } else {
        checkBtn.textContent = "URL segura";
        checkBtn.style.background = "#27ae60";
        setTimeout(() => {
          checkBtn.textContent = "Verificar URL Atual";
          checkBtn.style.background = "";
        }, 2000);
      }
    });
  });
});

dashBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: "http://localhost:5000" });
});
