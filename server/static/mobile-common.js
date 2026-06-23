function mobileEsc(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function mobileFetchSession() {
  const resp = await fetch("/api/v1/session", { credentials: "same-origin" });
  if (!resp.ok) {
    throw new Error("HTTP " + resp.status);
  }
  return resp.json();
}

async function mobileLogin(username, password) {
  const resp = await fetch("/api/v1/mobile-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(String(data.error || "Login fehlgeschlagen"));
  }
  return data;
}

async function mobileLogout() {
  await fetch("/api/v1/web-logout", {
    method: "POST",
    credentials: "same-origin",
  }).catch(() => {});
}

function mobileEnvironmentLabel(value) {
  const env = String(value || "").trim().toLowerCase();
  if (env === "prod") return "Prod.";
  if (env === "test") return "Test";
  return "";
}

function mobileRedirectAfterLogin() {
  const params = new URLSearchParams(window.location.search);
  const alertId = params.get("alert_id");
  if (alertId) {
    return "/mobile/alerts?alert_id=" + encodeURIComponent(alertId);
  }
  return "/mobile/alerts";
}
