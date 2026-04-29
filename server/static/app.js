async function loadReports() {
  const body = document.getElementById("reportRows");
  body.innerHTML = "<tr><td colspan=\"4\">Lade Daten...</td></tr>";

  try {
    const response = await fetch("/api/v1/latest?limit=50");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const reports = data.reports || [];

    if (reports.length === 0) {
      body.innerHTML = "<tr><td colspan=\"4\">Noch keine Daten vorhanden.</td></tr>";
      return;
    }

    body.innerHTML = "";
    for (const report of reports) {
      const filesystems = (report.payload.filesystems || [])
        .map((fs) => `${fs.mountpoint}: ${fs.used_percent}%`)
        .join(" | ");

      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${report.received_at_utc}</td>
        <td>${report.hostname || ""}</td>
        <td>${report.primary_ip || ""}</td>
        <td>${filesystems}</td>
      `;
      body.appendChild(row);
    }
  } catch (error) {
    body.innerHTML = `<tr><td colspan=\"4\">Fehler: ${error.message}</td></tr>`;
  }
}

document.getElementById("refreshButton").addEventListener("click", loadReports);
loadReports();
