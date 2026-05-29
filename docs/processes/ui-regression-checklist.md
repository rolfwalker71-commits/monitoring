# UI Regression Checklist (Monitoring Dashboard)

Ziel: Schneller, wiederholbarer Sicht- und Funktionscheck nach UI-Aenderungen.
Scope: Webclient Dashboard (Light/Dark, Sidebar, Header, Tabs, Filesystem, Kundeninfos).

## Preconditions

1. Webclient laeuft und Login erfolgreich.
2. Mindestens ein Host mit Daten ist sichtbar.
3. Browser-Cache wenn noetig neu laden.

## 10-Point Quick Check

1. Version sichtbar
- Erwartung: Header zeigt aktuelle Version konsistent.

2. Header/KPI-Hierarchie
- Erwartung: KPI-Chips sind lesbar, Alarmbezug visuell klarer als neutrale Chips.
- Erwartung: Keine Ueberlappung mit Schnellaktionen.

3. Schnellaktionen
- Aktion: Schnellaktions-Buttons anklicken (ohne destructive Actions).
- Erwartung: Keine Layoutspruenge oder abgeschnittene Inhalte.

4. Host-Schnellfilter (Suche)
- Aktion: Suchbegriff eingeben und wieder loeschen.
- Erwartung: Hostliste filtert und setzt sich sauber zurueck.

5. OS-/Land-Filter
- Aktion: OS/Land aktivieren und auf Alle zurueck.
- Erwartung: Filterzustand sichtbar, Liste reagiert korrekt, keine Darstellungsfehler.

6. Haupttabs
- Aktion: Zwischen Uebersicht und Einzelmeldungen wechseln.
- Erwartung: Kein Tab-State-Fehler, keine leeren/kaputten Bereiche.

7. Uebersicht-Subtabs
- Aktion: Alarme & Infos, Filesysteme, Kundeninfos durchschalten.
- Erwartung: Umschaltung stabil, visuelle Struktur konsistent.

8. Kundeninfos
- Aktion: Host auswaehlen, Kundeninfos aufrufen.
- Erwartung: Kundenname/Kunde-ID sichtbar wenn zugeordnet; Speichern-Button korrekt verfuegbar.

9. Filesysteme/Charts
- Aktion: Filesystem-Ansicht pruefen.
- Erwartung: Karten/Progress-Bars/Tabellen sind gut lesbar, keine Ueberlagerung.

10. Theme Toggle
- Aktion: Light <-> Dark umschalten.
- Erwartung: Kontrast bleibt lesbar, keine harten Schwarzflaechen, keine Layoutspruenge.

## Known Non-UI Signal

- Session refresh 404 in Console war historisch bekannt, wenn Frontend POST auf `/api/v1/session/refresh` sendet, aber Backend den POST-Pfad nicht anbietet.
- Nach Backend-Fix muss dieser Warnpfad verschwinden.

## Optional Deep Checks

1. Responsive Kurzcheck auf schmaler Breite.
2. Hostkarte mit vielen Meta-Daten pruefen (Flag, OS, Chips, Status).
3. Dark-Mode Fokuszustand von Inputs/Filterchips pruefen.

## Pass/Fail Rule

- PASS: Kein funktionaler Unterschied, nur visuelle Verbesserungen.
- FAIL: Tab/Filter/Host/Kundeninfos reagieren anders als zuvor oder Rendering bricht.
