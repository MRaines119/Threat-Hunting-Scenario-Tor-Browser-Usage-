# Threat-Hunting-Scenario-Tor-Browser-Usage-
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat-Hunting-Scenario-Insider-Data-Staging-and-TOR-Exfiltration
- [Scenario Creation](https://docs.google.com/document/d/1Xd5RjqJfUFxJIgUX3sqeYuzR_MHY2Zt3vaVP7hjRFQA/edit?usp=drive_link)

## Platforms and Languages Leveraged
- Windows 10/11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- SIEM: Microsoft Sentinel (Advanced Hunting)
- Kusto Query Language (KQL)
- Tor Browser
- MITRE ATT&CK

## Scenario

Management suspects that a user may be staging sensitive company data and moving it off the network over the TOR network to evade the corporate web proxy and DLP inspection. Recent monitoring flagged encrypted traffic to known TOR entry nodes originating from a single endpoint, shortly after files with sensitive-looking names were grouped and archived on that host. The goal is to reconstruct the full activity chain — data collection, staging, TOR usage, and cleanup — confirm whether staging and TOR egress occurred on the same host and account, and notify management if insider exfiltration behavior is confirmed.

> **Note:** This is a lab exercise on an isolated Cyber Range VM. All "sensitive" files are dummy text files. TOR was used only to connect to the network — no dark-web sites were visited and no real data left the host.

### High-Level IoC Discovery Plan

- **Check `DeviceFileEvents`** for sensitive-named files being created and for archive (`.zip`/`.7z`/`.rar`) creation (data staging).
- **Check `DeviceProcessEvents`** for the TOR silent install (`/S`) and for `tor.exe` / `firefox.exe` execution.
- **Check `DeviceNetworkEvents`** for outbound connections over known TOR ports.
- **Correlate** staging and TOR egress to a single device and account.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| ------ | --------- | -- |
| Collection | Data from Local System | T1005 |
| Collection | Archive Collected Data | T1560.001 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |
| Command and Control | Encrypted Channel | T1573 |
| Command and Control | Multi-hop Proxy (TOR) | T1090.003 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table for Sensitive-Named Files

Searched for files containing sensitive keywords and discovered that the user `mjay` on device `mjaylabs-th` created three dummy sensitive files inside `C:\Users\mjay\Documents\hr-data\` — `payroll_export_Q3.txt`, `customer_ssn_list.txt`, and `confidential_contracts.txt` — between `2026-08-26 7:11 PM` and `7:12 PM`. This represents the collection stage: sensitive-named files grouped into a single working folder.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "mjaylabs-th"
| where FileName has_any ("payroll", "ssn", "confidential", "export", "customer")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessAccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1309" height="405" alt="image" src="https://github.com/user-attachments/assets/f238ce5e-ee0a-49be-8117-d1c174db8965" />


---

### 2. Searched the `DeviceProcessEvents` Table for TOR Silent Installation

Searched for a process command line containing `tor` and the silent-install switch `/S`. At `2026-08-25 3:39:49 PM`, the user `mjay` ran `tor-browser-windows-x86_64-portable-15.0.20.exe` with the `/S` flag, triggering a silent, no-prompt installation of the TOR Browser the day before the data-staging activity.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "mjaylabs-th"
| where ProcessCommandLine contains "tor" and ProcessCommandLine contains "/S"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
<img width="885" height="458" alt="image" src="https://github.com/user-attachments/assets/7e5b2782-e10a-4098-880d-60b4b468d9ed" />


---

### 3. Searched the `DeviceFileEvents` Table for Data Staging (Archives)

Searched for archive files created by a scripting/archiving tool. Two archives were created by `powershell.exe` under account `mjay` in `C:\Users\mjay\Documents\`: `hr-data.zip` at `2026-08-26 7:15 PM` (immediately after the sensitive files were collected) and `project_files.zip` at `7:34 PM` (a re-staged copy renamed to an innocuous name to disguise it).

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "mjaylabs-th"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| where InitiatingProcessFileName in~ ("powershell.exe", "7z.exe", "7zg.exe", "tar.exe", "WinRAR.exe")
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1270" height="346" alt="image" src="https://github.com/user-attachments/assets/549a6457-cbc6-4e5c-aff8-862ddd0bf3a8" />


---

### 4. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for evidence that the TOR browser was actually launched. Multiple `firefox.exe` `ProcessCreated` events (40 total) were returned, executing from the TOR Browser directory across both Aug 25 and Aug 26. An expanded record confirmed the binary was `firefox.exe` at `C:\Users\mjay\Desktop\Tor Browser\Browser\firefox.exe`, signed by Mozilla Corporation, spawned by parent process `explorer.exe` (interactive user launch), with SHA256 `d9bdc4a3b3af51dcf693d341f5280d7135b2c24e3ca682b259cd99c539e91c47`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "mjaylabs-th"
| where FileName in~ ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```
<img width="1282" height="442" alt="image" src="https://github.com/user-attachments/assets/bf6723ce-fdf3-4345-bb45-6f424bc1d8ea" />
<img width="1660" height="267" alt="image" src="https://github.com/user-attachments/assets/90b234b1-3ef4-421a-98e7-7fc5e9aeac2c" />

---

### 5. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for outbound connections initiated by `tor.exe` / `firefox.exe` on known TOR ports. Two distinct patterns confirmed live TOR usage: `firefox.exe` connecting to `127.0.0.1:9150` (the browser talking to its **local** TOR SOCKS proxy — loopback, not egress), and `tor.exe` connecting to external relay nodes `176.9.241.229:9001` and `188.213.94.245:9001` (the **actual anonymized egress** leaving the host, outside proxy/DLP inspection).

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "mjaylabs-th"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1172" height="425" alt="image" src="https://github.com/user-attachments/assets/abeb38e0-5b85-4a13-a916-b3bc282ba0e8" />

---

### 6. Correlated Staging and TOR Egress to a Single Host

Joined `DeviceFileEvents` (archive staging) with `DeviceNetworkEvents` (TOR egress) on `DeviceName`. The join confirmed that the same device `mjaylabs-th` and account `mjay` performed both the data staging (`project_files.zip`) and the TOR relay/SOCKS connections — the core conclusion of the hunt.

**Query used to locate events:**

```kql
let staging =
    DeviceFileEvents
    | where DeviceName == "mjaylabs-th"
    | where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
    | where InitiatingProcessFileName in~ ("powershell.exe", "7z.exe", "tar.exe")
    | project StageTime = Timestamp, DeviceName, ArchiveName = FileName,
              Account = InitiatingProcessAccountName;
let tor =
    DeviceNetworkEvents
    | where DeviceName == "mjaylabs-th"
    | where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
    | where RemotePort == 9001                            // relay egress only (drops 9150 loopback)
    | project TorTime = Timestamp, DeviceName, RemoteIP, RemotePort;
staging
| join kind=inner tor on DeviceName
| where TorTime between (StageTime - 1h .. StageTime + 1h) // bound the correlation window
| project DeviceName, Account, ArchiveName, StageTime, TorTime, RemoteIP, RemotePort
| order by StageTime desc
```
<img width="1090" height="551" alt="image" src="https://github.com/user-attachments/assets/e1d40955-2742-4354-9489-02786aa142bf" />


> **Analyst note:** The initial device-level join returned matches across two days because TOR was first exercised on Aug 25 (setup/testing) and the staging occurred Aug 26. The query above adds an explicit `±1h` time window and filters to `RemotePort == 9001` (true relay egress, excluding loopback SOCKS on 9150) to isolate the tight staging-to-egress pairing.

---

## Chronological Event Timeline

### 1. Process Execution — TOR Browser Silent Install
- **Timestamp:** `2026-08-25 3:39:49 PM`
- **Event:** User `mjay` executed `tor-browser-windows-x86_64-portable-15.0.20.exe` in silent mode.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.20.exe /S`

### 2. Process Execution — TOR Browser Launch
- **Timestamp:** `2026-08-25 3:41:05 PM`
- **Event:** User `mjay` launched the TOR Browser (`firefox.exe`), spawned by `explorer.exe` (interactive launch). `tor.exe` and additional `firefox.exe` processes followed.
- **Action:** Process creation detected.
- **File Path:** `C:\Users\mjay\Desktop\Tor Browser\Browser\firefox.exe`
- **SHA256:** `d9bdc4a3b3af51dcf693d341f5280d7135b2c24e3ca682b259cd99c539e91c47`

### 3. Network Connection — TOR Network (initial)
- **Timestamp:** `2026-08-25 3:42 PM` – `6:19 PM`
- **Event:** `tor.exe` established outbound connections to relay node `176.9.241.229` on port `9001`; `firefox.exe` connected to the local SOCKS proxy `127.0.0.1:9150`.
- **Action:** Connection success.

### 4. File Creation — Sensitive Data Collection
- **Timestamps:** `2026-08-26 7:11 PM` – `7:12 PM`
- **Event:** User `mjay` created `payroll_export_Q3.txt`, `customer_ssn_list.txt`, and `confidential_contracts.txt` in `C:\Users\mjay\Documents\hr-data\`.
- **Action:** File creation detected.

### 5. File Creation — Data Staging (Archive)
- **Timestamp:** `2026-08-26 7:15 PM`
- **Event:** `powershell.exe` compressed the `hr-data` folder into `hr-data.zip`.
- **Action:** File creation detected.
- **File Path:** `C:\Users\mjay\Documents\hr-data.zip`

### 6. Network Connection — TOR Network (staging day)
- **Timestamps:** `2026-08-26 7:28 PM` and `7:32 PM`
- **Event:** TOR Browser relaunched; `tor.exe` reconnected to relay `176.9.241.229:9001` and `firefox.exe` to `127.0.0.1:9150`, within the staging window.
- **Action:** Connection success.

### 7. File Creation — Disguised Re-Staged Archive
- **Timestamp:** `2026-08-26 7:34 PM`
- **Event:** `powershell.exe` created `project_files.zip` — a re-staged copy renamed to an innocuous name.
- **Action:** File creation detected.
- **File Path:** `C:\Users\mjay\Documents\project_files.zip`

### 8. Indicator Removal — Staging Folder Deleted (not logged)
- **Event:** The `hr-data` staging folder was removed via a recursive PowerShell delete. **No `FileDeleted` event was captured** in `DeviceFileEvents`.
- **Analysis:** MDE's file sensor logs `FileCreated`/`FileModified`/`FileRenamed` reliably, but `FileDeleted` coverage is inconsistent — particularly for recursive folder deletions. Indicator-removal evidence was therefore established from the reliable `FileCreated`/archive events plus the absence of source files at review time.

---

## Summary

The user `mjay` on device `mjaylabs-th` staged sensitive-named data and used a pre-installed TOR Browser to establish anonymized, encrypted egress that bypasses the corporate proxy and DLP. The user collected three sensitive-named files into `Documents\hr-data`, compressed them into `hr-data.zip`, and later produced a disguised copy `project_files.zip`. TOR Browser was silently installed (`/S`) on Aug 25 and launched interactively via `explorer.exe`; `tor.exe` established outbound relay connections on port `9001` to `176.9.241.229` and `188.213.94.245`, while `firefox.exe` used the local SOCKS proxy on `127.0.0.1:9150`. A correlation join confirmed that both the staging and the TOR egress originated from the same host and account. An attempt to delete the staging folder was not captured by MDE — a documented telemetry limitation that was worked around using reliably logged events.

---

## Response Taken

Insider data-staging and TOR egress were confirmed on endpoint `mjaylabs-th` by the user `mjay`. The device was isolated, the user's direct manager was notified, and the correlated hunt query was converted into a scheduled Microsoft Sentinel analytics rule (run hourly, `RemotePort == 9001` egress within ±1h of archive staging) so future occurrences generate an incident automatically. A follow-up recommendation was logged to validate the observed relay IPs against the public TOR consensus and to test single-file vs. recursive deletion logging to confirm the MDE telemetry boundary.

---
