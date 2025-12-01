# Threat Hunt Project: Detected Unauthorized TOR Browser Usage

<img width="771" height="379" alt="image" src="https://github.com/user-attachments/assets/f759c11f-e9b4-4448-9f03-edc7496c94c1" />

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/shegufahaque/threat-hunting-scenario-TOR/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any files that had the string “tor” in it and discovered what looks like the user “she114” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` at `2025-11-13T21:51:11.5045679Z` on the desktop.These events began at `2025-11-13T19:00:00.4847273Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName has "threatHntV-SH"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-13T19:00:00.4847273Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1462" height="558" alt="image" src="https://github.com/user-attachments/assets/f90340d5-8d08-4a81-8046-75490ec4d028" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommandLine` that contains the string “tor-browser-windows-x86_64-portable-15.0.1.exe”. Based on the log returned at `2025-11-13T19:03:17.8761943Z`, on the device named "threathntv-sh", the user she114 quietly launched the Tor Browser portable installer from their Downloads folder, using a command that ran it silently in the background (/S), leaving no installation window or prompts visible.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName has "threatHntV-SH"
| where ProcessCommandLine has "tor-browser-windows-x86_64-portable-15.0.1.exe"
| project Timestamp, DeviceName, ActionType, AccountName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1467" height="162" alt="image" src="https://github.com/user-attachments/assets/0937f65a-d28a-438d-abfc-ce7514164934" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “she114” actually opened the tor browser. There was evidence that they did open it at `2025-11-13T19:04:22.6380528Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName has "threatHntV-SH"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, AccountName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

<img width="1449" height="522" alt="image" src="https://github.com/user-attachments/assets/2b2517f8-22da-4e62-9b5b-2b15a5701d93" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the TOR browser was used to establish a connection using any known TOR ports. At `2025-11-13T19:06:28.0405951Z`, on the device threathntv-sh, the user she114 successfully made a network connection using the TOR process `tor.exe` located on their desktop. The Tor client connected to the remote IP address `89.58.62.138` over port `9001`, which is commonly used for Tor relay traffic. There were a couple other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName has "threatHntV-SH"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

<img width="1454" height="526" alt="image" src="https://github.com/user-attachments/assets/11523653-513e-4e8f-ae65-b7611a07ac06" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp (UTC):** `2025-11-13T19:03:00Z`
- **Event:** The user "she114" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.1.exe` to the Downloads folder.
- **Action:** File download detected
- **File Path:** `C:\Users\she114\Downloads\tor-browser-windows-x86_64-portable-15.0.1.exe`

### 2. Process Execution - TOR Browser Installation

 - **Timestamp (UTC):** `2025-11-13T19:03:17Z`
 - **Event:** The user "she114" executed the file `tor-browser-windows-x86_64-portable-15.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
 - **Action:** Process creation detected.
 - **Command:** `tor-browser-windows-x86_64-portable-15.0.1.exe /S`
 - **File Path:** `C:\Users\she114\Downloads\tor-browser-windows-x86_64-portable-15.0.1.exe`

### 3. Process Execution - TOR Browser Launch

 - **Timestamp (UTC):** `2025-11-13T19:04:22Z`
 - **Event:** User "she114" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
 - **Action:** Process creation of TOR browser-related executables detected.
 - **File Path:** `C:\Users\she114\Desktop\Tor Browser\Browser\TorBrowser\firefox.exe` and `C:\Users\she114\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

 - **Timestamp (UTC):** `2025-11-13T19:06:28Z`
 - **Event:** A network connection to IP `89.58.62.138` on port `9001` by user "she114" was established using `tor.exe`, confirming TOR browser network activity.
 - **Action:** Connection success
 - **Process:** `tor.exe`
 - **File Path:** `C:\Users\she114\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

 - **Timestamp (UTC):** Multiple events after `2025-11-13T19:06:28Z`
 - **Connections observed on:** Port `443` (encrypted traffic, TOR transport), port `9001` (TOR relay), connections to multiple TOR infrastructure endpoints
 - **Event:** Additional TOR network connections were established, indicating ongoing activity by user "she114" through the TOR browser.
 - **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

 - **Timestamp (UTC):** `2025-11-13T21:51:11Z`
 - **Event:** The user "she114" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
 - **Action:** File creation detected.
 - **File Path:** `C:\Users\she114\Desktop\tor-shopping-list.txt`

---

## Summary

Between 11:03 AM and 11:07 AM on Nov 13, 2025, user she114 downloaded, silently installed, launched, and successfully used the TOR Browser on device threathntv-sh. The installer was executed using a silent mode switch, resulting in background installation. TOR-related files were placed on the desktop, and multiple TOR processes (firefox.exe, tor.exe) executed afterward.
At 11:06:28 AM, the system established an outbound connection to a known TOR relay (port 9001), proving active TOR network usage. Later that evening, additional TOR-related file activity occurred, including the creation of a text file `tor-shopping-list.txt`.
The activity clearly demonstrates intentional installation and use of the TOR Browser by user she114.

---

## Response Taken

TOR usage was confirmed on endpoint threatHntV-SH by the user she114. The device was isolated, and the user's direct manager was notified.

---
