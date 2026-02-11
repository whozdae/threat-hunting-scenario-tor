

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt=" Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/whozdae/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

The investigation began with a query of the DeviceFileEvents table to identify any file system activity associated with the "Tor" string. Logs confirmed that on February 9, 2026, at 11:37:24 AM, the user initiated the download and creation of several Tor-related files. Notably, a file named Tor shopping list was discovered on the desktop, suggesting intentional use of the software for specific tasks.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName  == "coconut-water-p"
| where InitiatingProcessAccountName == "rangefinder"
|where FileName contains "tor."
| order by Timestamp desc 
| where Timestamp >= datetime(2026-02-09T19:37:24.3940267Z)
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1608" height="649" alt="image" src="https://github.com/user-attachments/assets/bfbe9314-c646-4313-a1ca-7db5e2778f6e" />


---

### 2. Searched the `DeviceProcessEvents` Table

Analysis of the DeviceProcessEvents table was performed to determine how the software was deployed. Evidence indicates that at 11:38:05 AM, the user executed the portable installer tor-browser-windows-x86_64-portable-15.0.5.exe from the local Downloads folder. The execution included command-line arguments consistent with a silent installation, intended to bypass standard setup prompts.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName  == "coconut-water-p"
| where ProcessCommandLine contains "tor-browser-windows-x86."
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1540" height="314" alt="image" src="https://github.com/user-attachments/assets/1ac6c048-c53b-4cbc-8dd7-6a7229a1dd89" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

To confirm whether the application was actively used, the process events were cross-referenced for core Tor Browser binaries, including tor.exe and the modified firefox.exe. The logs validated that the browser was successfully launched, initiating the necessary sub-processes to facilitate an encrypted connection.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "coconut-water-p"
| where FileName  has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1704" height="539" alt="image" src="https://github.com/user-attachments/assets/b202fefa-5b97-4ca0-8479-b286989e44b0" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The final stage of the hunt focused on DeviceNetworkEvents to identify outbound traffic over non-standard ports associated with Tor relays and bridges. On February 9, 2026, at 11:40 AM, the process tor.exe established a successful connection to external IP 157.90.92.115 via Port 9001. Additional concurrent connections were observed over Ports 80 and 443, confirming the bypass of standard corporate web filtering.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName  == "coconut-water-p"
|where InitiatingProcessAccountName != "system"
|where InitiatingProcessFileName in ( "tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
|order by Timestamp desc 
```
<img width="1495" height="487" alt="image" src="https://github.com/user-attachments/assets/5e62b708-4f49-42ff-9b97-2b7c8f7a5db4" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-09T11:37:25.0000000Z`
- **Event:** The user "rangefinder" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.5.exe` to the Downloads folder.
- **Action:** Process creation detected (Installer presence confirmed).
- **File Path:** `C:\Users\rangefinder\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-09T11:38:05.0000000Z`
- **Event:** The user "rangefinder" executed the file `tor-browser-windows-x86_64-portable-15.0.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
- **File Path:** `C:\Users\rangefinder\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-09T11:39:10.0000000Z`
- **Event:** User "rangefinder" opened the TOR browser. Subsequent processes associated with the TOR browser, such as `firefox.exe` and `tor.exe`, were created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\rangefinder\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-09T11:39:30.0000000Z`
- **Event:** A network connection to IP `193.11.166.196` on port `443` by user "rangefinder" was established

---

## Summary

The user rangefinder successfully downloaded and silently installed the Tor Browser on the device coconut-water-p on the morning of Feb 9, 2026.
Installation: The user utilized the silent install switch (/S) to deploy the browser to the Desktop.
Execution: Immediately following installation, the firefox.exe and tor.exe processes were launched, establishing connections to known Tor exit nodes and relays (Ports 9001, 443).
Activity: The following day (Feb 10), the user created a file named tor-shopping-list.txt, suggesting active use of the browser for specific tasks.


---

## Response Taken

TOR usage was confirmed on endpoint coconut-water-p. The device was isolated, and the user's direct manager was notified.

---
