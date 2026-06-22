# PowerShell Log Analysis in Splunk

## Project Overview
This project demonstrates an end-to-end SOC-style investigation of **PowerShell activity logs** collected from a Windows system and analyzed in **Splunk Cloud**. The objective of the project was to generate PowerShell activity on a Windows host, inspect the corresponding **Windows Event Logs** in Event Viewer, ingest the relevant log data into Splunk, and build a dashboard to visualize execution activity, event distribution, severity levels, and frequently occurring PowerShell messages.

The project focuses on how a SOC analyst can use **Windows PowerShell Operational logs** to identify suspicious or noteworthy PowerShell behavior, monitor command execution, and create timeline-based visualizations for incident investigation.

---

## Objectives
- Generate PowerShell activity on a Windows host
- Observe and validate PowerShell logs in **Event Viewer**
- Identify relevant PowerShell event IDs
- Ingest PowerShell-related logs into **Splunk Cloud**
- Create a Splunk dashboard for log analysis and visualization
- Perform basic investigation of PowerShell execution patterns

---

## Tools & Technologies Used
- **Windows 10 / Windows PowerShell**
- **Event Viewer**
- **Splunk Cloud**
- **PowerShell Operational Logs**
- **Windows Administrative Tools**

---

## Lab Environment
### Target System
- **OS:** Windows
- **Hostname:** DESKTOP-ELU460N
- **User:** Kamesh
- **PowerShell Activity Source:** Microsoft-Windows-PowerShell/Operational

### SIEM Platform
- **Splunk Cloud** used for log ingestion, search, and dashboard creation

---

## PowerShell Event IDs Observed
During the investigation, PowerShell Operational logs were monitored using Event Viewer. The following event IDs were identified in the screenshots and used for analysis:

- **Event ID 4103** – PowerShell pipeline execution / command invocation details
- **Event ID 4104** – PowerShell script block logging / script block content
- **Event ID 40961 / 40962 / 53504** – PowerShell-related events visible in Splunk dashboard visualizations

> Note: In this project, the key investigation focus was on **PowerShell Operational events**, especially **4103** and **4104**, because they provide visibility into PowerShell execution and script activity.

---

## Attack / Activity Simulation Performed
To generate PowerShell logs for analysis, multiple commands were executed from an elevated PowerShell session. These activities included:

- Checking Windows version
- Identifying current user and hostname
- Viewing IP configuration
- Listing running processes
- Listing Windows services
- Starting PowerShell with **ExecutionPolicy Bypass**
- Enumerating user directories under `C:\Users`

Example commands executed:
```powershell
winver
whoami
hostname
ipconfig
Get-Process
Get-Service
powershell -ExecutionPolicy Bypass
Get-ChildItem C:\Users
