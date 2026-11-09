# OSP Monitoring — Data Core & Measurements Dashboard

A hybrid **Local Collector + Static GitHub Pages Presentation** dashboard for **OTDR Analytics (`.sor`)**, **Network Topology (NMS)**, and **Router/OLT Optical Power Diagnostics (via SSH Jumpbox)**.

- **Live Presentation Dashboard (GitHub Pages):**  
  [https://hilmandika.github.io/OSP-Monitoring/](https://hilmandika.github.io/OSP-Monitoring/)

---

## How the Hybrid Architecture Works

1. **GitHub Pages (Presentation Mode — No VPN Required):**
   - Anyone can open the GitHub Pages link from any device to inspect pre-parsed OTDR fiber traces, events, Network Topology maps, and the latest saved Router Optical Power Scan report.
2. **Local Laptop Collector (Full Mode — Connected to Corporate VPN / Jumpbox):**
   - Team members run the app locally on their laptop (`http://localhost:8000`) while connected to the VPN.
   - From the local app, you can:
     - Connect to the SSH Jumpbox (`10.60.190.15`) and click **Scan All Routers** (or **Diagnose Port Power**) to collect live optical power readings.
     - Scan local folders containing `.sor` OTDR files.
     - Add/edit devices and connections in **Network Topology**.
   - Click the green **Publish to GitHub** button in the top-right header to automatically package the latest snapshot (`frontend/static_data/`) and push it to GitHub Pages.

---

## Quick Start on Any Team Laptop

### 1. Clone the Repository (First Time Only)
```bash
git clone git@github.com:hilmandika/OSP-Monitoring.git
cd OSP-Monitoring
```
*(Ensure Python 3.9+ and Git with push access to `hilmandika/OSP-Monitoring` are installed on the laptop).*

### 2. Launch the Local Collector App
- **On macOS:** Double-click **`Start_Collector_Mac.command`** in Finder (or run `./Start_Collector_Mac.command` in Terminal).
- **On Windows:** Double-click **`Start_Collector_Windows.bat`** in File Explorer.

The launcher will automatically:
1. Pull the latest snapshot from GitHub (`git pull`).
2. Create the `.venv` virtual environment and install dependencies (`requirements.txt`) on first run.
3. Start the FastAPI server at **`http://localhost:8000`** and open your browser.

---

## Collecting Data & Publishing to GitHub Pages

1. **Collect Optical Power from Routers (Console Tab):**
   - Connect your laptop to the corporate VPN.
   - Open the **Console** tab at `http://localhost:8000`.
   - Enter your Jumpbox credentials and click **Connect**.
   - Enter the target router password under **2. Target Device SSH** and click **Scan All Routers** (or select a single router and click **Diagnose Port Power**).
   - Once the scan completes, the readings are automatically saved to `backend/data/optical_scan.json`.
2. **Update OTDR Data or Topology (Optional):**
   - In **OTDR Analytics**, paste a local folder path of `.sor` files and click **Scan Directory**.
   - In **Network Topology**, edit devices/links and click **Save Changes**.
3. **Publish to GitHub Pages:**
   - Click the green **Publish to GitHub** button in the top-right corner of the header.
   - The app exports all OTDR traces, Topology data, and Optical Power scan results into `frontend/static_data/` and pushes to both `main` and `gh-pages`.
   - Within ~30–60 seconds, [https://hilmandika.github.io/OSP-Monitoring/](https://hilmandika.github.io/OSP-Monitoring/) will reflect the new data!
