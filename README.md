# 🛡️ Mild-Viking — Lightweight Network Monitor

A fun, lightweight Raspberry Pi network traffic monitor that displays system stats on a 2.13" e-Paper HAT alongside a real-time web dashboard. 

Originally forked from [Ragnar](https://github.com/PierreGode/Ragnar) (and descended from [Bjorn](https://github.com/infinition/Bjorn)), **Mild-Viking** has been entirely tamed. All offensive security, attacking, and scanning tooling have been completely removed. It is now a pure, passive network observer built to live safely on your home network.

---

## 🚀 Installation

You can deploy Mild-Viking directly onto your Raspberry Pi using the automated install script:

```bash
wget [https://raw.githubusercontent.com/auggnation/Ragnarbutdifferent/main/install-mv.sh](https://raw.githubusercontent.com/auggnation/Ragnarbutdifferent/main/install-mv.sh)
sudo chmod +x install-mv.sh && sudo ./install-mv.sh
📊 Features
Passive Network Observation — Keeps a lightweight eye on your network traffic without running aggressive or intrusive scans.

E-Paper Display Cycles — Formatted for a 2.13" e-Paper HAT. Auto-scrolls through multiple sub-pages (Stats, Local Devices, Network Status) every few seconds.

Gamified Uptime — Your Mild-Viking gains levels the longer it stays online (1 level per hour of continuous uptime).

Status Animations — Visual indicators change based on current network throughput intensity (Idle, Active, and High Traffic states).

Web Dashboard — Access a real-time overview of your network metrics via any browser on your local network at http://<your-pi-ip>:8000.

Smart Connectivity — Prefers a stable Ethernet connection, with built-in Wi-Fi management acting as a reliable fallback.

🛠️ Service Management
Mild-Viking runs as a background system service. You can manage it using standard systemd commands:

Bash
# Check if the monitor is running smoothly
sudo systemctl status mild-viking

# Restart the service after making changes
sudo systemctl restart mild-viking

# View real-time application logs
sudo journalctl -u mild-viking -f
📜 Credits & Lineage
auggnation — Turning this into a safe, fun, lightweight passive home monitor.

PierreGode/Ragnar — The intermediate fork.

infinition/Bjorn — The original upstream project ancestor.


### How to apply this to your repo:
1. Open your local `README.md` file inside the `~/Ragnar` folder.
2. Replace the entire content with the block above.
3. Save, then push it up to GitHub:
   ```bash
   git add README.md
   git commit -m "Update README to reflect lightweight passive features"
   git push origin main
