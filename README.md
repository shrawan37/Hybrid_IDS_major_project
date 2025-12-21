# Intrusion Detection System

A simple network intrusion detection system with both signature-based and anomaly detection capabilities.

## Quick Installation

1. **Clone the repository**

```bash
git clone https://github.com/Reet-Ace/HYBRID-IDS.git
cd HYBRID-IDS
```

2. **Install requirements**

```bash
pip install -r requirements.txt
```

3. **Install system dependencies (if needed)**

**Windows users:** Download and install [Npcap](https://npcap.com/#download)

**Linux users:** 
```bash
sudo apt-get install libpcap-dev python3-tk  # Ubuntu/Debian
# OR
sudo dnf install libpcap-devel python3-tkinter  # Fedora/RHEL
```

**macOS users:**
```bash
brew install libpcap
```

## Running the Application

1. **Launch the application**

```bash
python ids_UI.py
```

2. **Using the IDS**

* Select a network interface from the dropdown
* Click "Start Capture" to begin monitoring
* View captured packets in the main window
* Threat alerts will appear as pop-ups
* Click "Stop Capture" to end monitoring

## Note

Administrator/root privileges may be required to capture packets:

**Windows:** Run Command Prompt as Administrator
**Linux/macOS:** Use sudo
```bash
sudo python ids_UI.py
```

## Files

* `ids_UI.py` - Main application with GUI
* `packetcapture.py` - Network packet capture module
* `detectionengine.py` - Threat detection logic
* `buildalert_system.py` - Alert generation system
* `alert_popup.py` - Notification display
* `packet_info.py` - Detailed packet information
* `signatures.json` - Attack signatures database
