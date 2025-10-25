# IS-LAB-PROJECT


# 🧅 Tor-Based Secure File Transfer System

This project implements a **secure file transfer system** over the **Tor network**, using an **Onion Service** (hidden service) for encrypted, anonymous communication between a sender (server) and receiver (client).  
It allows files to be shared privately using **Basic Authentication** and **SHA-256 integrity verification**.

---

## 📘 Overview

### 🖥 Components:
- **`sender.py`** — Runs a Flask server and automatically registers a Tor Hidden Service using the Tor Control Port.
- **`receiver.py`** — Connects to the Onion address through the Tor network, authenticates, downloads the file, and verifies its SHA-256 hash.

The system works like this:

Sender (Flask + Tor) <--- Tor Network ---> Receiver (Requests over Tor)

yaml
Copy code

---

## ⚙️ Prerequisites

Before running the project, make sure you have the following installed:

| Requirement | Version | Description |
|--------------|----------|--------------|
| **Python** | 3.8 or higher | Needed to run both sender and receiver scripts |
| **Tor** | Latest stable version | Used for Onion service creation and routing |
| **Flask** | Any stable version | Backend server framework |
| **Requests** | Latest | Used by receiver for file download |

---

## 🧩 Installation Steps

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
2️⃣ Install Required Python Libraries
bash
Copy code
pip install flask requests stem
3️⃣ Install and Configure Tor
Windows Users:

Download the Tor Expert Bundle from:
👉 https://www.torproject.org/download/tor/

Extract it (e.g., to C:\Tor).

Navigate to that folder in PowerShell:

bash
Copy code
cd C:\Tor
Inside that folder, open the torrc file (or create one if missing) and add these lines:

yaml
Copy code
ControlPort 9051
SocksPort 9050
CookieAuthentication 1
DataDirectory C:\Tor\Data
Save the file and run Tor:

bash
Copy code
.\tor.exe -f .\torrc
You should see messages like:

matlab
Copy code
Bootstrapped 100%: Done
🚀 Running the Sender (Server)
1️⃣ Open a new PowerShell window in your project folder.
2️⃣ Run:
bash
Copy code
python sender.py
3️⃣ What Happens:
Tor is contacted via 127.0.0.1:9051.

A new Onion Service is created.

The hidden service address (like a76xqb7w2yn5ittosykqah5teyoqhnvibwqnvfhaakce5ypr2tuaqqid.onion) is displayed and saved to onion_address.txt.

The Flask server starts locally on port 8000.

4️⃣ Example Output:
css
Copy code
[+] Connected to Tor Control Port
[+] Onion Service created: a76xqb7w2yn5ittosykqah5teyoqhnvibwqnvfhaakce5ypr2tuaqqid.onion
[+] Flask server running at 127.0.0.1:8000
