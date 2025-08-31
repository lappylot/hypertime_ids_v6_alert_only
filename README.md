 
# Hypertime IDS v6 (Alert-Only Mode)

Hypertime IDS is a **quantum-inspired Intrusion Detection System (IDS)** designed for experimental research into post-quantum security and alerting.
This version runs in **alert-only mode**, logging suspicious activity without blocking traffic.

It includes:

* Post-quantum hybrid key support
* Encrypted SQLite logging backend
* OpenAI schema validation for event parsing
* TUI (Terminal User Interface) for live monitoring
* Alert-only mode (safe for testing environments)

---

## Requirements

* Windows 10/11 with PowerShell
* Python 3.10+ installed
* Git installed

Optional but recommended:

* Windows Terminal or VS Code terminal for easier management

---

## Clone the Repository

Open PowerShell and run:

```
cd C:\Users\YOUR_USERNAME\Desktop  
git clone https://github.com/lappylot/hypertime_ids_v6_alert_only  
cd hypertime_ids_v6_alert_only  
```

(Replace `YOUR_USERNAME` with your actual Windows username.)

---

## Installation

Run the provided installer script:

```
.\install.ps1  
```

This will:

* Create a virtual environment (.venv)
* Install all required Python dependencies into .venv
* Verify that your environment is ready

---

## Running the IDS

Each time you want to start Hypertime IDS:

1. Navigate into the project folder:

   ```
   cd C:\Users\YOUR_USERNAME\Desktop\hypertime_ids_v6_alert_only  
   ```

2. Allow PowerShell scripts for this session only (safe):

   ```
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass  
   ```

3. Activate the virtual environment:

   ```
   .\.venv\Scripts\Activate.ps1  
   ```

4. Run the IDS:

   ```
   python main.py  
   ```

If successful, your PowerShell prompt will show `(venv)` at the beginning.

---

## Stopping the IDS

* Press Ctrl + C inside PowerShell to stop the IDS process
* Run `deactivate` to exit the virtual environment
* Closing PowerShell automatically resets the execution policy

---

## Troubleshooting

**Error: "running scripts is disabled on this system"**

Fix by allowing scripts for the current session only:

```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass  
.\.venv\Scripts\Activate.ps1  
```

**Alternate activation method**

If `.ps1` activation doesn’t work, use the batch file instead:

```
.\.venv\Scripts\activate.bat  
```

**Run without activation**

You can also run IDS directly using the `.venv` Python interpreter:

```
.\.venv\Scripts\python.exe main.py  
```

---

## Running on Linux/macOS

On non-Windows systems:

1. Clone and enter the repo:

   ```
   git clone https://github.com/lappylot/hypertime_ids_v6_alert_only  
   cd hypertime_ids_v6_alert_only  
   ```

2. Create and activate venv:

   ```
   python3 -m venv .venv  
   source .venv/bin/activate  
   ```

3. Install dependencies:

   ```
   pip install -r requirements.txt  
   ```

4. Run IDS:

   ```
   python3 main.py  
   ```

5. Deactivate with:

   ```
   deactivate  
   ```

---

## Notes

* Always run IDS inside the `.venv` virtual environment
* The execution policy bypass only lasts for the current PowerShell session
* Logs are stored in an encrypted SQLite database inside the project
* IDS runs in alert-only mode (it won’t block traffic)

---

## Quickstart (Windows One-Liner)

If you already installed everything, you can restart IDS in one command:

```
cd C:\Users\YOUR_USERNAME\Desktop\hypertime_ids_v6_alert_only; Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\.venv\Scripts\Activate.ps1; python main.py  
```

---

## Roadmap

Planned features for future versions:

* Active response mode (blocking malicious traffic)
* Web dashboard for alerts
* Multi-node distributed deployment
* Extended post-quantum cryptography support

---

## License

This project is licensed under **GPL-3.0**.
See the LICENSE file for details.

 
