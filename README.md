# Threat Intelligence Automation (Beginner CTI Project)

This project automates the process of enriching suspicious IP addresses from a live public threat feed using the [VirusTotal API](https://www.virustotal.com/). It's built using **Python**, **VS Code**, and **Jupyter/Terminal tools**, and designed specifically as a **learning project** to build hands-on experience in:

- Cyber Threat Intelligence (CTI)
- Python scripting for automation
- Working with public REST APIs
- Using virtual environments
- Pushing and managing code on GitHub

---

## Project Goals

- Automate IOC (Indicator of Compromise) enrichment
- Pull a public feed of suspicious IPs (blocklist.de)
- Query each IP using VirusTotal's API to check for malicious reports
- Print alerts for IPs flagged as potentially dangerous
- Build a practical, beginner-friendly foundation for future security automation projects

---

## Setup 
# 1. Clone the repo
git clone https://github.com/rithvichr/threat-intel-automation.git
cd threat-intel-automation

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the environment
# On Mac/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Add your VirusTotal API key
echo 'VT_API_KEY = "your_virustotal_key_here"' > config.py

# 6. Run the script
python main.py

---
##API Key Setup
To get your API key:

Sign up at https://www.virustotal.com

Go to your profile → API key

Copy your key

Create a file named config.py:

python
Copy
Edit
VT_API_KEY = "your_api_key_here"


---
## Demo

Here’s what it looks like when you run it:

```bash
📥 Loading IPs from the threat feed...
🔍 Checking IPs with VirusTotal...
Checking IP: 185.220.101.4
Checking IP: 89.248.165.64
✅ Done! Here's what we found:

               IP  Malicious  Suspicious  Harmless
0  185.220.101.4          5           0         34
1  89.248.165.64          3           1         40
