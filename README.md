<<<<<<< HEAD
🎣 Phishing Email Detector (Rule-Based Engine)
A transparent desktop application built with Python and PySide6 that utilizes a comprehensive set of security rules to detect phishing indicators in email content, focusing on suspicious language and link obfuscation.

✨ Key Features
Rule-Based Logic: The detector relies purely on expert-defined keywords and patterns to identify phishing attempts. This makes the detection process 100% transparent and auditable.

Categorized Rules: Suspicious keywords are organized into categories (e.g., Urgency, Financial, Account Security) for better coverage and reporting.

Link Validation: Automatically flags any URL in the email body that does not belong to a large, pre-defined list of trusted domains (stored in the all_trusted_sites variable).

Multi-Input Interface: Analyze emails from three sources:

Gmail API: Connects to your inbox to fetch and analyze recent emails (requires Google API setup).

File Input: Upload .txt, .html, or .eml files.

Manual Input: Paste raw email content.

Modern GUI: Uses PySide6 for a clean, user-friendly, multi-page dark-themed application.
File structure 
PHISHING_EMAIL_DETECTOR_R.../
├── .venv/                         # Python Virtual Environment (Optional, hidden by default)
├── venv/                          # Python Virtual Environment (Alternative directory)
├── credentials.json               # Google API Credentials (For Gmail feature setup)
├── readme.md                      # Project Documentation (The file you just created)
├── requirements.txt               # List of Python dependencies (For installation)
├── rule_based.py                  # Main Python script containing the rule-based logic and GUI
└── token.json                     # Google API Token (Generated automatically after first successful Gmail authentication)

⚙️ Prerequisites and Setup
This project requires Python 3.x and specific third-party libraries.

1. Dependencies
Install all essential Python libraries using the requirements.txt file provided below.

requirements.txt
PySide6
google-api-python-client
google-auth-oauthlib
google-auth-transport-requests
beautifulsoup4
To install these, run:

Bash

pip install -r requirements.txt
2. Gmail API Setup  🔑
To use the "Gmail Account Analysis" feature, you must obtain and configure Google OAuth 2.0 credentials.

Step	Action
1. Enable API	Go to the Google Cloud Console, select your project, and enable the Gmail API in the API Library.
2. Consent Screen	Configure the OAuth consent screen (choose "External" User Type).
3. Create Credentials	Go to Credentials > Create Credentials > OAuth client ID. Select Desktop app as the Application Type.
4. Download File	Click DOWNLOAD JSON and rename the file to exactly credentials.json.
5. Place File	Place credentials.json in the root directory of this project.
6. Token Generation	The first time you run the Gmail feature, the application will launch a browser window for authorization. This process automatically generates a token.json file, which is used for subsequent secure logins.

Export to Sheets
💻 Rule Logic Implementation Details
The core detection happens in the static method EmailAnalyzer.analyze_email_content.

1. Keyword Analysis (Social Engineering)
The system scans the entire email body for an extensive list of phrases commonly used in phishing attacks. The rule categories are:

Urgency (e.g., "immediate action required," "account will be closed")

Account Security (e.g., "verify your identity," "reset password")

Financial (e.g., "wire transfer," "payment pending")

Rewards/Scams (e.g., "claim your reward," "prize money")

Verification (e.g., "click here to verify")

2. Link Analysis (Technical Indicators)
All hyperlinks are extracted. The system flags a link as suspicious if its destination does not contain a substring matching a domain from the list of highly trusted_sites.

3. Risk Assessment
The email is classified into one of two categories based on the rule triggers:

"HIGH RISK": Classified if any suspicious keywords are found OR any suspicious links are detected.

"LOW RISK": Classified only if neither the keyword rules nor the link rules are triggered.

🚀 Getting Started
Run the main application file:

Bash

python phishing_detector.py 
# (Assuming your main script is saved as phishing_detector.py)
Analyze an Email:

Navigate to "Select Input Method".

Choose your preferred analysis method (Gmail, File, or Manual Input).

The "Analysis Results" page will display the email's risk level (HIGH/LOW) and provide a detailed report showing which specific keywords and suspicious links were detected.

🛠 Project Customization
The core logic can be easily tuned for better detection by modifying the following variables at the beginning of the script:

Variable	Purpose	How to Modify
suspicious_keywords	Defines phrases that trigger a positive phishing detection.	Add/Remove phrases to adapt to new social engineering tactics.
trusted_sites	A whitelist of domains the system considers safe.	Add major corporate or government domains relevant to your users.
SCOPES	Defines the API access level for Gmail.	DO NOT CHANGE. Must remain read-only (gmail.readonly) for security.

Export to Sheets
=======
# phishing-email-dectector_rule_based
>>>>>>> d0efde539faec78e3f2cd05b3fecd7a261e33038
