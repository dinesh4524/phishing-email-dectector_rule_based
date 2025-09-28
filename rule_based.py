import sys
import re
import base64
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, 
    QWidget, QLabel, QFileDialog, QMessageBox, QProgressBar, 
    QComboBox, QStackedWidget, QHBoxLayout
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor, QPalette, QTextCursor, QTextCharFormat, QBrush

# Suspicious keywords list (organized by category)
suspicious_keywords = {
    "Urgency": [
        "immediate action required", "response needed", "act now", "urgent",
        "your account will be closed", "final notice", "limited time offer"
    ],
    "Account Security": [
        "verify your identity", "security update", "reset password",
        "confirm your details", "multi-factor authentication",
        "account suspended", "unauthorized transaction",
        "your account is compromised", "locked account"
    ],
    "Financial": [
        "wire transfer", "payment pending", "overdue invoice",
        "refund", "payment failure", "billing error",
        "unexpected charge", "pending transaction"
    ],
    "Rewards/Scams": [
        "congratulations", "claim your reward", "prize money",
        "free gift", "government grant", "bitcoin transfer",
        "crypto giveaway"
    ],
    "Verification": [
        "click here to verify", "helpdesk verification",
        "email verification required", "reactivate now"
    ],
    "General": [
        "password", "bank", "account", "credit card", "security",
        "suspicious activity", "fraud prevention", "security alert",
        "identity theft", "access restricted"
    ]
}

# Flatten the keywords dictionary into a single list
all_keywords = [kw for sublist in suspicious_keywords.values() for kw in sublist]

# Trusted websites (organized by category)
trusted_sites = {
    "Social Media": ["facebook.com", "twitter.com", "linkedin.com", "instagram.com", "tiktok.com"],
    "Email": ["gmail.com", "outlook.com", "yahoo.com", "icloud.com"],
    "Banking": [
        "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
        "capitalone.com", "discover.com", "americanexpress.com"
    ],
    "Shopping": ["amazon.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com"],
    "Tech": [
        "google.com", "apple.com", "microsoft.com", "paypal.com",
        "netflix.com", "spotify.com", "zoom.us", "slack.com"
    ],
    "Government": ["gov.uk", "irs.gov", "ssa.gov"],
    "Finance": ["revolut.com", "wise.com", "zelle.com", "venmo.com", "coinbase.com"]
}

# Flatten the trusted sites dictionary into a single list
all_trusted_sites = [site for sublist in trusted_sites.values() for site in sublist]

# Gmail API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class EmailAnalyzer:
    @staticmethod
    def authenticate_gmail():
        """Authenticate with Gmail API"""
        creds = None
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        return build('gmail', 'v1', credentials=creds)

    @staticmethod
    def fetch_email_list(limit=10):
        """Fetch list of emails with subjects and IDs"""
        try:
            service = EmailAnalyzer.authenticate_gmail()
            results = service.users().messages().list(
                userId='me', maxResults=limit).execute()
            messages = results.get('messages', [])
            return [{
                'id': msg['id'],
                'subject': next(
                    header['value'] for header in 
                    service.users().messages().get(
                        userId='me', 
                        id=msg['id'], 
                        format='metadata', 
                        metadataHeaders=['Subject']
                    ).execute()['payload']['headers'] 
                    if header['name'] == 'Subject'
                )
            } for msg in messages]
        except Exception as e:
            raise Exception(f"Failed to fetch emails: {str(e)}")

    @staticmethod
    def fetch_email_content(email_id):
        """Fetch full email content by ID"""
        try:
            service = EmailAnalyzer.authenticate_gmail()
            msg = service.users().messages().get(
                userId='me', id=email_id, format='full').execute()
            
            headers = msg['payload']['headers']
            email_data = {
                'from': next(h['value'] for h in headers if h['name'] == 'From'),
                'subject': next(h['value'] for h in headers if h['name'] == 'Subject'),
                'body': ''
            }

            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        email_data['body'] = base64.urlsafe_b64decode(
                            part['body']['data']).decode('utf-8')
                        break
                    elif part['mimeType'] == 'text/html':
                        email_data['body'] = EmailAnalyzer.extract_text_from_html(
                            base64.urlsafe_b64decode(part['body']['data']).decode('utf-8'))
            else:
                email_data['body'] = base64.urlsafe_b64decode(
                    msg['payload']['body']['data']).decode('utf-8')
            
            return email_data
        except Exception as e:
            raise Exception(f"Failed to fetch email content: {str(e)}")

    @staticmethod
    def extract_text_from_html(html_text):
        """Extract clean text from HTML email"""
        soup = BeautifulSoup(html_text, "html.parser")
        for tag in soup(["script", "style", "meta", "link", "base", "noscript", "head"]):
            tag.extract()
        text = soup.get_text(separator="\n")
        return re.sub(r"\n\s*\n+", "\n\n", text).strip()

    @staticmethod
    def analyze_email_content(email_text):
        """Analyze email content for phishing indicators"""
        email_text_lower = email_text.lower()
        
        # Keyword analysis by category
        keyword_results = {}
        for category, keywords in suspicious_keywords.items():
            found = {kw: email_text_lower.count(kw) for kw in keywords if kw in email_text_lower}
            if found:
                keyword_results[category] = found
        
        # Link analysis
        url_pattern = r'https?://[^\s]+'
        links = re.findall(url_pattern, email_text)
        suspicious_links = [
            link for link in links 
            if not any(f"://{trusted}" in link for trusted in all_trusted_sites)
        ]
        
        # Determine overall risk level
        risk_level = "High" if (keyword_results or suspicious_links) else "Low"
        
        return {
            "risk_level": risk_level,
            "keyword_results": keyword_results,
            "suspicious_links": suspicious_links,
            "link_count": len(links),
            "suspicious_link_count": len(suspicious_links)
        }

class WelcomePage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Title
        title = QLabel("Phishing Email Detector")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: #4a90e2; margin-bottom: 30px;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        # Description
        desc = QLabel(
            "A security tool to detect potential phishing attempts in your emails.\n"
            "Analyze emails from Gmail, text files, or manual input."
        )
        desc.setFont(QFont("Arial", 12))
        desc.setStyleSheet("color: #cccccc; margin-bottom: 40px;")
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)

        # Start button
        start_btn = QPushButton("Get Started")
        start_btn.setFont(QFont("Arial", 14))
        start_btn.setStyleSheet(
            "QPushButton {"
            "background-color: #4a90e2;"
            "color: white;"
            "border: none;"
            "padding: 12px 24px;"
            "border-radius: 4px;"
            "min-width: 200px;"
            "}"
            "QPushButton:hover {"
            "background-color: #3a7bc8;"
            "}"
        )
        start_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        layout.addWidget(start_btn, alignment=Qt.AlignCenter)

        # Footer
        footer = QLabel("Phishing Detector | Security Tool")
        footer.setFont(QFont("Arial", 9))
        footer.setStyleSheet("color: #666666; margin-top: 50px;")
        layout.addWidget(footer, alignment=Qt.AlignCenter)

class OptionsPage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Title
        title = QLabel("Select Input Method")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setStyleSheet("color: #4a90e2; margin-bottom: 30px;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        # Button container
        btn_container = QWidget()
        btn_layout = QVBoxLayout()
        btn_container.setLayout(btn_layout)
        btn_layout.setSpacing(15)
        btn_layout.setContentsMargins(50, 0, 50, 0)

        # Gmail button
        gmail_btn = self.create_option_button(
            "Gmail Account", 
            "Connect to your Gmail account to analyze recent emails",
            lambda: self.stacked_widget.setCurrentIndex(2)
        )
        btn_layout.addWidget(gmail_btn)

        # File button
        file_btn = self.create_option_button(
            "Text File", 
            "Upload a text or HTML file containing email content",
            lambda: self.stacked_widget.setCurrentIndex(3)
        )
        btn_layout.addWidget(file_btn)

        # Manual button
        manual_btn = self.create_option_button(
            "Manual Input", 
            "Paste email content directly into the analyzer",
            lambda: self.stacked_widget.setCurrentIndex(4)
        )
        btn_layout.addWidget(manual_btn)

        layout.addWidget(btn_container)

        # Back button
        back_btn = QPushButton("Back")
        back_btn.setFont(QFont("Arial", 12))
        back_btn.setStyleSheet(
            "QPushButton {"
            "background-color: transparent;"
            "color: #4a90e2;"
            "border: 1px solid #4a90e2;"
            "padding: 8px 16px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: rgba(74, 144, 226, 0.1);"
            "}"
        )
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        layout.addWidget(back_btn, alignment=Qt.AlignCenter)

    def create_option_button(self, title, description, callback):
        btn = QPushButton()
        btn.setFixedHeight(80)
        btn.setStyleSheet(
            "QPushButton {"
            "background-color: #2d2d2d;"
            "border: 1px solid #3d3d3d;"
            "border-radius: 4px;"
            "text-align: left;"
            "padding: 15px;"
            "}"
            "QPushButton:hover {"
            "background-color: #3d3d3d;"
            "border: 1px solid #4a90e2;"
            "}"
        )
        
        btn_layout = QVBoxLayout()
        btn.setLayout(btn_layout)
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet("color: #ffffff;")
        btn_layout.addWidget(title_label)
        
        desc_label = QLabel(description)
        desc_label.setFont(QFont("Arial", 11))
        desc_label.setStyleSheet("color: #aaaaaa;")
        btn_layout.addWidget(desc_label)
        
        btn.clicked.connect(callback)
        return btn

# ... (similar improvements for other pages)

class PhishingDetectorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setWindowTitle("Phishing Email Detector")
        self.resize(900, 700)

    def init_ui(self):
        # Dark theme palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(35, 35, 35))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(50, 50, 50))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(74, 144, 226))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.setPalette(palette)

        # Stacked widget for multi-page interface
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # Create pages
        self.welcome_page = WelcomePage(self.stacked_widget)
        self.options_page = OptionsPage(self.stacked_widget)
        # Add other pages here...

        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.welcome_page)
        self.stacked_widget.addWidget(self.options_page)
        # Add other pages here...
import sys
import re
import base64
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, 
    QWidget, QLabel, QFileDialog, QMessageBox, QProgressBar, 
    QComboBox, QStackedWidget, QHBoxLayout, QScrollArea, QFrame
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QColor, QPalette, QTextCursor, QTextCharFormat, QBrush, QIcon


class GmailPage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Title
        title = QLabel("Gmail Account Analysis")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setStyleSheet("color: #4a90e2; margin-bottom: 20px;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        # Instructions
        instructions = QLabel(
            "Connect to your Gmail account to analyze recent emails for phishing attempts.\n"
            "You'll be asked to authorize access to your Gmail account (read-only)."
        )
        instructions.setFont(QFont("Arial", 11))
        instructions.setStyleSheet("color: #cccccc; margin-bottom: 30px;")
        instructions.setAlignment(Qt.AlignCenter)
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        # Load Emails Button
        self.load_btn = QPushButton("Load Emails from Gmail")
        self.load_btn.setFont(QFont("Arial", 12))
        self.load_btn.setStyleSheet(
            "QPushButton {"
            "background-color: #4a90e2;"
            "color: white;"
            "border: none;"
            "padding: 10px 20px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: #3a7bc8;"
            "}"
            "QPushButton:disabled {"
            "background-color: #555555;"
            "color: #999999;"
            "}"
        )
        self.load_btn.clicked.connect(self.load_emails)
        layout.addWidget(self.load_btn, alignment=Qt.AlignCenter)

        # Email Selection
        self.email_combo = QComboBox()
        self.email_combo.setFont(QFont("Arial", 11))
        self.email_combo.setStyleSheet(
            "QComboBox {"
            "background-color: #2d2d2d;"
            "color: white;"
            "border: 1px solid #3d3d3d;"
            "padding: 8px;"
            "border-radius: 4px;"
            "min-width: 300px;"
            "}"
        )
        self.email_combo.setPlaceholderText("Select an email to analyze")
        layout.addWidget(self.email_combo, alignment=Qt.AlignCenter)

        # Analyze Button
        self.analyze_btn = QPushButton("Analyze Selected Email")
        self.analyze_btn.setFont(QFont("Arial", 12))
        self.analyze_btn.setStyleSheet(
            "QPushButton {"
            "background-color: #4CAF50;"
            "color: white;"
            "border: none;"
            "padding: 10px 20px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: #3e8e41;"
            "}"
            "QPushButton:disabled {"
            "background-color: #555555;"
            "color: #999999;"
            "}"
        )
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.analyze_email)
        layout.addWidget(self.analyze_btn, alignment=Qt.AlignCenter)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Back Button
        back_btn = QPushButton("Back to Options")
        back_btn.setFont(QFont("Arial", 11))
        back_btn.setStyleSheet(
            "QPushButton {"
            "background-color: transparent;"
            "color: #4a90e2;"
            "border: 1px solid #4a90e2;"
            "padding: 8px 16px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: rgba(74, 144, 226, 0.1);"
            "}"
        )
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        layout.addWidget(back_btn, alignment=Qt.AlignCenter)

        # Add spacer to push content up
        layout.addStretch()

    def load_emails(self):
        self.load_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Indeterminate mode

        QTimer.singleShot(100, self._load_emails_async)

    def _load_emails_async(self):
        try:
            emails = EmailAnalyzer.fetch_email_list(limit=15)
            self.email_combo.clear()
            for email in emails:
                self.email_combo.addItem(email['subject'], email['id'])
            
            if emails:
                self.analyze_btn.setEnabled(True)
                QMessageBox.information(self, "Success", f"Loaded {len(emails)} emails successfully.")
            else:
                QMessageBox.warning(self, "Warning", "No emails found in your inbox.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load emails: {str(e)}")
        finally:
            self.load_btn.setEnabled(True)
            self.progress.setVisible(False)

    def analyze_email(self):
        email_id = self.email_combo.currentData()
        if not email_id:
            QMessageBox.warning(self, "Warning", "Please select an email first.")
            return

        self.progress.setVisible(True)
        QTimer.singleShot(100, lambda: self._analyze_email_async(email_id))

    def _analyze_email_async(self, email_id):
        try:
            email_content = EmailAnalyzer.fetch_email_content(email_id)
            analysis_page = self.stacked_widget.widget(5)  # AnalyzePage is at index 5
            analysis_page.set_email_content(email_content)
            self.stacked_widget.setCurrentIndex(5)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze email: {str(e)}")
        finally:
            self.progress.setVisible(False)

class FilePage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Title
        title = QLabel("File Analysis")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setStyleSheet("color: #4a90e2; margin-bottom: 20px;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        # Instructions
        instructions = QLabel(
            "Select a text or HTML file containing email content to analyze for phishing attempts.\n"
            "Supported formats: .txt, .html, .eml"
        )
        instructions.setFont(QFont("Arial", 11))
        instructions.setStyleSheet("color: #cccccc; margin-bottom: 30px;")
        instructions.setAlignment(Qt.AlignCenter)
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        # File Selection Button
        self.file_btn = QPushButton("Select File")
        self.file_btn.setFont(QFont("Arial", 12))
        self.file_btn.setStyleSheet(
            "QPushButton {"
            "background-color: #4a90e2;"
            "color: white;"
            "border: none;"
            "padding: 10px 20px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: #3a7bc8;"
            "}"
        )
        self.file_btn.clicked.connect(self.select_file)
        layout.addWidget(self.file_btn, alignment=Qt.AlignCenter)

        # Selected File Label
        self.file_label = QLabel("No file selected")
        self.file_label.setFont(QFont("Arial", 10))
        self.file_label.setStyleSheet("color: #aaaaaa;")
        self.file_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.file_label)

        # Analyze Button
        self.analyze_btn = QPushButton("Analyze File")
        self.analyze_btn.setFont(QFont("Arial", 12))
        self.analyze_btn.setStyleSheet(
            "QPushButton {"
            "background-color: #4CAF50;"
            "color: white;"
            "border: none;"
            "padding: 10px 20px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: #3e8e41;"
            "}"
            "QPushButton:disabled {"
            "background-color: #555555;"
            "color: #999999;"
            "}"
        )
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.analyze_file)
        layout.addWidget(self.analyze_btn, alignment=Qt.AlignCenter)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Back Button
        back_btn = QPushButton("Back to Options")
        back_btn.setFont(QFont("Arial", 11))
        back_btn.setStyleSheet(
            "QPushButton {"
            "background-color: transparent;"
            "color: #4a90e2;"
            "border: 1px solid #4a90e2;"
            "padding: 8px 16px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: rgba(74, 144, 226, 0.1);"
            "}"
        )
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        layout.addWidget(back_btn, alignment=Qt.AlignCenter)

        # Add spacer to push content up
        layout.addStretch()

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Email File",
            "",
            "Email Files (*.txt *.html *.eml);;All Files (*)"
        )
        
        if file_path:
            self.file_path = file_path
            self.file_label.setText(os.path.basename(file_path))
            self.analyze_btn.setEnabled(True)

    def analyze_file(self):
        if not hasattr(self, 'file_path'):
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return

        self.progress.setVisible(True)
        QTimer.singleShot(100, self._analyze_file_async)

    def _analyze_file_async(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            email_content = {'body': content}
            if self.file_path.endswith('.html'):
                email_content['body'] = EmailAnalyzer.extract_text_from_html(content)
            
            analysis_page = self.stacked_widget.widget(5)  # AnalyzePage is at index 5
            analysis_page.set_email_content(email_content)
            self.stacked_widget.setCurrentIndex(5)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze file: {str(e)}")
        finally:
            self.progress.setVisible(False)

class ManualInputPage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Title
        title = QLabel("Manual Input Analysis")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setStyleSheet("color: #4a90e2; margin-bottom: 20px;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        # Instructions
        instructions = QLabel(
            "Paste email content in the box below to analyze for phishing attempts.\n"
            "You can paste plain text or HTML email content."
        )
        instructions.setFont(QFont("Arial", 11))
        instructions.setStyleSheet("color: #cccccc; margin-bottom: 15px;")
        instructions.setAlignment(Qt.AlignCenter)
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        # Text Edit
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Arial", 11))
        self.text_edit.setStyleSheet(
            "QTextEdit {"
            "background-color: #2d2d2d;"
            "color: white;"
            "border: 1px solid #3d3d3d;"
            "padding: 10px;"
            "border-radius: 4px;"
            "}"
        )
        self.text_edit.setPlaceholderText("Paste email content here...")
        layout.addWidget(self.text_edit)

        # Analyze Button
        self.analyze_btn = QPushButton("Analyze Content")
        self.analyze_btn.setFont(QFont("Arial", 12))
        self.analyze_btn.setStyleSheet(
            "QPushButton {"
            "background-color: #4CAF50;"
            "color: white;"
            "border: none;"
            "padding: 10px 20px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: #3e8e41;"
            "}"
            "QPushButton:disabled {"
            "background-color: #555555;"
            "color: #999999;"
            "}"
        )
        self.analyze_btn.clicked.connect(self.analyze_content)
        layout.addWidget(self.analyze_btn, alignment=Qt.AlignCenter)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Back Button
        back_btn = QPushButton("Back to Options")
        back_btn.setFont(QFont("Arial", 11))
        back_btn.setStyleSheet(
            "QPushButton {"
            "background-color: transparent;"
            "color: #4a90e2;"
            "border: 1px solid #4a90e2;"
            "padding: 8px 16px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: rgba(74, 144, 226, 0.1);"
            "}"
        )
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        layout.addWidget(back_btn, alignment=Qt.AlignCenter)

    def analyze_content(self):
        content = self.text_edit.toPlainText().strip()
        if not content:
            QMessageBox.warning(self, "Warning", "Please enter some content to analyze.")
            return

        self.progress.setVisible(True)
        QTimer.singleShot(100, lambda: self._analyze_content_async(content))

    def _analyze_content_async(self, content):
        try:
            email_content = {'body': content}
            analysis_page = self.stacked_widget.widget(5)  # AnalyzePage is at index 5
            analysis_page.set_email_content(email_content)
            self.stacked_widget.setCurrentIndex(5)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze content: {str(e)}")
        finally:
            self.progress.setVisible(False)

class AnalyzePage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Title
        self.title = QLabel("Analysis Results")
        self.title.setFont(QFont("Arial", 20, QFont.Bold))
        self.title.setStyleSheet("color: #4a90e2; margin-bottom: 20px;")
        layout.addWidget(self.title, alignment=Qt.AlignCenter)

        # Risk Level Indicator
        self.risk_frame = QFrame()
        self.risk_frame.setStyleSheet(
            "QFrame {"
            "background-color: #2d2d2d;"
            "border-radius: 8px;"
            "padding: 15px;"
            "}"
        )
        risk_layout = QVBoxLayout()
        self.risk_frame.setLayout(risk_layout)

        risk_title = QLabel("Risk Assessment")
        risk_title.setFont(QFont("Arial", 14, QFont.Bold))
        risk_title.setStyleSheet("color: white; margin-bottom: 10px;")
        risk_layout.addWidget(risk_title)

        self.risk_label = QLabel()
        self.risk_label.setFont(QFont("Arial", 16, QFont.Bold))
        risk_layout.addWidget(self.risk_label, alignment=Qt.AlignCenter)

        self.risk_description = QLabel()
        self.risk_description.setFont(QFont("Arial", 11))
        self.risk_description.setWordWrap(True)
        risk_layout.addWidget(self.risk_description)

        layout.addWidget(self.risk_frame)

        # Scroll Area for Detailed Results
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border: none;")
        
        content = QWidget()
        self.scroll_layout = QVBoxLayout()
        content.setLayout(self.scroll_layout)
        scroll.setWidget(content)
        
        layout.addWidget(scroll)

        # Original Email Section
        self.original_frame = QFrame()
        self.original_frame.setStyleSheet(
            "QFrame {"
            "background-color: #2d2d2d;"
            "border-radius: 8px;"
            "padding: 15px;"
            "margin-top: 15px;"
            "}"
        )
        original_layout = QVBoxLayout()
        self.original_frame.setLayout(original_layout)

        original_title = QLabel("Original Email Content")
        original_title.setFont(QFont("Arial", 14, QFont.Bold))
        original_title.setStyleSheet("color: white; margin-bottom: 10px;")
        original_layout.addWidget(original_title)

        self.original_text = QTextEdit()
        self.original_text.setReadOnly(True)
        self.original_text.setFont(QFont("Arial", 11))
        self.original_text.setStyleSheet(
            "QTextEdit {"
            "background-color: #252525;"
            "color: white;"
            "border: 1px solid #3d3d3d;"
            "padding: 10px;"
            "border-radius: 4px;"
            "}"
        )
        original_layout.addWidget(self.original_text)

        self.scroll_layout.addWidget(self.original_frame)

        # Back Button
        back_btn = QPushButton("Back to Options")
        back_btn.setFont(QFont("Arial", 11))
        back_btn.setStyleSheet(
            "QPushButton {"
            "background-color: transparent;"
            "color: #4a90e2;"
            "border: 1px solid #4a90e2;"
            "padding: 8px 16px;"
            "border-radius: 4px;"
            "}"
            "QPushButton:hover {"
            "background-color: rgba(74, 144, 226, 0.1);"
            "}"
        )
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        layout.addWidget(back_btn, alignment=Qt.AlignCenter)

    def set_email_content(self, email_content):
        self.original_text.setPlainText(email_content.get('body', ''))
        
        # Perform analysis
        analysis = EmailAnalyzer.analyze_email_content(email_content['body'])
        
        # Update risk assessment
        risk_level = analysis['risk_level']
        if risk_level == "High":
            self.risk_label.setText("HIGH RISK")
            self.risk_label.setStyleSheet("color: #ff4444;")
            self.risk_description.setText(
                "This email contains multiple indicators of a phishing attempt. "
                "Do not click any links or provide any personal information."
            )
        else:
            self.risk_label.setText("LOW RISK")
            self.risk_label.setStyleSheet("color: #4CAF50;")
            self.risk_description.setText(
                "This email appears to be safe, but always exercise caution with "
                "unexpected messages requesting personal information."
            )

        # Clear previous results
        for i in reversed(range(self.scroll_layout.count())): 
            widget = self.scroll_layout.itemAt(i).widget()
            if widget is not None and widget != self.original_frame:
                widget.deleteLater()

        # Add keyword results
        if analysis['keyword_results']:
            kw_frame = QFrame()
            kw_frame.setStyleSheet(
                "QFrame {"
                "background-color: #2d2d2d;"
                "border-radius: 8px;"
                "padding: 15px;"
                "margin-top: 15px;"
                "}"
            )
            kw_layout = QVBoxLayout()
            kw_frame.setLayout(kw_layout)

            kw_title = QLabel("Suspicious Keywords Found")
            kw_title.setFont(QFont("Arial", 14, QFont.Bold))
            kw_title.setStyleSheet("color: white; margin-bottom: 10px;")
            kw_layout.addWidget(kw_title)

            for category, keywords in analysis['keyword_results'].items():
                cat_label = QLabel(f"{category}:")
                cat_label.setFont(QFont("Arial", 12, QFont.Bold))
                cat_label.setStyleSheet("color: #cccccc; margin-top: 10px;")
                kw_layout.addWidget(cat_label)

                for kw, count in keywords.items():
                    item = QLabel(f"• {kw} (found {count} time{'s' if count > 1 else ''})")
                    item.setFont(QFont("Arial", 11))
                    item.setStyleSheet("color: #aaaaaa; margin-left: 15px;")
                    kw_layout.addWidget(item)

            self.scroll_layout.insertWidget(0, kw_frame)

        # Add link results
        if analysis['suspicious_links']:
            links_frame = QFrame()
            links_frame.setStyleSheet(
                "QFrame {"
                "background-color: #2d2d2d;"
                "border-radius: 8px;"
                "padding: 15px;"
                "margin-top: 15px;"
                "}"
            )
            links_layout = QVBoxLayout()
            links_frame.setLayout(links_layout)

            links_title = QLabel("Suspicious Links Found")
            links_title.setFont(QFont("Arial", 14, QFont.Bold))
            links_title.setStyleSheet("color: white; margin-bottom: 10px;")
            links_layout.addWidget(links_title)

            links_info = QLabel(
                f"Found {analysis['suspicious_link_count']} suspicious links "
                f"out of {analysis['link_count']} total links."
            )
            links_info.setFont(QFont("Arial", 11))
            links_info.setStyleSheet("color: #cccccc; margin-bottom: 10px;")
            links_layout.addWidget(links_info)

            for link in analysis['suspicious_links']:
                item = QLabel(f"• {link[:80]}{'...' if len(link) > 80 else ''}")
                item.setFont(QFont("Arial", 11))
                item.setStyleSheet("color: #ff6666; margin-left: 15px;")
                item.setToolTip(link)
                links_layout.addWidget(item)

            self.scroll_layout.insertWidget(1 if analysis['keyword_results'] else 0, links_frame)

class PhishingDetectorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setWindowTitle("Phishing Email Detector")
        self.resize(1000, 800)
        self.setMinimumSize(800, 600)

    def init_ui(self):
        # Dark theme palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(35, 35, 35))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(50, 50, 50))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(74, 144, 226))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.setPalette(palette)

        # Stacked widget for multi-page interface
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # Create and add pages
        self.welcome_page = WelcomePage(self.stacked_widget)
        self.options_page = OptionsPage(self.stacked_widget)
        self.gmail_page = GmailPage(self.stacked_widget)
        self.file_page = FilePage(self.stacked_widget)
        self.manual_page = ManualInputPage(self.stacked_widget)
        self.analyze_page = AnalyzePage(self.stacked_widget)

        self.stacked_widget.addWidget(self.welcome_page)
        self.stacked_widget.addWidget(self.options_page)
        self.stacked_widget.addWidget(self.gmail_page)
        self.stacked_widget.addWidget(self.file_page)
        self.stacked_widget.addWidget(self.manual_page)
        self.stacked_widget.addWidget(self.analyze_page)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    
    # Set window icon if available
    try:
        app.setWindowIcon(QIcon('icon.png'))
    except:
        pass
    
    window = PhishingDetectorApp()
    window.show()
    sys.exit(app.exec())
