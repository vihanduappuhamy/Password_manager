import time
from LoginDatabase import AuthentionDatabase
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QWidget,
    QStackedWidget, QMessageBox
)
from PyQt6.QtCore import Qt


class LoginWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.accepted_user = None
        self.enc_key = None  # encryption key after login
        self.db = AuthentionDatabase()
        self.setWindowTitle("Login")
        self.setFixedSize(500, 500)

        self.stackedWidget = QStackedWidget(self)
        self.loginPage = QWidget()
        self.createAccountPage = QWidget()
        self.stackedWidget.addWidget(self.loginPage)
        self.stackedWidget.addWidget(self.createAccountPage)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.stackedWidget)
        self.setLayout(main_layout)

        # Setup pages
        self.setup_login_page()
        self.setup_create_account_page()
        self.stackedWidget.setCurrentIndex(0)

    # -------------------------------
    # Login page
    # -------------------------------
    def setup_login_page(self):
        layout = QVBoxLayout()
        title = QLabel("Login")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.usernameInput = QLineEdit()
        self.usernameInput.setPlaceholderText("Username")
        self.passwordInput = QLineEdit()
        self.passwordInput.setEchoMode(QLineEdit.EchoMode.Password)
        self.passwordInput.setPlaceholderText("Password")

        self.loginButton = QPushButton("Login")
        self.loginButton.clicked.connect(self.verify_login)
        self.gotoCreateButton = QPushButton("Create Account")
        self.gotoCreateButton.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(1))

        layout.addWidget(title)
        layout.addWidget(self.usernameInput)
        layout.addWidget(self.passwordInput)
        layout.addWidget(self.loginButton)
        layout.addWidget(self.gotoCreateButton)

        self.loginPage.setLayout(layout)

    # -------------------------------
    # Create account page
    # -------------------------------
    def create_account(self):
        username = self.newUsernameInput.text().strip()
        password = self.newPasswordInput.text()
        confirm = self.confirmPasswordInput.text()
        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password cannot be empty")
            return
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return
        try:
            self.db.create_user(username, password)
            QMessageBox.information(self, "Success", "Account created successfully")
            self.stackedWidget.setCurrentIndex(0)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed: {str(e)}")

    def setup_create_account_page(self):
        layout = QVBoxLayout()
        self.createTitle = QLabel("Create Account")
        self.createTitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.newUsernameInput = QLineEdit()
        self.newUsernameInput.setPlaceholderText("New Username")
        self.newPasswordInput = QLineEdit()
        self.newPasswordInput.setEchoMode(QLineEdit.EchoMode.Password)
        self.newPasswordInput.setPlaceholderText("New Password")
        self.confirmPasswordInput = QLineEdit()
        self.confirmPasswordInput.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirmPasswordInput.setPlaceholderText("Confirm Password")

        self.submitButton = QPushButton("Submit")
        self.submitButton.clicked.connect(self.create_account)
        self.backButton = QPushButton("Back to Login")
        self.backButton.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(0))

        layout.addWidget(self.createTitle)
        layout.addWidget(self.newUsernameInput)
        layout.addWidget(self.newPasswordInput)
        layout.addWidget(self.confirmPasswordInput)
        layout.addWidget(self.submitButton)
        layout.addWidget(self.backButton)
        self.createAccountPage.setLayout(layout)

    # -------------------------------
    # Login verification
    # -------------------------------
    def verify_login(self):
        username = self.usernameInput.text()
        password = self.passwordInput.text()
        locked, remaining = self.db.is_locked_out(username)
        if locked:
            QMessageBox.warning(self, "Locked Out", f"Try again in {int(remaining)} seconds")
            return

        if self.db.verify_user(username, password):
            self.accepted_user = username
            self.accepted_enc_key = self.db.enc_key  # <- store encryption key
            self.accept()  # closes login dialog with Accepted
        else:
            QMessageBox.warning(self, "Error", "Invalid username or password")

