import random
import string
from PyQt6 import QtWidgets
from PyQt6.QtWidgets import QMainWindow, QMessageBox, QPushButton, QButtonGroup
from LoginDatabase import AuthentionDatabase


# -----------------------------
# UI Class
# -----------------------------
class ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.MainLayout = QtWidgets.QVBoxLayout(self.centralwidget)

        # Navigation buttons
        self.MenuLayout = QtWidgets.QVBoxLayout()
        self.ProfileButton = QPushButton("Profile", checkable=True)
        self.PasswordsButton = QPushButton("Passwords", checkable=True)
        self.ProfileButton.setFixedSize(100, 30)
        self.PasswordsButton.setFixedSize(100, 30)

        self.MenuButtonGroup = QButtonGroup()
        self.MenuButtonGroup.addButton(self.ProfileButton)
        self.MenuButtonGroup.addButton(self.PasswordsButton)
        self.MenuButtonGroup.setExclusive(True)

        self.MenuLayout.addWidget(self.PasswordsButton)
        self.MenuLayout.addWidget(self.ProfileButton)
        self.MainLayout.addLayout(self.MenuLayout)

        # Status label
        self.PageStatusLabel = QtWidgets.QLabel("Current Page: Passwords")
        self.MainLayout.addWidget(self.PageStatusLabel)

        # Stacked widget
        self.stackedWidget = QtWidgets.QStackedWidget()
        self.MainLayout.addWidget(self.stackedWidget)

        # Setup pages
        self.setup_password_page()
        self.setup_profile_page()

        MainWindow.setCentralWidget(self.centralwidget)

    def setup_password_page(self):
        self.passwordPage = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(self.passwordPage)

        self.websiteInput = QtWidgets.QLineEdit()
        self.websiteInput.setPlaceholderText("Website")

        self.siteUsernameInput = QtWidgets.QLineEdit()
        self.siteUsernameInput.setPlaceholderText("Site Username")

        self.sitePasswordInput = QtWidgets.QLineEdit()
        self.sitePasswordInput.setPlaceholderText("Password")

        self.generatePasswordButton = QPushButton("Generate Strong Password")
        self.addPasswordButton = QPushButton("Add Password")
        self.passwordList = QtWidgets.QTextEdit()
        self.passwordList.setReadOnly(True)
        self.passwordList.setPlaceholderText("Passwords will be displayed here")

        layout.addWidget(self.websiteInput)
        layout.addWidget(self.siteUsernameInput)
        layout.addWidget(self.sitePasswordInput)
        layout.addWidget(self.generatePasswordButton)
        layout.addWidget(self.addPasswordButton)
        layout.addWidget(QtWidgets.QLabel("Stored Passwords:"))
        layout.addWidget(self.passwordList)

        self.stackedWidget.addWidget(self.passwordPage)

    def setup_profile_page(self):
        self.profilePage = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(self.profilePage)

        self.currentUsernameLabel = QtWidgets.QLabel("Current Username:")
        self.newUsernameInput = QtWidgets.QLineEdit()
        self.newUsernameInput.setPlaceholderText("New Username")

        self.currentPasswordInput = QtWidgets.QLineEdit()
        self.currentPasswordInput.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.currentPasswordInput.setPlaceholderText("Current Password")

        self.newPasswordInput = QtWidgets.QLineEdit()
        self.newPasswordInput.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.newPasswordInput.setPlaceholderText("New Password")

        self.confirmNewPasswordInput = QtWidgets.QLineEdit()
        self.confirmNewPasswordInput.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.confirmNewPasswordInput.setPlaceholderText("Confirm New Password")

        self.updateProfileButton = QPushButton("Update Profile")

        layout.addWidget(self.currentUsernameLabel)
        layout.addWidget(self.newUsernameInput)
        layout.addWidget(self.currentPasswordInput)
        layout.addWidget(self.newPasswordInput)
        layout.addWidget(self.confirmNewPasswordInput)
        layout.addWidget(self.updateProfileButton)

        self.stackedWidget.addWidget(self.profilePage)


# -----------------------------
# Main Window Class
# -----------------------------
class MainWindow(QMainWindow):
    def __init__(self, logged_in_user, enc_key):
        super().__init__()
        self.ui = ui_MainWindow()
        self.ui.setupUi(self)

        self.db = AuthentionDatabase()
        self.db.enc_key = enc_key
        self.logged_in_user = logged_in_user

        # Connect buttons
        self.ui.ProfileButton.clicked.connect(self.go_to_profile)
        self.ui.PasswordsButton.clicked.connect(self.go_to_passwords)
        self.ui.updateProfileButton.clicked.connect(self.update_profile)
        self.ui.generatePasswordButton.clicked.connect(self.generate_strong_password)
        self.ui.addPasswordButton.clicked.connect(self.add_password_entry)

        # Default page
        self.ui.PasswordsButton.setChecked(True)
        self.ui.stackedWidget.setCurrentIndex(0)
        self.display_stored_passwords()

    # Navigation
    def go_to_profile(self, checked):
        if checked:
            self.ui.stackedWidget.setCurrentIndex(1)
            self.ui.PageStatusLabel.setText("Current Page: Profile")
            self.ui.currentUsernameLabel.setText(f"Current Username: {self.logged_in_user}")

    def go_to_passwords(self, checked):
        if checked:
            self.ui.stackedWidget.setCurrentIndex(0)
            self.ui.PageStatusLabel.setText("Current Page: Passwords")
            self.display_stored_passwords()

    # Password management
    def generate_strong_password(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>/?"
        password = ''.join(random.SystemRandom().choice(chars) for _ in range(20))
        self.ui.sitePasswordInput.setText(password)

    def add_password_entry(self):
        website = self.ui.websiteInput.text().strip()
        site_username = self.ui.siteUsernameInput.text().strip()
        site_password = self.ui.sitePasswordInput.text().strip()

        if not website or not site_password:
            QMessageBox.warning(self, "Input Error", "Website and password are required.")
            return

        try:
            self.db.save_website_password(self.logged_in_user, website, site_username, site_password)
            QMessageBox.information(self, "Success", "Password added successfully.")
            self.display_stored_passwords()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save password: {str(e)}")

    def display_stored_passwords(self):
        try:
            entries = self.db.get_passwords_for_user(self.logged_in_user)
        except ValueError:
            self.ui.passwordList.setText("[Encryption key missing. Login required.]")
            return

        output = "\n".join(
            [f"Website: {w}\nUsername: {u or 'N/A'}\nPassword: {p}\n{'-'*40}" for w, u, p in entries]
        )
        self.ui.passwordList.setText(output)

    # Profile management
    def update_profile(self):
        current_pw = self.ui.currentPasswordInput.text()
        new_username = self.ui.newUsernameInput.text().strip()
        new_pw = self.ui.newPasswordInput.text()
        confirm_pw = self.ui.confirmNewPasswordInput.text()

        if not self.db.verify_user(self.logged_in_user, current_pw):
            QMessageBox.warning(self, "Error", "Current password is incorrect.")
            return

        if new_pw and new_pw != confirm_pw:
            QMessageBox.warning(self, "Error", "New passwords do not match.")
            return

        try:
            if new_username:
                self.db.update_username(self.logged_in_user, new_username)
                self.logged_in_user = new_username
            if new_pw:
                self.db.update_password(self.logged_in_user, new_pw)

            QMessageBox.information(self, "Success", "Profile updated successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Update failed: {str(e)}")
