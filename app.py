import sys
from PyQt6 import QtWidgets
from PyQt6.QtWidgets import QDialog
from LoginWindow import LoginWindow
from MainWindow import MainWindow

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    login = LoginWindow()
    if login.exec() == QDialog.DialogCode.Accepted:
        window = MainWindow(login.accepted_user, login.accepted_enc_key)
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(0)
