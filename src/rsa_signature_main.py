import sys
from lib import rsa
from lib.rsa_signature_ui import Ui_mainWindow
from lib.common import random_prime
from PyQt5 import QtWidgets, QtGui, QtCore


def parse_ints(target: str) -> (int, int):
    args = target.split()
    ret_val = []

    for arg in args:
        if len(ret_val) == 2:
            break
        ret_val.append(int(arg))

    if len(ret_val) < 2:
        raise ValueError("Not enough arguments")

    return tuple(ret_val)


class Window(QtWidgets.QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.ui = Ui_mainWindow()
        self.ui.setupUi(self)

        self.ui.pushButton_new_pubkey.clicked.connect(self.new_pubkey)
        self.ui.pushButton_encrypt.clicked.connect(self.encrypt)
        self.ui.pushButton_check.clicked.connect(self.decrypt)

        labels = (self.ui.label_pubkey,
                  self.ui.label_input,
                  self.ui.label_output,
                  self.ui.label_pubkey_in,
                  self.ui.label_signature_in,
                  self.ui.label_signature)

        self.ui.label_pubkey.setText("Открытый ключ")
        self.ui.label_input.setText("Введите сообщение")
        self.ui.label_signature.setText("Подпись (зашифрованный хэш md5)")
        self.ui.label_pubkey_in.setText("Введите открытый ключ")
        self.ui.label_signature_in.setText("Введите подпись")
        self.ui.label_output.setText("Введите полученное сообщение")
        self.ui.label_result.setText("")

        for label in labels:
            label.adjustSize()

        for lineedit in (self.ui.lineEdit_pubkey, self.ui.lineEdit_signature):
            lineedit.setReadOnly(True)

        self.new_pubkey()

    def new_pubkey(self):
        self.rsa_sender = rsa.RsaSignature()
        pubkey = self.rsa_sender.get_pubkey()
        pubkey = str(pubkey[0]) + ' ' + str(pubkey[1])

        self.ui.lineEdit_pubkey.setText(pubkey)
        self.ui.lineEdit_pubkey_in.setText(pubkey)

    def encrypt(self):
        text = self.ui.textEdit_input.toPlainText()
        if text:
            self.ui.textEdit_output.setText(text)

            self.rsa_sender.update(text.encode())

            signature = self.rsa_sender.signature()[0]
            self.ui.lineEdit_signature.setText(signature.decode())
            self.ui.lineEdit_signature_in.setText(signature.decode())

    def decrypt(self):
        try:
            text = self.ui.textEdit_output.toPlainText().encode()
            signature = self.ui.lineEdit_signature_in.text().encode()
            pubkey = parse_ints(self.ui.lineEdit_pubkey_in.text())

            rsa_getter = rsa.RsaSignature()
            auth = rsa_getter.compare_signature((signature, text), pubkey)
            if auth:
                self.ui.label_result.setStyleSheet("color: rgb(21, 199, 0);")
                self.ui.label_result.setText("Подпись подтверждена")
            else:
                self.ui.label_result.setStyleSheet("color: rgb(221, 0, 0);")
                self.ui.label_result.setText("Ошибка")
        except ValueError:
            return


app = QtWidgets.QApplication([])
application = Window()
application.show()
sys.exit(app.exec())
