import sys

from PyQt5 import QtWidgets

from lib import rsa
from ui.rsa_auth_ui import Ui_mainWindow


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
        self.ui.pushButton_pubkey_in.clicked.connect(self.check_auth)
        self.ui.pushButton_decrypt.clicked.connect(self.decrypt)

        labels = (self.ui.label_pubkey,
                  self.ui.label_pubkey_in,
                  self.ui.label_encrypted,
                  self.ui.label_encrypted_in,
                  self.ui.label_decrypted,
                  self.ui.label_message)

        self.ui.label_pubkey.setText("Открытый ключ")
        self.ui.label_encrypted_in.setText("Введите зашифрованное сообщение")
        self.ui.label_decrypted.setText("Расшифрованное сообщение")
        self.ui.label_pubkey_in.setText("Введите открытый ключ")
        self.ui.label_encrypted.setText("Зашифрованное сообщение")
        self.ui.label_message.setText("Сгенерированное сообщение")

        for label in labels:
            label.adjustSize()

        for lineedit in (self.ui.lineEdit_pubkey,
                         self.ui.lineEdit_encrypted,
                         self.ui.lineEdit_decrypted,
                         self.ui.lineEdit_message):
            lineedit.setReadOnly(True)

        self.new_pubkey()

    def new_pubkey(self):
        self.rsa_sender = rsa.RsaPlain()
        pubkey = self.rsa_sender.get_pubkey()
        pubkey = str(pubkey[0]) + ' ' + str(pubkey[1])

        self.ui.lineEdit_pubkey.setText(pubkey)
        self.ui.lineEdit_pubkey_in.setText(pubkey)

    def check_auth(self):
        try:
            self.rsa_receiver = rsa.RsaPlain()
            pubkey = parse_ints(self.ui.lineEdit_pubkey_in.text())

            msg = str(self.rsa_receiver.generate_message(pubkey))
            encrypted = str(self.rsa_receiver.encrypt(int(msg), pubkey))
            self.msg = msg

            self.ui.lineEdit_message.setText(msg)
            self.ui.lineEdit_encrypted.setText(encrypted)

            self.ui.lineEdit_encrypted_in.setText(encrypted)
        except ValueError:
            return

    def decrypt(self):
        try:
            encrypted = int(self.ui.lineEdit_encrypted_in.text())
            decrypted = str(self.rsa_sender.decrypt(encrypted))

            auth = self.msg == decrypted

            self.ui.lineEdit_decrypted.setText(decrypted)
            if auth:
                self.ui.label_effect.setStyleSheet("color: rgb(21, 199, 0);")
                self.ui.label_effect.setText("Аутентификация пройдена")
            else:
                self.ui.label_effect.setStyleSheet("color: rgb(221, 0, 0);")
                self.ui.label_effect.setText("Ошибка")
        except ValueError:
            return


app = QtWidgets.QApplication([])
application = Window()
application.show()
sys.exit(app.exec())
