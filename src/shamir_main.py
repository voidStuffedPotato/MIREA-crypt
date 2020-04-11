import sys
from shamir_src import shamir
from shamir_src.shamir_ui import Ui_mainWindow
from PyQt5 import QtWidgets, QtGui, QtCore
from common import random_prime

K = 3
N = 5
MODULO = random_prime(2 ** 16)


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

        self.ui.pushButton.clicked.connect(self.encrypt)
        self.ui.pushButton_2.clicked.connect(self.decrypt)

        self.labels = (self.ui.label_deciphered,
                       self.ui.label_keys,
                       self.ui.label_out,
                       self.ui.label_welcome)

        self.out_lineedits = (self.ui.lineEdit_right_1,
                              self.ui.lineEdit_right_2,
                              self.ui.lineEdit_right_3)

        self.key_lineedits = (self.ui.lineEdit_center_1,
                              self.ui.lineEdit_center_2,
                              self.ui.lineEdit_center_3,
                              self.ui.lineEdit_center_4,
                              self.ui.lineEdit_center_5)

        self.ui.label_welcome.setText(
            f"Введите секрет (целое число) меньшее {MODULO}"
        )
        self.ui.label_out.setText(
            """Ключи расшифрования (любые три разных)"""
        )
        self.ui.label_keys.setText("Полученные ключи")
        self.ui.label_deciphered.setText("Расшифрованный секрет")

        for label in self.labels:
            label.adjustSize()

    def encrypt(self):
        try:
            secret = int(self.ui.lineEdit_secret.text())
            keys = shamir.shamir_encrypt(secret, 3, 5, mod=MODULO)

            for (key, lineedit) in zip(keys, self.key_lineedits):
                lineedit.setText((str(key[0]) + ' ' + str(key[1])))

            # копируем ключи в поля ввода ключей
            for (key, lineedit) in list(zip(keys[:3], self.out_lineedits)):
                lineedit.setText((str(key[0]) + ' ' + str(key[1])))
        except ValueError:
            return

    def decrypt(self):
        keys = []
        try:
            for lineedit in self.out_lineedits:
                tup = parse_ints(lineedit.text())
                keys.append(tup)

        except ValueError:
            return

        self.ui.lineEdit_deciphered.setText(
            str(shamir.shamir_decrypt(keys, mod=MODULO))
        )


app = QtWidgets.QApplication([])
application = Window()
application.show()
sys.exit(app.exec())
