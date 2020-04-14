import sys

from PyQt5 import QtWidgets

from lib import crc
from ui.crc_ui import Ui_mainWindow

CRC_32_POLYNOMIAL = 0x04C11DB7


class Window(QtWidgets.QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.ui = Ui_mainWindow()
        self.ui.setupUi(self)

        self.ui.pushButton_welcome.clicked.connect(self.encode)
        self.ui.pushButton_cipher.clicked.connect(self.decode)

        self.labels = (self.ui.label_deciphered,
                       self.ui.label_cipher,
                       self.ui.label_welcome)

        self.ui.label_welcome.setText(f"Введите сообщение (целое число)")
        self.ui.label_cipher.setText("CRC-код (hex)")
        self.ui.label_deciphered.setText("Декодированное сообщение")

        for label in self.labels:
            label.adjustSize()

    def encode(self):
        try:
            message = int(self.ui.lineEdit_welcome.text())
            code = crc.encode(message, CRC_32_POLYNOMIAL)
            self.ui.lineEdit_cipher.setText(hex(code))
        except ValueError:
            return

    def decode(self):
        try:
            code = int(self.ui.lineEdit_cipher.text(), 16)
            deciphered = crc.decode(code, CRC_32_POLYNOMIAL)

        except ValueError:
            return

        except crc.CryptError:
            self.ui.lineEdit_deciphered.setText("Ошибка декодирования")
            return

        self.ui.lineEdit_deciphered.setText(str(deciphered))


app = QtWidgets.QApplication([])
application = Window()
application.show()
sys.exit(app.exec())
