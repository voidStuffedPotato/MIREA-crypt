# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '../ui/rsa_auth_ui.ui'
#
# Created by: PyQt5 UI code generator 5.14.2
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_mainWindow(object):
    def setupUi(self, mainWindow):
        mainWindow.setObjectName("mainWindow")
        mainWindow.resize(600, 320)
        mainWindow.setMinimumSize(QtCore.QSize(600, 320))
        mainWindow.setMaximumSize(QtCore.QSize(600, 320))
        mainWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.centralwidget = QtWidgets.QWidget(mainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(10, 10, 281, 81))
        self.gridLayoutWidget.setObjectName("gridLayoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.lineEdit_pubkey = QtWidgets.QLineEdit(self.gridLayoutWidget)
        self.lineEdit_pubkey.setObjectName("lineEdit_pubkey")
        self.gridLayout.addWidget(self.lineEdit_pubkey, 1, 0, 1, 3)
        self.label_pubkey = QtWidgets.QLabel(self.gridLayoutWidget)
        self.label_pubkey.setObjectName("label_pubkey")
        self.gridLayout.addWidget(self.label_pubkey, 0, 0, 1, 3)
        self.pushButton_new_pubkey = QtWidgets.QPushButton(self.gridLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButton_new_pubkey.sizePolicy().hasHeightForWidth())
        self.pushButton_new_pubkey.setSizePolicy(sizePolicy)
        self.pushButton_new_pubkey.setMaximumSize(QtCore.QSize(20000, 20))
        self.pushButton_new_pubkey.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_new_pubkey.setObjectName("pushButton_new_pubkey")
        self.gridLayout.addWidget(self.pushButton_new_pubkey, 2, 0, 1, 3)
        self.gridLayoutWidget_2 = QtWidgets.QWidget(self.centralwidget)
        self.gridLayoutWidget_2.setGeometry(QtCore.QRect(310, 120, 281, 121))
        self.gridLayoutWidget_2.setObjectName("gridLayoutWidget_2")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.gridLayoutWidget_2)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.label_message = QtWidgets.QLabel(self.gridLayoutWidget_2)
        self.label_message.setObjectName("label_message")
        self.gridLayout_2.addWidget(self.label_message, 4, 0, 1, 1)
        self.lineEdit_encrypted = QtWidgets.QLineEdit(self.gridLayoutWidget_2)
        self.lineEdit_encrypted.setObjectName("lineEdit_encrypted")
        self.gridLayout_2.addWidget(self.lineEdit_encrypted, 3, 0, 1, 2)
        self.label_encrypted = QtWidgets.QLabel(self.gridLayoutWidget_2)
        self.label_encrypted.setObjectName("label_encrypted")
        self.gridLayout_2.addWidget(self.label_encrypted, 2, 0, 1, 2)
        self.lineEdit_message = QtWidgets.QLineEdit(self.gridLayoutWidget_2)
        self.lineEdit_message.setObjectName("lineEdit_message")
        self.gridLayout_2.addWidget(self.lineEdit_message, 5, 0, 1, 1)
        self.verticalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(10, 120, 281, 123))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_encrypted_in = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_encrypted_in.setObjectName("label_encrypted_in")
        self.verticalLayout.addWidget(self.label_encrypted_in)
        self.lineEdit_encrypted_in = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        self.lineEdit_encrypted_in.setObjectName("lineEdit_encrypted_in")
        self.verticalLayout.addWidget(self.lineEdit_encrypted_in)
        self.pushButton_decrypt = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.pushButton_decrypt.setObjectName("pushButton_decrypt")
        self.verticalLayout.addWidget(self.pushButton_decrypt)
        self.label_decrypted = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_decrypted.setObjectName("label_decrypted")
        self.verticalLayout.addWidget(self.label_decrypted)
        self.lineEdit_decrypted = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        self.lineEdit_decrypted.setObjectName("lineEdit_decrypted")
        self.verticalLayout.addWidget(self.lineEdit_decrypted)
        self.gridLayoutWidget_3 = QtWidgets.QWidget(self.centralwidget)
        self.gridLayoutWidget_3.setGeometry(QtCore.QRect(310, 10, 281, 81))
        self.gridLayoutWidget_3.setObjectName("gridLayoutWidget_3")
        self.gridLayout_3 = QtWidgets.QGridLayout(self.gridLayoutWidget_3)
        self.gridLayout_3.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.pushButton_pubkey_in = QtWidgets.QPushButton(self.gridLayoutWidget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButton_pubkey_in.sizePolicy().hasHeightForWidth())
        self.pushButton_pubkey_in.setSizePolicy(sizePolicy)
        self.pushButton_pubkey_in.setMaximumSize(QtCore.QSize(20000, 20))
        self.pushButton_pubkey_in.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_pubkey_in.setObjectName("pushButton_pubkey_in")
        self.gridLayout_3.addWidget(self.pushButton_pubkey_in, 2, 0, 1, 1)
        self.label_pubkey_in = QtWidgets.QLabel(self.gridLayoutWidget_3)
        self.label_pubkey_in.setObjectName("label_pubkey_in")
        self.gridLayout_3.addWidget(self.label_pubkey_in, 0, 0, 1, 1)
        self.lineEdit_pubkey_in = QtWidgets.QLineEdit(self.gridLayoutWidget_3)
        self.lineEdit_pubkey_in.setObjectName("lineEdit_pubkey_in")
        self.gridLayout_3.addWidget(self.lineEdit_pubkey_in, 1, 0, 1, 1)
        self.label_effect = QtWidgets.QLabel(self.centralwidget)
        self.label_effect.setGeometry(QtCore.QRect(10, 250, 281, 16))
        self.label_effect.setObjectName("label_effect")
        mainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(mainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 600, 20))
        self.menubar.setObjectName("menubar")
        mainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(mainWindow)
        self.statusbar.setObjectName("statusbar")
        mainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(mainWindow)
        QtCore.QMetaObject.connectSlotsByName(mainWindow)

    def retranslateUi(self, mainWindow):
        _translate = QtCore.QCoreApplication.translate
        mainWindow.setWindowTitle(_translate("mainWindow", "MainWindow"))
        self.label_pubkey.setText(_translate("mainWindow", "TextLabel"))
        self.pushButton_new_pubkey.setText(_translate("mainWindow", "Новый открытый ключ"))
        self.label_message.setText(_translate("mainWindow", "TextLabel"))
        self.label_encrypted.setText(_translate("mainWindow", "TextLabel"))
        self.label_encrypted_in.setText(_translate("mainWindow", "TextLabel"))
        self.pushButton_decrypt.setText(_translate("mainWindow", "Расшифровать сообщение"))
        self.label_decrypted.setText(_translate("mainWindow", "TextLabel"))
        self.pushButton_pubkey_in.setText(_translate("mainWindow", "Сгенерировать зашифрованное сообщение"))
        self.label_pubkey_in.setText(_translate("mainWindow", "TextLabel"))
        self.label_effect.setText(_translate("mainWindow", "TextLabel"))
