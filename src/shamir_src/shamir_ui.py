# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'shamir_ui.ui'
#
# Created by: PyQt5 UI code generator 5.14.2
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_mainWindow(object):
    def setupUi(self, mainWindow):
        mainWindow.setObjectName("mainWindow")
        mainWindow.resize(600, 300)
        mainWindow.setMinimumSize(QtCore.QSize(600, 300))
        mainWindow.setMaximumSize(QtCore.QSize(600, 300))
        mainWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.centralwidget = QtWidgets.QWidget(mainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(10, 10, 281, 91))
        self.gridLayoutWidget.setObjectName("gridLayoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 4, 2, 1, 1)
        self.pushButton = QtWidgets.QPushButton(self.gridLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButton.sizePolicy().hasHeightForWidth())
        self.pushButton.setSizePolicy(sizePolicy)
        self.pushButton.setMaximumSize(QtCore.QSize(100, 20))
        self.pushButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 4, 1, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem1, 4, 0, 1, 1)
        self.lineEdit_secret = QtWidgets.QLineEdit(self.gridLayoutWidget)
        self.lineEdit_secret.setObjectName("lineEdit_secret")
        self.gridLayout.addWidget(self.lineEdit_secret, 1, 0, 1, 3)
        self.label_welcome = QtWidgets.QLabel(self.gridLayoutWidget)
        self.label_welcome.setObjectName("label_welcome")
        self.gridLayout.addWidget(self.label_welcome, 0, 0, 1, 3)
        self.gridLayoutWidget_2 = QtWidgets.QWidget(self.centralwidget)
        self.gridLayoutWidget_2.setGeometry(QtCore.QRect(320, 10, 271, 121))
        self.gridLayoutWidget_2.setObjectName("gridLayoutWidget_2")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.gridLayoutWidget_2)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.lineEdit_center_3 = QtWidgets.QLineEdit(self.gridLayoutWidget_2)
        self.lineEdit_center_3.setObjectName("lineEdit_center_3")
        self.gridLayout_2.addWidget(self.lineEdit_center_3, 3, 0, 1, 1)
        self.lineEdit_center_4 = QtWidgets.QLineEdit(self.gridLayoutWidget_2)
        self.lineEdit_center_4.setObjectName("lineEdit_center_4")
        self.gridLayout_2.addWidget(self.lineEdit_center_4, 3, 1, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem2, 4, 1, 1, 1)
        self.lineEdit_center_1 = QtWidgets.QLineEdit(self.gridLayoutWidget_2)
        self.lineEdit_center_1.setObjectName("lineEdit_center_1")
        self.gridLayout_2.addWidget(self.lineEdit_center_1, 2, 0, 1, 1)
        self.lineEdit_center_5 = QtWidgets.QLineEdit(self.gridLayoutWidget_2)
        self.lineEdit_center_5.setObjectName("lineEdit_center_5")
        self.gridLayout_2.addWidget(self.lineEdit_center_5, 4, 0, 1, 1)
        self.lineEdit_center_2 = QtWidgets.QLineEdit(self.gridLayoutWidget_2)
        self.lineEdit_center_2.setObjectName("lineEdit_center_2")
        self.gridLayout_2.addWidget(self.lineEdit_center_2, 2, 1, 1, 1)
        self.label_keys = QtWidgets.QLabel(self.gridLayoutWidget_2)
        self.label_keys.setObjectName("label_keys")
        self.gridLayout_2.addWidget(self.label_keys, 0, 0, 1, 2)
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(320, 150, 271, 71))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_deciphered = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_deciphered.setObjectName("label_deciphered")
        self.verticalLayout_2.addWidget(self.label_deciphered)
        self.lineEdit_deciphered = QtWidgets.QLineEdit(self.verticalLayoutWidget_2)
        self.lineEdit_deciphered.setObjectName("lineEdit_deciphered")
        self.verticalLayout_2.addWidget(self.lineEdit_deciphered)
        self.verticalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(10, 150, 281, 100))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_out = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_out.setObjectName("label_out")
        self.verticalLayout.addWidget(self.label_out)
        self.gridLayout_3 = QtWidgets.QGridLayout()
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.pushButton_2 = QtWidgets.QPushButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButton_2.sizePolicy().hasHeightForWidth())
        self.pushButton_2.setSizePolicy(sizePolicy)
        self.pushButton_2.setMaximumSize(QtCore.QSize(100, 20))
        self.pushButton_2.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_2.setObjectName("pushButton_2")
        self.gridLayout_3.addWidget(self.pushButton_2, 2, 1, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_3.addItem(spacerItem3, 2, 2, 1, 1)
        self.lineEdit_right_1 = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        self.lineEdit_right_1.setObjectName("lineEdit_right_1")
        self.gridLayout_3.addWidget(self.lineEdit_right_1, 0, 0, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_3.addItem(spacerItem4, 2, 0, 1, 1)
        self.lineEdit_right_3 = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        self.lineEdit_right_3.setObjectName("lineEdit_right_3")
        self.gridLayout_3.addWidget(self.lineEdit_right_3, 0, 2, 1, 1)
        self.lineEdit_right_2 = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        self.lineEdit_right_2.setObjectName("lineEdit_right_2")
        self.gridLayout_3.addWidget(self.lineEdit_right_2, 0, 1, 1, 1)
        self.verticalLayout.addLayout(self.gridLayout_3)
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
        self.pushButton.setText(_translate("mainWindow", "Зашифровать"))
        self.label_welcome.setText(_translate("mainWindow", "TextLabel"))
        self.label_keys.setText(_translate("mainWindow", "TextLabel"))
        self.label_deciphered.setText(_translate("mainWindow", "TextLabel"))
        self.label_out.setText(_translate("mainWindow", "TextLabel"))
        self.pushButton_2.setText(_translate("mainWindow", "Расшифровать"))
