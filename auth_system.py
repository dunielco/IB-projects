import sys, os
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QGridLayout, QLabel, QLineEdit, QFileDialog, QMessageBox, QListWidget, QInputDialog
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from cryptography.fernet import Fernet

with open("key.txt", "rb") as f:
    cipher_key = f.read()
cipher = Fernet(cipher_key)

def encryptFile():
    with open("users.txt", "rb") as f:        
        encrypted_text = cipher.encrypt(f.read())
    with open("C:/Users/Dzuiny/AppData/LocalLow/secret.txt", "wb") as f:
        f.write(encrypted_text)
    with open("users.txt", "w") as f:
        f.truncate()

username_to = ""

# зашифрованный файл при выключенной проге, перезаписывать зашифрованный файл
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.myclose = False

        self.setWindowTitle("Система авторизации")
        self.setFixedSize(400, 130)

        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)

        self.mainLayout = QVBoxLayout()
        self.centralWidget.setLayout(self.mainLayout)

        self.gridLayout = QGridLayout()
        self.mainLayout.addLayout(self.gridLayout)

        self.usernameLabel = QLabel("Логин:")
        self.gridLayout.addWidget(self.usernameLabel, 0, 0)

        self.usernameLineEdit = QLineEdit()
        self.gridLayout.addWidget(self.usernameLineEdit, 0, 1)

        self.passwordLabel = QLabel("Пароль:")
        self.gridLayout.addWidget(self.passwordLabel, 1, 0)

        self.passwordLineEdit = QLineEdit()
        self.passwordLineEdit.setEchoMode(QLineEdit.Password)
        self.gridLayout.addWidget(self.passwordLineEdit, 1, 1)

        self.loginButton = QPushButton("Войти")
        self.gridLayout.addWidget(self.loginButton, 2, 1)

        self.exitButton = QPushButton("Выйти")
        self.gridLayout.addWidget(self.exitButton, 3, 1)

        self.messageBox = QMessageBox()        
        self.messageBox.setWindowTitle(" ")

        self.loginButton.clicked.connect(self.login)
        self.exitButton.clicked.connect(self.exit)
        self.count = 0
    
        if not os.path.exists("users.txt"):
            with open("users.txt", "w") as f:
                f.write(f"ADMIN,,False,0")
        else:
            password, ok = QInputDialog.getText(self, "Доступ к базе", "Введите пароль:", QLineEdit.Password)
            if ok:
                if password == "access":
                    with open("C:/Users/Dzuiny/AppData/LocalLow/secret.txt", "rb") as f:        
                        decrypted_text = cipher.decrypt(f.read()).decode()
                    with open("users.txt", "w") as f:
                        f.write(decrypted_text)
                    with open("users.txt", "r") as f:
                        lines = f.readlines()
                    with open("users.txt", "w") as f:
                        for line in lines:
                            if line.strip():
                                f.write(line)
                else: 
                    QMessageBox.warning(self, "Ошибка!", "Неверный пароль.")
                    exit()
            else:
                exit()

    def login(self):
        global username_to
        username = self.usernameLineEdit.text()
        password = self.passwordLineEdit.text()
        with open("users.txt", "r") as f:
            for line in f:
                username_check = line.split(",")[0]
                password_check = line.split(",")[1]
                blocked_check = line.split(",")[2]

                if username == username_check and password == password_check and blocked_check == "True":
                    QMessageBox.warning(self, "Внимание!", "Вы заблокированы!")
                    self.count = 0
                    break

                if username == "ADMIN" and username == username_check and password == password_check:
                    QMessageBox.information(self, "Успех!", "Вы вошли как администратор")
                    self.showAdminInterface()
                    self.close()
                    self.count = 0
                    break

                if username == username_check and username != "ADMIN" and password == password_check:
                    QMessageBox.information(self, "Успех!", "Добро пожаловать, " + username + "!")
                    username_to = username
                    self.showUserInterface()
                    self.close()
                    self.count = 0
                    
                    break
            else:
                QMessageBox.critical(self, "Внимание!", "Неверные данные!")
                self.count += 1
                if self.count == 3:
                    self.close()

    def closeEvent(self, event):
        if self.myclose:
            encryptFile()		
        else:
            event.ignore()

    def exit(self):
        encryptFile()
        exit()

    def showAdminInterface(self):
        self.adminWindow = AdminWindow()
        self.adminWindow.show()

    def showUserInterface(self):
        self.userWindow = UserWindow()
        self.userWindow.show()

class AdminWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.myclose = False

        self.setWindowTitle("Профиль администратора")
        self.setFixedSize(600, 400)

        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)

        self.mainLayout = QVBoxLayout()
        self.centralWidget.setLayout(self.mainLayout)

        self.gridLayout = QGridLayout()
        self.mainLayout.addLayout(self.gridLayout)

        self.userListLabel = QLabel("Список пользователей:")
        self.gridLayout.addWidget(self.userListLabel, 0, 0)

        self.userListWidget = QListWidget()
        self.gridLayout.addWidget(self.userListWidget, 1, 0)

        self.addUserButton = QPushButton("Добавить пользователя")
        self.gridLayout.addWidget(self.addUserButton, 2, 0)

        self.removeUserButton = QPushButton("Удалить пользователя")
        self.gridLayout.addWidget(self.removeUserButton, 3, 0)

        self.blockUserButton = QPushButton("Заблокировать пользователя")
        self.gridLayout.addWidget(self.blockUserButton, 4, 0)

        self.unblockUserButton = QPushButton("Разблокировать пользователя")
        self.gridLayout.addWidget(self.unblockUserButton, 5, 0)

        self.changeLengthButton = QPushButton("Изменить длину пароля")
        self.gridLayout.addWidget(self.changeLengthButton, 6, 0)

        self.changePasswordButton = QPushButton("Сменить свой пароль")
        self.gridLayout.addWidget(self.changePasswordButton, 7, 0)

        self.exitButton = QPushButton("Выйти")
        self.gridLayout.addWidget(self.exitButton, 8, 0)

        self.addUserButton.clicked.connect(self.addUser)
        self.removeUserButton.clicked.connect(self.removeUser)
        self.blockUserButton.clicked.connect(self.blockUser)
        self.unblockUserButton.clicked.connect(self.unblockUser)
        self.changeLengthButton.clicked.connect(self.changeLength)
        self.changePasswordButton.clicked.connect(self.changePassword)
        self.exitButton.clicked.connect(self.exit)

        self.loadUserList()

        with open("users.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.split(",")[0] == "ADMIN":                    
                    if line.split(",")[1] == "":
                        self.changePasswordFirst()
                        encryptFile()
                        exit()
                        break

    def closeEvent(self, event):
        if self.myclose:
            encryptFile()	
        else:
            event.ignore()

    def loadUserList(self):
        self.userListWidget.clear()
        with open("users.txt", "r") as f:
            for line in f:
                if line != "":
                    username, password, blocked, length = line.strip().split(",")
                    user_info = username + "," + blocked + "," + length
                    self.userListWidget.addItem(user_info)

    def addUser(self):
        username, ok = QInputDialog.getText(self, "Добавление пользователя", "Введите имя:")
        error = False
        if ok:
            with open("users.txt", "r") as f:                
                for line in f:
                    if username == line.split(",")[0]:
                        QMessageBox.warning(self, "Ошибка", "Пользователь уже существует.")
                        error = True
                        break                    
            if error == False:        
                with open("users.txt", "a") as a:
                    a.write(f"\r{username},,False,0")

        self.loadUserList()

    def removeUser(self):
        username = self.userListWidget.currentItem().text().split(",")[0]
        if username == "ADMIN":
            QMessageBox.warning(self, "Ошибка", "Пользователя нельзя удалить!")
            return
        reply = QMessageBox.question(self, "Подтверждение", "Вы уверены, что хотите удалить пользователя {}?".format(username), QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] != username:
                        f.write(line)
        
        self.loadUserList()

    def blockUser(self):
        username = self.userListWidget.currentItem().text().split(",")[0]
        if username == "ADMIN":
            QMessageBox.warning(self, "Ошибка", "Пользователя нельзя заблокировать!")
            return
        reply = QMessageBox.question(self, "Подтверждение", "Вы уверены, что хотите заблокировать пользователя {}?".format(username), QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] == username:
                        line = line.replace("False", "True")
                    f.write(line)

        self.loadUserList()

    def unblockUser(self):
        username = self.userListWidget.currentItem().text().split(",")[0]
        reply = QMessageBox.question(self, "Подтверждение", "Вы уверены, что хотите разблокировать пользователя {}?".format(username), QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] == username:
                        line = line.replace("True", "False")
                    f.write(line)
        self.loadUserList()

    def changeLength(self):
        username = self.userListWidget.currentItem().text().split(",")[0]
        length, ok = QInputDialog.getText(self, "Изменение длины пароля", "Введите новую длину:")
        if ok:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] == username:
                        length_old = line.split(",")[3]
                        if int(length) >= 0 and length != "":                            
                            line = line.replace(f",{length_old}", f",{length}\n")             
                            QMessageBox.information(self, "Успех!", "Длина пароля изменена.")
                        else:
                            QMessageBox.warning(self, "Ошибка", "Неверная длина пароля.")
                    f.write(line)
        self.loadUserList()


    def changePasswordFirst(self):
        error = False
        username = "ADMIN"
        password, ok = QInputDialog.getText(self, "Смена пароля", "Введите новый пароль:", QLineEdit.Password)
        if ok:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] == username:
                        if len(password) > int(line.split(",")[3]):
                            line = line.replace(",,", f",{password},")                            
                            QMessageBox.information(self, "Успех!", "Пароль изменен.")                               
                        else:
                            QMessageBox.warning(self,"Слишком короткий пароль!", "Пароль долже быть длиной более " + line.split(",")[3] + " символа(ов)")
                            error = True
                    f.write(line)
        if error == True:
            encryptFile()            
            exit() 

    def changePassword(self):
        username = "ADMIN"
        password_old, ok = QInputDialog.getText(self, "Смена пароля", "Введите текущий пароль:", QLineEdit.Password)
        if ok:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] == username:
                        current_password = line.split(",")[1]
                        if current_password == password_old:
                            password_new, ok = QInputDialog.getText(self, "Смена пароля", "Введите новый пароль:", QLineEdit.Password)
                            if len(password_new) > int(line.split(",")[3]):
                                line = line.replace(f",{password_old},", f",{password_new},")                            
                                QMessageBox.information(self, "Успех!", "Пароль изменен.")
                            else:
                                QMessageBox.warning(self,"Слишком короткий пароль!", "Пароль долже быть длиной более " + line.split(",")[3] + " символа(ов)")
                        else:
                            QMessageBox.warning(self, "Ошибка", "Неверный текущий пароль.")
                    f.write(line)

    def exit(self):
        encryptFile()
        exit()

class UserWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        with open("users.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.split(",")[0] == username_to:                    
                    if line.split(",")[1] == "":
                        self.changePasswordFirst()
                        encryptFile()
                        exit()
                        break
                    if len(line.split(",")[1]) <= int(line.split(",")[3]):
                        self.changePassword()
                        encryptFile()
                        exit()
                        break

        self.setWindowTitle("Профиль пользователя")
        self.setFixedSize(200, 100)

        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)

        self.mainLayout = QVBoxLayout()
        self.centralWidget.setLayout(self.mainLayout)

        self.gridLayout = QGridLayout()
        self.mainLayout.addLayout(self.gridLayout)

        self.changePasswordButton = QPushButton("Сменить свой пароль")
        self.gridLayout.addWidget(self.changePasswordButton, 1, 0)

        self.exitButton = QPushButton("Выйти")
        self.gridLayout.addWidget(self.exitButton, 2, 0)

        self.changePasswordButton.clicked.connect(self.changePassword)
        self.exitButton.clicked.connect(self.exit)

    def exit(self):
        encryptFile()
        exit()

    def changePasswordFirst(self):
        error = False
        password, ok = QInputDialog.getText(self, "Смена пароля", "Введите новый пароль:", QLineEdit.Password)
        password2, ok = QInputDialog.getText(self, "Смена пароля", "Введите новый пароль повторно:", QLineEdit.Password)
        if ok:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] == username_to:
                        if len(password) > int(line.split(",")[3]):
                            if password == password2:
                                line = line.replace(",,", f",{password},")                            
                                QMessageBox.information(self, "Успех!", "Пароль изменен.")
                            else:
                                QMessageBox.warning(self, "Ошибка!", "Пароли не совпадают!")                              
                        else:
                            QMessageBox.warning(self,"Слишком короткий пароль!", "Пароль долже быть длиной более " + line.split(",")[3] + " символа(ов)")
                            error = True
                    f.write(line)
        if error == True:
            encryptFile()            
            exit() 

    def changePassword(self):
        password_old, ok = QInputDialog.getText(self, "Смена пароля", "Введите текущий пароль:", QLineEdit.Password)
        if ok:
            with open("users.txt", "r") as f:
                lines = f.readlines()
            with open("users.txt", "w") as f:
                for line in lines:
                    if line.split(",")[0] == username_to:
                        current_password = line.split(",")[1]
                        if current_password == password_old:
                            password_new, ok = QInputDialog.getText(self, "Смена пароля", "Введите новый пароль:", QLineEdit.Password)
                            password_new2, ok = QInputDialog.getText(self, "Смена пароля", "Введите пароль повторно:", QLineEdit.Password)
                            if len(password_new) > int(line.split(",")[3]):
                                if password_new == password_new2:
                                    line = line.replace(f",{password_old},", f",{password_new},")                            
                                    QMessageBox.information(self, "Успех!", "Пароль изменен.")
                                else:
                                    QMessageBox.warning(self, "Ошибка!", "Пароли не совпадают!")
                            else:
                                QMessageBox.warning(self,"Слишком короткий пароль!", "Пароль долже быть длиной более " + line.split(",")[3] + " символа(ов)")
                        else:
                            QMessageBox.warning(self, "Ошибка!", "Неверный текущий пароль.")
                    f.write(line)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())