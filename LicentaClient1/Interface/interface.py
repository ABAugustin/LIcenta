import socket
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QLineEdit, QVBoxLayout, QHBoxLayout, QWidget, QDialog, QDialogButtonBox, QFileDialog
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import sys
from PyQt5.QtGui import QGuiApplication

# Import your other modules here
from AES.AESOperations import derive_key
from Wireguard.Wireguard import generate_safe_word, final_wireguard_setup
from Headers.headers import *
from main import receive_ssl_greeting_certificate_main, diffie_hellman_exchange, set_up_and_send_wg_dto, receive_pairing_dto


class PasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Root Password")
        self.setFixedSize(400, 200)

        # Set custom stylesheet for the dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #2E3440;
                color: white;
                font-family: Arial;
                font-size: 14px;
            }
            QLabel {
                font-size: 16px;
            }
            QLineEdit {
                padding: 5px;
                font-size: 14px;
                border: 1px solid #88C0D0;
                border-radius: 5px;
                background-color: #3B4252;
                color: white;
            }
            QPushButton {
                background-color: #88C0D0;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
                color: #2E3440;
            }
            QPushButton:hover {
                background-color: #81A1C1;
            }
        """)

        # Create layout and widgets
        layout = QVBoxLayout()
        self.label = QLabel("Enter the root password:")
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept_password)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        self.setLayout(layout)
        self.password = None

    def accept_password(self):
        self.password = self.password_input.text()
        if self.password:
            self.accept()
        else:
            self.label.setText("Password cannot be empty!")
            self.label.setStyleSheet("color: #BF616A;")


class ConnectionWindow(QMainWindow):
    def __init__(self, root_password):
        super().__init__()
        self.setWindowTitle("File Transfer Connection")
        self.resize_relative_to_screen(0.5, 0.5)
        self.center_window()
        self.root_password = root_password

        self.server_socket = None
        self.server_connected = False
        self.user_id = None
        self.safe_word = None
        self.told_word = None
        self.initUI()
        threading.Thread(target=self.establish_connection, daemon=True).start()

    def resize_relative_to_screen(self, width_ratio: float, height_ratio: float):
        screen_geometry = QGuiApplication.primaryScreen().geometry()
        new_width = int(screen_geometry.width() * width_ratio)
        new_height = int(screen_geometry.height() * height_ratio)
        self.resize(new_width, new_height)

    def center_window(self):
        screen_geometry = QGuiApplication.primaryScreen().geometry()
        window_geometry = self.frameGeometry()
        screen_center = screen_geometry.center()
        window_geometry.moveCenter(screen_center)
        self.move(window_geometry.topLeft())

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()
        top_row_layout = QHBoxLayout()
        bottom_row_layout = QHBoxLayout()

        self.label = QLabel("Connecting to the server...")
        self.label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.label)

        self.button1 = QPushButton("Generate Safe Word!")
        self.button1.clicked.connect(self.on_click_generate_safe_word)
        self.code = QLineEdit()
        self.code.setReadOnly(True)
        self.code.setAlignment(Qt.AlignCenter)
        top_row_layout.addWidget(self.button1)
        top_row_layout.addWidget(self.code)

        self.button2 = QPushButton("Submit Input")
        self.button2.clicked.connect(self.on_click_submit_code)
        self.input_box = QLineEdit()
        self.input_box.setAlignment(Qt.AlignCenter)
        bottom_row_layout.addWidget(self.button2)
        bottom_row_layout.addWidget(self.input_box)

        main_layout.addLayout(top_row_layout)
        main_layout.addLayout(bottom_row_layout)

        central_widget.setLayout(main_layout)

    def establish_connection(self):
        try:
            self.server_socket = socket.socket()
            self.server_socket.connect((server_ip, server_port))
            self.server_connected = True
            self.label.setText("Connection Established")
            self.label.setStyleSheet("color: #A3BE8C;")
        except Exception as e:
            self.label.setText("Connection Failed")
            self.label.setStyleSheet("color: #BF616A;")
            print(f"Error establishing connection: {e}")

    def on_click_generate_safe_word(self):
        if not self.server_connected:
            self.label.setText("Not connected to server")
            self.label.setStyleSheet("color: #BF616A;")
            return
        try:
            self.code.setText(generate_safe_word())
            public_key_server, self.user_id = receive_ssl_greeting_certificate_main(self.server_socket, server_ip, server_port, cert_dir)
            shared_secret = diffie_hellman_exchange(self.server_socket, public_key_server)
            self.aes_key = derive_key(shared_secret)
            self.safe_word = self.code.text()
        except Exception as e:
            self.label.setText("Failed to generate safe word")
            self.label.setStyleSheet("color: #BF616A;")
            print(f"Error during safe word generation: {e}")

    def on_click_submit_code(self):
        input_code = self.input_box.text()
        if len(input_code) != 10:
            self.label.setText("Input must be 10 characters long")
            self.label.setStyleSheet("color: #D08770;")
            return
        self.label.setText("Waiting for server response...")
        self.label.setStyleSheet("color: #88C0D0;")
        threading.Thread(target=self.handle_submit_code, args=(input_code,), daemon=True).start()

    def handle_submit_code(self, input_code):
        try:
            self.told_word = input_code
            set_up_and_send_wg_dto(self.server_socket, self.user_id, self.aes_key, self.safe_word, self.told_word, self.root_password)
            public_key_pair, ip_address_pair, port_pair, endpoint_pair = receive_pairing_dto(self.server_socket, self.aes_key)
            final_wireguard_setup(public_key_pair, ip_address_pair, port_pair, endpoint_pair,self.root_password)
            self.label.setText("Pairing complete! WireGuard setup finalized.")
            self.label.setStyleSheet("color: #A3BE8C;")
            self.switch_to_transfer_window()
        except Exception as e:
            self.label.setText("Failed to complete pairing")
            self.label.setStyleSheet("color: #BF616A;")
            print(f"Error during pairing process: {e}")

    def switch_to_transfer_window(self):
        self.transfer_window = TransferWindow(self.root_password)
        self.transfer_window.show()
        self.close()


class TransferWindow(QMainWindow):
    def __init__(self, root_password):
        super().__init__()
        self.setWindowTitle("File Transfer Application")
        self.resize_relative_to_screen(0.5, 0.5)
        self.center_window()
        self.root_password = root_password

        self.files_to_send = []
        self.received_folder_path = "./received_files"
        threading.Thread(target=self.start_server, daemon=True).start()
        self.initUI()

    def resize_relative_to_screen(self, width_ratio: float, height_ratio: float):
        screen_geometry = QGuiApplication.primaryScreen().geometry()
        new_width = int(screen_geometry.width() * width_ratio)
        new_height = int(screen_geometry.height() * height_ratio)
        self.resize(new_width, new_height)

    def center_window(self):
        screen_geometry = QGuiApplication.primaryScreen().geometry()
        window_geometry = self.frameGeometry()
        screen_center = screen_geometry.center()
        window_geometry.moveCenter(screen_center)
        self.move(window_geometry.topLeft())

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()

        file_folder_layout = QVBoxLayout()
        self.file_button = QPushButton("Select Files to Send")
        self.file_button.clicked.connect(self.select_files)
        self.file_label = QLabel("No files selected")
        self.file_label.setAlignment(Qt.AlignCenter)

        self.folder_button = QPushButton("Select Folder for Received Files")
        self.folder_button.clicked.connect(self.select_folder)
        self.folder_label = QLabel("No folder selected")
        self.folder_label.setAlignment(Qt.AlignCenter)

        self.send_button = QPushButton("Send Data")
        self.send_button.clicked.connect(self.send_data)

        file_folder_layout.addWidget(self.file_button)
        file_folder_layout.addWidget(self.file_label)
        file_folder_layout.addWidget(self.folder_button)
        file_folder_layout.addWidget(self.folder_label)
        file_folder_layout.addWidget(self.send_button)

        main_layout.addLayout(file_folder_layout)
        central_widget.setLayout(main_layout)

    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Send")
        if files:
            self.files_to_send = files
            self.file_label.setText(f"Selected {len(files)} files")

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder for Received Files")
        if folder:
            self.received_folder_path = folder
            self.folder_label.setText(f"Selected Folder: {folder}")

    def start_server(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("0.0.0.0", 12345))
            server_socket.listen(5)
            print("[SERVER] Listening on port 12345")

            while True:
                client_socket, client_address = server_socket.accept()
                print(f"[SERVER] Connection from {client_address}")

                file_name = client_socket.recv(1024).decode()
                file_path = f"{self.received_folder_path}/{file_name}"
                with open(file_path, "wb") as file:
                    while chunk := client_socket.recv(1024):
                        file.write(chunk)

                print(f"[SERVER] File saved: {file_path}")
                client_socket.close()
        except Exception as e:
            print(f"[SERVER] Error: {e}")

    def send_data(self):
        if not self.files_to_send:
            self.file_label.setText("No files selected for transfer!")
            return
        target_ip = "10.0.0.2"
        for file_path in self.files_to_send:
            try:
                file_name = os.path.basename(file_path)
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((target_ip, 12345))

                client_socket.send(file_name.encode())
                with open(file_path, "rb") as file:
                    while chunk := file.read(1024):
                        client_socket.send(chunk)

                print(f"[CLIENT] File sent: {file_name}")
                client_socket.close()
            except Exception as e:
                print(f"[CLIENT] Error sending file {file_path}: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Afișează dialogul pentru introducerea parolei root
    password_dialog = PasswordDialog()
    if password_dialog.exec_() == QDialog.Accepted:
        # Dacă parola este acceptată, deschide fereastra ConnectionWindow
        connection_window = ConnectionWindow(password_dialog.password)
        connection_window.show()
        sys.exit(app.exec_())
    else:
        print("Password prompt canceled.")
        sys.exit(0)
