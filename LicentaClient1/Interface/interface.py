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

        self.wireguard_ip_local = None
        self.wireguard_port_local = None
        self.peer_wireguard_ip_remote = None
        self.peer_wireguard_port_remote = None

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
            self.wireguard_ip_local, self.wireguard_port_local =set_up_and_send_wg_dto(self.server_socket, self.user_id, self.aes_key, self.safe_word, self.told_word,
                                   self.root_password)
            public_key_pair, ip_address_pair, port_pair, endpoint_pair = receive_pairing_dto(self.server_socket,self.aes_key)
            self.peer_wireguard_ip_remote = endpoint_pair
            self.peer_wireguard_port_remote = port_pair

            final_wireguard_setup(public_key_pair, ip_address_pair, port_pair, endpoint_pair, self.root_password)

            self.label.setText("Pairing complete! WireGuard setup finalized.")
            self.label.setStyleSheet("color: #A3BE8C;")
            QApplication.quit()  # Închide aplicația curentă
        except Exception as e:
            self.label.setText("Failed to complete pairing")
            self.label.setStyleSheet("color: #BF616A;")
            print(f"Error during pairing process: {e}")

    def switch_to_transfer_window(self):
        self.close()
        self.transfer_window = FileTransferWindow()
        self.transfer_window.show()


class FileTransferWindow(QMainWindow):
    def __init__(self, wireguard_ip, wireguard_port, peer_wireguard_ip, peer_wireguard_port):
        self.wireguard_ip = wireguard_ip
        self.wireguard_port = wireguard_port
        self.peer_wireguard_ip = peer_wireguard_ip
        self.peer_wireguard_port = peer_wireguard_port
        super().__init__()
        self.setWindowTitle("File Transfer Application")
        self.resize_relative_to_screen(0.5, 0.5)
        self.center_window()

        self.initUI()
        self.peer_socket = None
        self.init_peer_to_peer()

    def resize_relative_to_screen(self, width_ratio: float, height_ratio: float):
        screen_geometry = QApplication.primaryScreen().geometry()
        new_width = int(screen_geometry.width() * width_ratio)
        new_height = int(screen_geometry.height() * height_ratio)
        self.resize(new_width, new_height)

    def center_window(self):
        screen_geometry = QApplication.primaryScreen().geometry()
        window_geometry = self.frameGeometry()
        screen_center = screen_geometry.center()
        window_geometry.moveCenter(screen_center)
        self.move(window_geometry.topLeft())

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        self.file_button = QPushButton("Select File to Send")
        self.file_button.clicked.connect(self.select_file)
        layout.addWidget(self.file_button)

        self.file_label = QLabel("No file selected")
        self.file_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.file_label)

        self.folder_button = QPushButton("Select Folder to Receive Files")
        self.folder_button.clicked.connect(self.select_folder)
        layout.addWidget(self.folder_button)

        self.folder_label = QLabel("No folder selected")
        self.folder_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.folder_label)

        self.send_button = QPushButton("Send File")
        self.send_button.clicked.connect(self.send_file)
        layout.addWidget(self.send_button)

        central_widget.setLayout(layout)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if file_path:
            self.file_path = file_path
            self.file_label.setText(f"Selected File: {file_path}")

    def select_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Receive Files")
        if folder_path:
            self.receive_folder = folder_path
            self.folder_label.setText(f"Selected Folder: {folder_path}")

    def init_peer_to_peer(self):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_socket.bind((self.wireguard_ip, self.wireguard_port))  # Leagă socket-ul la adresa WireGuard
        self.peer_socket.bind(("0.0.0.0", 0))
        self.peer_socket.listen(1)
        threading.Thread(target=self.accept_connections, daemon=True).start()

    def accept_connections(self):
        while True:
            conn, addr = self.peer_socket.accept()
            threading.Thread(target=self.handle_peer, args=(conn,), daemon=True).start()

    def handle_peer(self, conn):
        try:
            with conn:
                file_name = conn.recv(1024).decode()
                file_size = int(conn.recv(1024).decode())
                file_path = os.path.join(self.receive_folder, file_name)

                with open(file_path, "wb") as f:
                    received = 0
                    while received < file_size:
                        data = conn.recv(4096)
                        if not data:
                            break
                        f.write(data)
                        received += len(data)
                print(f"Received file: {file_path}")
        except Exception as e:
            print(f"Error receiving file: {e}")

    def send_file(self):
        if hasattr(self, 'file_path') and hasattr(self, 'peer_address'):
            try:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.connect((self.peer_wireguard_ip, self.peer_wireguard_port))  # Conectează-te la destinatar prin WireGuard

                file_name = os.path.basename(self.file_path)
                file_size = os.path.getsize(self.file_path)

                conn.sendall(file_name.encode())
                conn.sendall(str(file_size).encode())

                with open(self.file_path, "rb") as f:
                    while chunk := f.read(4096):
                        conn.sendall(chunk)
                print("File sent successfully")
                conn.close()
            except Exception as e:
                print(f"Error sending file: {e}")
        else:
            print("File path or peer address not set")


def main():
    # Prima aplicație
    app = QApplication(sys.argv)

    # Show password dialog first
    password_dialog = PasswordDialog()
    if password_dialog.exec_() == QDialog.Accepted:
        # Launch connection window
        connection_window = ConnectionWindow(password_dialog.password)
        connection_window.show()


        # Run the first application
        exit_code = app.exec_()

        # Verificăm dacă aplicația s-a închis cu succes
        if exit_code == 0:
            # Lansează a doua aplicație (FileTransferWindow)

            app2 = QApplication(sys.argv)
            transfer_window = FileTransferWindow(connection_window.wireguard_ip_local,connection_window.wireguard_port_localt,connection_window.peer_wireguard_ip_remotep,connection_window.peer_wireguard_port_remote)
            transfer_window.show()
            sys.exit(app2.exec_())
        else:
            sys.exit(exit_code)  # Asigurăm închiderea completă dacă apare o eroare
    else:
        print("Password prompt canceled.")
        sys.exit(0)

if __name__ == "__main__":
    main()
