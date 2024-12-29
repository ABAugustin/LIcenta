import socket
import threading

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QLineEdit, QVBoxLayout, QHBoxLayout, QWidget
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import sys
from PyQt5.QtGui import QGuiApplication

from AES.AESOperations import derive_key
from Wireguard.Wireguard import generate_safe_word, final_wireguard_setup
from Headers.headers import *
from main import receive_ssl_greeting_certificate_main, diffie_hellman_exchange, set_up_and_send_wg_dto, \
    receive_pairing_dto


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Transfer Application")

        # Set window size relative to the screen size
        self.resize_relative_to_screen(0.5, 0.5)

        # Center the window
        self.center_window()

        self.server_socket = None  # Initialize server socket
        self.server_connected = False
        self.user_id = None
        self.safe_word = None
        self.told_word = None
        self.initUI()

        # Start the connection in a separate thread
        threading.Thread(target=self.establish_connection, daemon=True).start()

    def resize_relative_to_screen(self, width_ratio: float, height_ratio: float):
        """Resize the window relative to the screen size."""
        screen_geometry = QGuiApplication.primaryScreen().geometry()
        screen_width = screen_geometry.width()
        screen_height = screen_geometry.height()

        # Calculate dimensions based on ratios
        new_width = int(screen_width * width_ratio)
        new_height = int(screen_height * height_ratio)

        self.resize(new_width, new_height)

    def center_window(self):
        """Center the window on the screen."""
        screen_geometry = QGuiApplication.primaryScreen().geometry()
        window_geometry = self.frameGeometry()

        # Calculate the center point of the screen
        screen_center = screen_geometry.center()

        # Move the window's center point to match the screen's center point
        window_geometry.moveCenter(screen_center)

        # Reposition the window to match the new center point
        self.move(window_geometry.topLeft())

    def initUI(self):
        self.label = QLabel("Welcome to file transfers", self)
        self.label.setFont(QFont("Arial", 14))  # Reduced font size for smaller label
        self.label.setStyleSheet(
            "color: black;"
            "background-color: green;"
        )
        self.label.setAlignment(Qt.AlignCenter)

        # Set up the central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create layouts
        main_layout = QVBoxLayout()
        top_row_layout = QHBoxLayout()
        bottom_row_layout = QHBoxLayout()

        # Add the first button and input box on the same row
        self.button1 = QPushButton("Generate Safe Word!", self)
        self.button1.setStyleSheet("min-width: 150px; min-height: 50px;")
        self.button1.clicked.connect(self.on_click_generate_safe_word)
        self.code = QLineEdit(self)
        self.code.setReadOnly(True)
        self.code.setAlignment(Qt.AlignCenter)  # Center the text inside the input box
        self.code.setStyleSheet("min-height: 50px;")
        top_row_layout.addWidget(self.button1)
        top_row_layout.addWidget(self.code)

        # Add the second button and input box on the same row
        self.button2 = QPushButton("Submit Input", self)
        self.button2.setStyleSheet("min-width: 150px; min-height: 50px;")
        self.button2.clicked.connect(self.on_click_submit_code)
        self.input_box = QLineEdit(self)
        self.input_box.setAlignment(Qt.AlignCenter)  # Center the text inside the input box
        self.input_box.setStyleSheet("min-height: 50px;")
        bottom_row_layout.addWidget(self.button2)
        bottom_row_layout.addWidget(self.input_box)

        # Add layouts to the main layout
        main_layout.addWidget(self.label)
        main_layout.addLayout(top_row_layout)
        main_layout.addLayout(bottom_row_layout)

        # Set the layout for the central widget
        central_widget.setLayout(main_layout)

    def establish_connection(self):
        try:
            self.server_socket = socket.socket()
            self.server_socket.connect((server_ip, server_port))
            self.server_connected = True
            self.label.setText("Connection Established")
            self.label.setStyleSheet("background-color: lightgreen; color: black;")
        except Exception as e:
            self.label.setText("Connection Failed")
            self.label.setStyleSheet("background-color: red; color: black;")
            print(f"Error establishing connection: {e}")

    def on_click_generate_safe_word(self):
        if not self.server_connected:
            self.label.setText("Not connected to server")
            self.label.setStyleSheet("background-color: red; color: black;")
            return

        try:
            self.code.setText(generate_safe_word())
            # Exchange security handshake with the server
            public_key_server, self.user_id = receive_ssl_greeting_certificate_main(self.server_socket, server_ip, server_port, cert_dir)
            shared_secret = diffie_hellman_exchange(self.server_socket, public_key_server)
            self.aes_key = derive_key(shared_secret)  # Save derived AES key for later use
            self.safe_word = self.code.text()
        except Exception as e:
            self.label.setText("Failed to generate safe word")
            self.label.setStyleSheet("background-color: red; color: black;")
            print(f"Error during safe word generation: {e}")

    def on_click_submit_code(self):
        input_code = self.input_box.text()

        if len(input_code) != 10:
            self.label.setText("Input must be 10 characters long")
            self.label.setStyleSheet("background-color: yellow; color: black;")
            return

        self.label.setText("Waiting for server response...")
        self.label.setStyleSheet("background-color: lightblue; color: black;")

        # Use a thread to handle server communication
        threading.Thread(target=self.handle_submit_code, args=(input_code,), daemon=True).start()

    def handle_submit_code(self, input_code):
        try:
            # Save the input code
            self.told_word = input_code

            # Send the setup data to the server
            set_up_and_send_wg_dto(self.server_socket, self.user_id, self.aes_key, self.safe_word, self.told_word)

            # Wait for the server's pairing data
            public_key_pair, ip_address_pair, port_pair, endpoint_pair = receive_pairing_dto(self.server_socket, self.aes_key)

            # Setup the final WireGuard configuration
            final_wireguard_setup(public_key_pair, ip_address_pair, port_pair, endpoint_pair)

            # Update the UI to show success
            self.label.setText("Pairing complete! WireGuard setup finalized.")
            self.label.setStyleSheet("background-color: green; color: white;")

        except Exception as e:
            self.label.setText("Failed to complete pairing")
            self.label.setStyleSheet("background-color: red; color: black;")
            print(f"Error during pairing process: {e}")


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
