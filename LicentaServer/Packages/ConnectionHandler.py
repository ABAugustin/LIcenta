import threading


class ConnectionHandler:
    def __init__(self):
        self.user_ip_no = 2
        self.user_count_no = 0
        self.lock = threading.Lock()

    def toggle_user_id_no(self):
        with self.lock:
            # Ensure user_count_no toggles between 1 and 2
            if self.user_ip_no == 1:
                self.user_ip_no = 2
            else:
                self.user_ip_no = 1
            return self.user_ip_no

    def toggle_user_count_no(self):
        with self.lock:
            self.user_count_no += 1
            return self.user_count_no
