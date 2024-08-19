import threading
class ConnectionHandler:
    def __init__(self):
        self.user_count_no = 1
        self.lock = threading.Lock()

    def toggle_user_count(self):
        with self.lock:
            # Ensure user_count_no toggles between 1 and 2
            if self.user_count_no == 1:
                self.user_count_no = 2
            else:
                self.user_count_no = 1
            return self.user_count_no