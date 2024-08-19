import threading
class ConnectionHandler:
    def __init__(self, initial_user_count_no=1):
        self.user_count_no = initial_user_count_no
        self.lock = threading.Lock()

    def toggle_user_count(self):
        with self.lock:
            # Toggle the user_count_no between 1 and 2
            if self.user_count_no == 1:
                self.user_count_no = 2
            else:
                self.user_count_no = 1
            return self.user_count_no
