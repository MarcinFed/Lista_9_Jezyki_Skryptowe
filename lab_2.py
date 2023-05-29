from lab_1 import SSHLogEntry
import re


class RejectedPasswordSSHLogEntry(SSHLogEntry):
    def __init__(self, log: str) -> None:
        super().__init__(log)
        self.user_name: str = self.get_user_name()

    def get_user_name(self) -> str:
        user_name_pattern = r"(?<=user )\w+"
        return re.findall(user_name_pattern, self._message)[0]

    def validate(self) -> bool:
        return "Failed password for invalid user" in self._message


class AcceptedPasswordSSHLogEntry(SSHLogEntry):
    def __init__(self, log: str) -> None:
        super().__init__(log)
        self.user_name: str = self.get_user_name()

    def get_user_name(self) -> str:
        user_name_pattern = r"(?<=user )\w+"
        return re.findall(user_name_pattern, self._message)[0]

    def validate(self) -> bool:
        return ("Accepted password" and "for" and "from") in self._message


class ErrorSSHLogEntry(SSHLogEntry):
    def __init__(self, log: str) -> None:
        super().__init__(log)
        self.error_message: str = self.get_error_msg()

    def get_error_msg(self) -> str:
        error_pattern = r"error: (.+?) \["
        message = re.findall(error_pattern, self._message)
        if message:
            return message[0]
        else:
            return ""

    def validate(self) -> bool:
        return "Failed" in self._message


class OtherSSHLogEntry(SSHLogEntry):
    def __init__(self, log: str) -> None:
        super().__init__(log)
        self.other_message: str = self._message

    def validate(self) -> bool:
        return True
