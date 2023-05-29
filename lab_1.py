from ipaddress import IPv4Address
from abc import ABC, abstractmethod
import re
from typing import Dict, Optional, Union


class SSHLogEntry(ABC):
    timestamp: str = "timestamp"
    host_name: str = "host_name"
    pid_number: str = "pid_number"
    message: str = "message"

    def __init__(self, log: str) -> None:
        prepared_log = self.parse_log_line(log)
        self.timestamp = prepared_log[self.timestamp]
        self._message = prepared_log[self.message]
        self.pid_number = prepared_log[self.pid_number]
        self.host_name = prepared_log[self.host_name] if prepared_log[self.host_name] else ""

    def parse_log_line(self, log: str) -> Dict[str, str]:
        try:
            log_pattern = r"^(\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+)\[(\d+)\]:\s(.*)$"
            match = re.match(log_pattern, log)
            if not match:
                return {}
            return {
                self.timestamp: match.group(1),
                self.host_name: match.group(2),
                self.pid_number: match.group(4),
                self.message: match.group(5),
            }
        except Exception:
            raise Exception("Error in log line")

    def __str__(self) -> str:
        return f"[{self.timestamp}] [{self.pid_number}] [{self.host_name}] [{self._message}]" if self.host_name else f"[{self.timestamp}] [{self.pid_number}] [{self._message}]"

    def get_ipv4_address(self) -> Optional[IPv4Address]:
        ipv4_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        match = re.search(ipv4_pattern, self._message)
        return IPv4Address(match.group(0)) if match else None

    @abstractmethod
    def validate(self) -> bool:
        pass

    @property
    def has_ip(self) -> bool:
        return self.get_ipv4_address() is not None

    def __repr__(self) -> str:
        return f"SSHLogEntry (timestamp={self.timestamp}, host_name={self.host_name}, pid_number={self.pid_number}, message={self._message})"

    def __eq__(self, other: Union[object, "SSHLogEntry"]) -> bool:
        if not isinstance(other, SSHLogEntry):
            raise TypeError("Trying to compare non SSHLogEntry object")
        return (self.timestamp, self.host_name, self.pid_number, self._message) == (other.timestamp, other.host_name, other.pid_number, other._message)

    def __lt__(self, other: Union[object, "SSHLogEntry"]) -> bool:
        if not isinstance(other, SSHLogEntry):
            raise TypeError("Trying to compare non SSHLogEntry object")
        return self.timestamp < other.timestamp

    def __gt__(self, other: Union[object, "SSHLogEntry"]) -> bool:
        if not isinstance(other, SSHLogEntry):
            raise TypeError("Trying to compare non SSHLogEntry object")
        return self.timestamp > other.timestamp

