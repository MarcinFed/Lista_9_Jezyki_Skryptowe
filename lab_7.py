from typing import List, Union, Iterator
from lab_1 import SSHLogEntry
from ipaddress import IPv4Address


class SSHLogJournal:
    def __init__(self) -> None:
        self.ssh_log_entries: List[SSHLogEntry] = []

    def __len__(self) -> int:
        return len(self.ssh_log_entries)

    def __contains__(self, log: SSHLogEntry) -> bool:
        return log in self.ssh_log_entries

    def __iter__(self) -> Iterator[SSHLogEntry]:
        return iter(self.ssh_log_entries)

    def append(self, log: SSHLogEntry) -> None:
        if log.validate():
            self.ssh_log_entries.append(log)

    def get_logs_by_host_name(self, host_name: str) -> List[SSHLogEntry]:
        return [log for log in self.ssh_log_entries if log.host_name == host_name]

    def get_log_by_index(self, index: int) -> SSHLogEntry:
        return self.ssh_log_entries[index]

    def get_logs_by_ipv4(self, ipv4_address: IPv4Address) -> List[SSHLogEntry]:
        return [log for log in self.ssh_log_entries if log.get_ipv4_address() == ipv4_address]

