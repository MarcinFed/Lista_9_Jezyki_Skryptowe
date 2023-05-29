import pytest
from lab_2 import RejectedPasswordSSHLogEntry, AcceptedPasswordSSHLogEntry, ErrorSSHLogEntry, OtherSSHLogEntry
from lab_7 import SSHLogJournal
from ipaddress import IPv4Address

def test_extract_time():
    log = "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
    entry = RejectedPasswordSSHLogEntry(log)
    assert entry.timestamp == "Dec 10 06:55:48"


def test_extract_ipv4():
    log = "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
    entry = RejectedPasswordSSHLogEntry(log)
    assert entry.get_ipv4_address() == IPv4Address("173.234.31.186")


def test_extract_invalid_ipv4():
    log = "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 666.777.88.213 port 38926 ssh2"
    entry = RejectedPasswordSSHLogEntry(log)
    with pytest.raises(ValueError):
        entry.get_ipv4_address()


def test_no_ipv4():
    log = "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster port 38926 ssh2"
    entry = RejectedPasswordSSHLogEntry(log)
    assert entry.get_ipv4_address() is None


@pytest.mark.parametrize("entry_class", [RejectedPasswordSSHLogEntry, AcceptedPasswordSSHLogEntry, ErrorSSHLogEntry, OtherSSHLogEntry])
def test_append(entry_class):
    log = "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
    entry = entry_class(log)
    journal = SSHLogJournal()
    journal.append(entry)
    assert isinstance(journal.get_log_by_index(0), entry_class)
