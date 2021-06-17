#
# This is a collection of functions which generate dummy data for the
# 3 report types requested by Etisalat.
#
import datetime
import ipaddress
import random

THREAT_LIST = [
    ("Microsoft SQL Server User Authentication Brute Force Attempt", 40010),
    ("Hupigon Command and Control Traffic", 85008),
    ("Microsoft Windows SMB Remote Code Execution Vulnerability", 32422),
]


def random_ipv4(min_address="192.168.0.1", max_address="192.168.255.255"):
    min_ipv4 = int(ipaddress.IPv4Address(min_address))
    max_ipv4 = int(ipaddress.IPv4Address(max_address))

    return ipaddress.IPv4Address._string_from_ip_int(
        random.randint(min_ipv4, max_ipv4)
    )


def get_datetime(timedelta: int = 0, formatter: str = "%Y/%m/%d %H:%M:%S", raw: bool = False):
    d = datetime.datetime.now() + datetime.timedelta(seconds=timedelta)
    if raw:
        return d
    else:
        return d.strftime(formatter)


def gen_possible_compromised_hosts(entry_count: int = 5):
    compromised_hosts_entries = list()
    for i in range(entry_count):
        src = random_ipv4()
        resolved_src = src
        threat = THREAT_LIST[random.randrange(len(THREAT_LIST)-1)]
        threatid = threat[0]
        tid = threat[1]
        category_of_threatid = "brute-force"
        count = random.randrange(100)
        entry_data = {
            "src": src,
            "resolved-src": resolved_src,
            "threatid": threatid,
            "tid": tid,
            "category_of_threatid": category_of_threatid,
            "count": count
        }
        compromised_hosts_entries.append(entry_data)
    return compromised_hosts_entries


def gen_data(report_type: str = ""):
    dataset = {
        "tenq": get_datetime(formatter="%H:%M:%S"),
        "tdeq": get_datetime(timedelta=1, formatter="%H:%M:%S"),
        "tlast": get_datetime(timedelta=1, formatter="%H:%M:%S"),
        "entries": gen_possible_compromised_hosts(),
    }

    return dataset
