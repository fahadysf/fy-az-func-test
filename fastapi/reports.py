#
# This is a collection of functions which generate dummy data for the
# 3 report types requested by Etisalat.
#
import datetime
import ipaddress
import random

THREAT_LIST = [
    ("Microsoft SQL Server User Authentication Brute Force Attempt", 40010, "high"),
    ("Hupigon Command and Control Traffic", 85008, "critical"),
    ("Microsoft Windows SMB Remote Code Execution Vulnerability", 32422, "high"),
    ("Cobalt Strike Beacon Command and Control Traffic Detection", 86172, "critical"),
    ("CrackDown_1_0_beta screenshot command", 11306, "high"),
    ("TheX_1_2 execute command", 11711, "high"),
    ("Little_Witch command pattern", 10679, "high"),
    ("Hanky_Panky_1_1 file list command", 11316, "high"),
    ("itsoknoproblembro Command and Control Traffic", 13275, "critical"),
    ("Fakeav Command and Control Traffic", 13278, "critical"),
    ("MuddyWater Command and Control Traffic", 85063, "critical"),
    ("TA505 Command and Control Traffic", 85137, "critical"),
    ("TA505 Command and Control Traffic", 85140, "critical"),
]

APP_LIST = [
    ('salesforce', 2),
    ('ms-ds-smb-v3', 3),
    ('web-browsing', 3),
    ('ssl', 4),
    ('facebook', 3),
    ('whatsapp', 4),
    ('symantec-av-updates', 1),
    ('ms-update', 1),
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


def gen_top_apps(entry_count: int = 5):
    app_report_entries = list()
    for i in range(entry_count):
        app = APP_LIST[random.randrange(len(APP_LIST)-1)]
        app_name = app[0]
        app_risk = app[1]
        app_bytes = random.randrange(100000, 200000000)
        app_sessions = random.randrange(10, 150)
        entry_data = {
            'app_name': app_name,
            'app_risk': app_risk,
            'app_bytes': app_bytes,
            'app_sessions': app_sessions
        }
        app_report_entries.append(entry_data)
    return app_report_entries


def gen_data(report_type: str = ""):
    dataset = {
        "tenq": get_datetime(formatter="%H:%M:%S"),
        "tdeq": get_datetime(timedelta=1, formatter="%H:%M:%S"),
        "tlast": get_datetime(timedelta=1, formatter="%H:%M:%S"),
        "entries": gen_possible_compromised_hosts(),
    }
    if report_type == 'possible-compromised-hosts':
        dataset['entries'] = gen_possible_compromised_hosts()
    elif report_type == 'top-apps':
        dataset['entries'] = gen_top_apps()
    return dataset
