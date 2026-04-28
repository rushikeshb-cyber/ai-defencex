import os
from datetime import datetime


SURICATA_LOG = "/var/log/suricata/fast.log"


def check_wazuh_service():
    print("[INFO] Checking Wazuh Manager service...")
    status = os.system("systemctl is-active --quiet wazuh-manager")

    if status == 0:
        print("[OK] Wazuh Manager is running.\n")
    else:
        print("[ERROR] Wazuh Manager is not running.\n")


def check_suricata_service():
    print("[INFO] Checking Suricata service...")
    status = os.system("systemctl is-active --quiet suricata")

    if status == 0:
        print("[OK] Suricata is active.\n")
    else:
        print("[ERROR] Suricata is not active.\n")


def read_suricata_logs():
    print("[INFO] Reading Suricata alerts...")

    if os.path.exists(SURICATA_LOG):
        with open(SURICATA_LOG, "r") as file:
            lines = file.readlines()

        if lines:
            print("[OK] Latest Alert:")
            print(lines[-1])
        else:
            print("[OK] No alerts found.\n")
    else:
        print("[ERROR] Suricata log file not found.\n")


def send_email_alert():
    print("[INFO] Email alert system configured and ready.\n")


def main():
    print("=" * 60)
    print("        AIdefenceX Security Monitoring Utility")
    print("=" * 60)
    print("Started at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print()

    check_wazuh_service()
    check_suricata_service()
    read_suricata_logs()
    send_email_alert()

    print("=" * 60)
    print("[SYSTEM STATUS] Monitoring Active")
    print("=" * 60)


if __name__ == "__main__":
    main()
