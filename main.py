import json
import time
import subprocess
import numpy as np
import re
import socket
from collections import defaultdict
from sklearn.ensemble import IsolationForest

ALERT_FILE="/var/ossec/logs/alerts/alerts.json"
AI_LOG="/home/rushi/ai-soc.log"
WAZUH_SOCKET="/var/ossec/queue/sockets/queue"

ip_activity=defaultdict(int)
port_activity=defaultdict(set)
login_activity=defaultdict(int)
dns_activity=defaultdict(int)

blocked=set()
last_alert_time={}

ALERT_COOLDOWN=60

TOOLS={
"nmap":"Network scanning detected",
"sqlmap":"SQL injection attempt",
"nikto":"Web vulnerability scan",
"hydra":"Brute force attack",
"metasploit":"Exploit framework activity",
"ettercap":"MITM attack",
"masscan":"High speed port scanning"
}

MITRE={
"nmap":"T1046 Network Service Scanning",
"masscan":"T1046 Network Service Scanning",
"sqlmap":"T1190 Exploit Public Facing Application",
"hydra":"T1110 Brute Force",
"nikto":"T1595 Active Scanning",
"ettercap":"T1557 Adversary-in-the-Middle",
"metasploit":"T1203 Exploitation for Client Execution"
}


def log(msg):
    with open(AI_LOG,"a") as f:
        f.write(msg+"\n")


def send_wazuh(msg):

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        sock.connect(WAZUH_SOCKET)

        event = f'1:ai-soc:{msg}'

        sock.send(event.encode())

    except Exception as e:
        log(str(e))

    finally:
        sock.close()


def valid_ip(ip):
    pattern=r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(pattern,ip)


def get_source_ip(alert):

    if "data" in alert and "srcip" in alert["data"]:
        return alert["data"]["srcip"]

    if "srcip" in alert:
        return alert["srcip"]

    if "agent" in alert and "ip" in alert["agent"]:
        return alert["agent"]["ip"]

    if "network" in alert and "src_ip" in alert["network"]:
        return alert["network"]["src_ip"]

    return None


def read_alerts():

    alerts=[]

    with open(ALERT_FILE) as f:

        for line in f.readlines()[-200:]:

            try:
                alerts.append(json.loads(line))
            except:
                pass

    return alerts


def extract_features(alert):

    level=alert["rule"]["level"]
    rule=alert["rule"]["id"]

    return [level,rule]


def train(alerts):

    data=[]

    for a in alerts:
        data.append(extract_features(a))

    model=IsolationForest(
        n_estimators=150,
        contamination=0.05
    )

    model.fit(np.array(data))

    return model


def block_ip(ip):

    if not valid_ip(ip):
        return

    if ip in blocked:
        return

    try:

        subprocess.run(
            ["sudo","iptables","-A","INPUT","-s",ip,"-j","DROP"]
        )

        blocked.add(ip)

        log(f"Blocked attacker IP {ip}")

    except Exception as e:

        log(str(e))


def detect_tools(description):

    desc=description.lower()

    for tool in TOOLS:

        if tool in desc:

            return tool

    return None


def detect_scan(ip,port):

    port_activity[ip].add(port)

    if len(port_activity[ip])>20:
        return True

    return False


def detect_bruteforce(ip):

    login_activity[ip]+=1

    if login_activity[ip]>8:
        return True

    return False


def detect_dns_tunnel(ip):

    dns_activity[ip]+=1

    if dns_activity[ip]==30:
        return True

    return False


def analyze(alerts,model):

    for alert in alerts:

        desc=alert["rule"]["description"]
        level=alert["rule"]["level"]

        src=get_source_ip(alert)

        if not src:
            continue

        port=alert.get("data",{}).get("dstport",0)

        ip_activity[src]+=1

        features=np.array([[level,alert["rule"]["id"]]])

        anomaly=model.predict(features)[0]==-1

        score=level*2

        tool=detect_tools(desc)

        if anomaly:
            score+=20

        if detect_scan(src,port):
            score+=25
            desc="Port scanning behavior detected"

        if detect_bruteforce(src):
            score+=20
            desc="Brute force activity detected"

        if detect_dns_tunnel(src):
            score+=30
            desc="Possible DNS tunneling detected"

        if tool:
            score+=25
            desc=TOOLS[tool]

        if score>80:
            severity="CRITICAL"
            block_ip(src)

        elif score>50:
            severity="HIGH"

        elif score>25:
            severity="MEDIUM"

        else:
            severity="LOW"


        now=time.time()

        if src in last_alert_time:

            if now-last_alert_time[src]<ALERT_COOLDOWN:
                continue

        last_alert_time[src]=now


        mitre="Unknown"

        if tool in MITRE:
            mitre=MITRE[tool]


        message=f"AI-SOC ALERT severity={severity} src={src} event={desc} mitre={mitre}"

        send_wazuh(message)

        log(message)


def main():

    alerts=read_alerts()

    if len(alerts)<20:
        return

    model=train(alerts)

    analyze(alerts,model)


while True:

    try:
        main()

    except Exception as e:
        log(str(e))

    time.sleep(10)
