#!/usr/bin/env python3
# You need to install scapy to get this code to work
import sys
import json
import subprocess

import scapy.layers.eap
import scapy.layers.dot11

print("Starting 'hostapd'")
process = subprocess.Popen(
    ["./hostapd/hostapd", "hostapd/hostapd-wpa3.conf"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

if process is None or process.stdout is None:
    print("Failed to start process")
    sys.exit(0)

for line in process.stdout:
    print(line, end="")
    if line.startswith("[fuzz] "):
        json_str = line[len("[fuzz] ") :]

        json_obj = json.loads(json_str)

        if json_obj["msg"] == "fuzz":
            data = json_obj["data"]
            # print(f"{data=}")
            data_unhex = bytes.fromhex(data)
            # print(f"{data_unhex=}")

            packet = None
            if json_obj["target"] == "eapol":
                packet = scapy.layers.eap.EAPOL(data_unhex)
            else:
                packet = scapy.layers.dot11.Dot11(data_unhex)

            print(f"{packet=}")
