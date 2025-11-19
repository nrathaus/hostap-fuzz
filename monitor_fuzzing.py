import json
import subprocess

import scapy
import scapy.layers.dot11

process = subprocess.Popen(
    ["./hostapd", "hostapd-wpa3.conf"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

for line in process.stdout:
    if line.startswith("[fuzz] "):
        print(line)
        json_str = line[len("[fuzz] ") :]

        json_obj = json.loads(json_str)

        if json_obj["msg"] == "fuzz":
            data = json_obj["data"]
            print(f"{data=}")
            data_unhex = bytes.fromhex(data)
            print(f"{data_unhex=}")

            packet = scapy.layers.dot11.Dot11(data_unhex)

            print(f"{packet=}")
