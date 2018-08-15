# Banter
A Proof of Concept (PoC) Remote Access Trojan (RAT) developed to play around with various ideas and concepts.

Banter was developed alongside the BackdoorPE (https://github.com/tserafin/BackdoorPE) tool with the end goal of infecting a legitimate Windows binary with the Banter client.

Key concepts investigated:
 - Automatic discovery and pairing with server by the client. Currently limited to the same network subnet.
 - Beaconing to avoid firewall
 - Heartbeats and restarting pairing process to accommodate server address changes
 - Persisting reboots

To grab all required packages run:
pip install -r requirements.txt

Possible future work:
 - Extending network discovery
 - Refactor tasking to use port knocking to reduce network footprint and tasking delay