Banter is a Proof of Concept (PoC) Remote Access Tool (RAT) developed to play around with various ideas and concepts.
Key concepts investigated:
 - Automatic discovery and pairing with server by the client. Currently limited to the same network subnet.
 - Beaconing to avoid firewall
 - Heartbeats and restarting pairing process to accommodate server address changes
 - Persisting reboots

It was developed alongside the BackdoorPE tool with the end goal of infecting a legitimate Windows binary with the Banter client.

To grab all required packages run:
pip install -r requirements.txt