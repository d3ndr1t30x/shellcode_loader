# Shellcode loader
Shellcode loader written in Python.

Overview

This project provides a basic shellcode loader written in Python. The loader:

Fetches shellcode from a specified URL.
Executes the shellcode directly in memory.
Collects basic metadata about the host machine.
Sends the metadata back to a specified server.
Polls the server at random intervals to disguise traffic patterns (jitter).

Note: This tool is intended for educational purposes or controlled environments. Executing shellcode can be dangerous and should be done responsibly and legally.
Features

Dynamic Shellcode Loading: The loader does not have the shellcode embedded in it but fetches it from a server.
Metadata Reporting: Sends basic system information (e.g., OS, hostname, architecture) to a server.
Jitter Implementation: Polls the server at random intervals to reduce detection.

Requirements

Python 3.x
Internet connection for fetching shellcode and sending metadata

Setup

Prepare the Server:
Host your shellcode binary (e.g., shellcode.bin) on a web server.
Create an endpoint to receive metadata (e.g., metadata endpoint).

Modify the Script:
Update the URLs in the script with your server's URLs:

python

shellcode_url = "http://your-server.com/shellcode.bin"
metadata_url = "http://your-server.com/metadata"

Run the Script:

Execute the Python script on the target machine:

```python shellcode_loader.py```
