from scapy.all import sniff, wrpcap
from typing import Any

def sniff_pkt(barrier: Any, stop_event: Any, pcap_filename: str, interface: str):
    """
    Reads data from a network interface and writes the packets into a .pcap file.

    Parameters:
    - stop_event (multiprocessing.Event): The Event object to stop the processes.
    - pcap_filename (str): The file to write to.
    - interface (str): The network interface to read from.
    - end_time (int): The time to stop reading in seconds.
    - real_time (bool): Enable real-time serial emulation.
    """
    try:
        if barrier:
            barrier.wait()
        print(f"Sniffing on interface {interface}...")
        capture = sniff(iface=interface, stop_filter=lambda x: stop_event.is_set())
        print("Number of packets sniffed: ", len(capture))
        wrpcap(pcap_filename, capture)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Finished sniffing...")
