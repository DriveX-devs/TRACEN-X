from scapy.all import sniff, wrpcap
import utils

MAX_SIZE_PKT_LIST = 400 # Reduce the I/O consecutive disk operations

def sniff_pkt(pcap_filename: str, interface: str):
    """
    Reads data from a network interface and writes the packets into a .pcap file.

    Parameters:
    - pcap_filename (str): The file to write to.
    - interface (str): The network interface to read from.
    - end_time (int): The time to stop reading in seconds.
    - real_time (bool): Enable real-time serial emulation.
    """
    try:
        capture = sniff(iface=interface, stop_filter=lambda x: utils.TERMINATOR_FLAG)
        print("Number of packets sniffed: ", len(capture))
        wrpcap(pcap_filename, capture)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Finished sniffing...")
