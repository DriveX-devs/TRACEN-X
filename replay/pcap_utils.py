from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

import utils
import time
import asn1tools as asn
from scapy.all import *

cpm_asn = "./data/asn/CPM-all.asn"
vam_asn = "./data/asn/VAM-PDU-FullDescription.asn"
CPM = asn.compile_files(cpm_asn, 'uper')
VAM = asn.compile_files(vam_asn, "uper")

def write_pcap(input_filename: str, interface: str, start_time: int, end_time: int):
    """
    Sends packets from a pcap file to a network interface within a given time window.

    Parameters:
    - input_filename (str): Path to the pcap file.
    - interface (str): Network interface to send packets through.
    - start_time (int): Start time in microseconds.
    - end_time (int): End time in microseconds.
    """
    pcap = rdpcap(input_filename)
    assert pcap, "Pcap file is empty"

    variable_delta_us_factor = 0
    # start_time_us represents the time in microseconds from the beginning of the messages simulation to the start time selected by the user
    start_time_us = start_time if start_time else 0

    base_ts = pcap[0].time  # epoch time in seconds
    startup_time = time.time() * 1e6
    for i, pkt in enumerate(pcap):
        pkt_ts_us = int(1e6 * (pkt.time - base_ts))

        if start_time is not None and pkt_ts_us < start_time:
            continue
        if end_time is not None and pkt_ts_us > end_time:
            break

        delta_time_us_real = time.time() * 1e6 - startup_time
        delta_time_us_simulation = pkt_ts_us - start_time_us
        variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
        if variable_delta_us_factor > 0:
            # Wait for the real time to be as close as possible to the simulation time
            # print("Sleeping for:", variable_delta_us_factor / 1e6)
            time.sleep(variable_delta_us_factor / 1e6)
        else:
            # print("Trying to sleep for a negative time, thus not sleeping: ", variable_delta_us_factor / 1e3)
            pass
        try:
            # converted_pkt = bytes(pkt)[4:]
            # converted_pkt = Ether() / IP(converted_pkt)
            sendp(pkt, iface=interface, verbose=False)
        except Exception as e:
            print(f"Error: {e}")


write_pcap(input_filename="/Users/diego/Downloads/track_2_50kmh_refTimeFix 1.pcapng", interface="utun1", start_time=None, end_time=None)
