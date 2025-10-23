import serial
import argparse
import signal
from multiprocessing import Process, Event, Barrier
import os
from pcap_utils import sniff_pkt
from serial_utils import read_serial
from can_utils import read_CAN_bus
import utils

def signal_handler(sig, frame, stop_event):
    """
    Signal handler for the SIGINT signal.
    """
    print("\nTerminating...")
    stop_event.set()

def main():
    """
    Entry point for the data recording framework.

    This script allows simultaneous logging of serial, CAN, and PCAP data from various sources.
    It supports real-time serial emulation, reads from hardware interfaces or log files, and writes structured outputs for later analysis or replay. Modules run in parallel threads based on the selected command-line options.

    
    Command-line Arguments:
    - --enable-serial (bool): Enable serial logging. Default is False. Can be activated by writing it.
    - --serial-device (str): The device to read from. Default is "/dev/ttyACM0".
    - --serial-filename (str): The serial file to write to. Default is "./data/outlog.json".
    - --baudrate (int): The baudrate to read from. Default is 115200.
    - --end-time (int): The time to stop reading in seconds. If not specified, will read indefinitely.
    - --enable-CAN (bool): Enable CAN logging. Default is False. Can be activated by writing it.
    - --CAN-device (str): The CAN device to read from. Default is "vcan0".
    - --CAN-filename (str): The CAN file to write to. Default is "./data/CANlog.json".
    - --CAN-db (str): The CAN database file. Default is "./data/motohawk.dbc".
    - --real-time-serial (bool): Enable real-time serial emulation. Default is False. Can be activated by writing it.
    - --enable-pcap (bool): Enable pcap logging. Default is False. Can be activated by writing it.
    - --interface (str): Network interface to read from. Default is "wlan0".
    - --pcap-filename (str): The pcap file to write to. Default is "./data/pcap_output/trace.pcapng".

    Example:
    python3 record/record.py --enable-serial --device=/dev/ttyACM0 --serial-filename ./data/outlog.json --baudrate 115200 --end-time 10 --enable-CAN --CAN-device vcan0 --CAN-filename ./data/CANlog.json --CAN-db ./data/motohawk.db --enable-pcap --interface wlan1 --pcap-filename ./data/pcap_output/trace2.pcapng
    """

    args = argparse.ArgumentParser()
    args.add_argument("--enable-serial", action="store_true", help="Enable serial logging")
    args.add_argument("--serial-device", type=str, help="The device to read from", default="/dev/ttyACM0")
    args.add_argument("--serial-filename", type=str, help="The serial file to write to", default="./data/gnss_output/outlog.json")
    args.add_argument("--baudrate", type=int, help="The baudrate to read from", default=115200)
    args.add_argument("--end-time", type=int, help="The time to stop reading in seconds, if not specified, will read indefinitely", default=None)
    args.add_argument("--enable-CAN", action="store_true", help="Enable CAN logging")
    args.add_argument("--CAN-device", type=str, help="The CAN device to read from", default="vcan0")
    args.add_argument("--CAN-log-file-source", type=str, help="CAN log file to read from", default=None)
    args.add_argument("--CAN-filename", type=str, help="The CAN file to write to", default="./data/can_output/CANlog.json")
    args.add_argument("--CAN-db", type=str, help="The CAN database file", default="./data/can_db/motohawk.dbc")
    args.add_argument("--real-time-serial", action="store_true", help="Enable real-time serial emulation")
    args.add_argument("--enable-pcap", action="store_true", help="Enable pcap logging")
    args.add_argument("--interface", type=str, help="The interface to read from", default="wlan0")
    args.add_argument("--pcap-filename", type=str, help="The pcap file to write to", default="./data/pcap_output/trace.pcapng")

    stop_event = Event()
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, stop_event))

    args = args.parse_args()
    enable_serial = args.enable_serial
    enable_CAN = args.enable_CAN
    enable_pcap = args.enable_pcap

    assert enable_serial or enable_CAN or enable_pcap, "At least one of serial, CAN or pcap logging must be enabled"

    end_time = args.end_time

    candump_process = None
    serial_process = None
    pcap_process = None

    num_barriers = 0
    if enable_serial:
        num_barriers += 1
    if enable_CAN:
        num_barriers += 1
    if enable_pcap:
        num_barriers += 1
    
    barrier = Barrier(num_barriers) if num_barriers > 1 else None

    if enable_CAN:
        CAN_device = args.CAN_device
        CAN_filename = args.CAN_filename
        CAN_db = args.CAN_db
        assert os.path.exists(CAN_db), "CAN db does not exist"
        CAN_log_file_source = args.CAN_log_file_source
        if CAN_log_file_source:
            assert os.path.exists(CAN_log_file_source), "CAN log file source does not exist"
        # Start thread to read CAN bus
        candump_process = Process(target=read_CAN_bus, args=(barrier, stop_event, CAN_device, CAN_filename, CAN_db, CAN_log_file_source, end_time))
        # Set the thread as a daemon so it will be killed when the main thread exits
        candump_process.start()

    if enable_serial:
        device = args.serial_device
        serial_filename = args.serial_filename
        baudrate = args.baudrate
        assert baudrate == 115200, "Baudrate must be 115200"
        real_time = args.real_time_serial
        ser = serial.Serial(
            port=device,
            baudrate=int(baudrate),
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=0
        )
        # Start the read serial function
        serial_process = Process(target=read_serial, args=(barrier, stop_event, serial_filename, ser, end_time, real_time))
        serial_process.start()

    if enable_pcap:
        interface = args.interface
        pcap_filename = args.pcap_filename
        pcap_process = Process(target=sniff_pkt, args=(barrier, stop_event, pcap_filename, interface))
        pcap_process.start()

    try:
        if enable_CAN:
            candump_process.join()

        if enable_serial:
            serial_process.join()

        if enable_pcap:
            pcap_process.join()
    except KeyboardInterrupt:
        print("Interrupted by user")
        stop_event.set()
        if candump_process: candump_process.join()
        if serial_process: serial_process.join()
        if pcap_process: pcap_process.join()


if __name__ == "__main__":
    main()
