import argparse
import os
import signal
import json
import sys
from pathlib import Path
from multiprocessing import Process, Event

from visualizer import Visualizer
from csv_conversion_utils import csv_conversion
from test_rate_utils import test_rate
from can_utils import write_CAN
from gui_utils import serial_gui
from serial_utils import write_serial
from pcap_utils import write_pcap
from utils import countCertificates
from utils import count_active_certificates

# Make sure sibling packages like PKIManager are importable when run as a script.
project_root = str(Path(__file__).resolve().parents[1])
if project_root not in sys.path:
    sys.path.append(project_root)
from PKIManager import ATManager, ATResponse, ECManager, ECResponse

def signal_handler(sig, frame, stop_event):
    """
    Signal handler for the SIGINT signal.
    """
    print("\nTerminating...")
    stop_event.set()

def main():
    """
    Entry point for the data replay and emulation framework.

    This script supports multiple replay modes including serial, CAN, CSV export, PCAP playback, and graphical visualization through a web-based GUI.
    It initializes the selected emulation processes based on user-specified command-line arguments, ensuring synchronized and modular replay of recorded datasets for debugging, validation, or visualization purposes.

    Command-line Arguments:
    - --enable-serial (bool): Whether to enable the serial emulator. Default is False. Can be activated by writing it.
    - --serial-filename (str): The file to read data from. Default is "./data/examples/example1.json".
    - --server-device (str): The device to write data to. Default is "./replay/ttyNewServer".
    - --client-device (str): The device to read data from. Default is "./replay/ttyNewClient".
    - --baudrate (int): The baudrate to write. Default is 115200.
    - --start-time (int): The timestamp to start the reading in seconds. If not specified, will read from the beginning of the file.
    - --end-time (int): The time to stop reading in seconds. If not specified, will write until the end of the file.
    - --enable-gui (bool): Whether to display the GUI. Default is False. Can be activated by writing it.
    - --enable-test-rate (int): Test rate mode. Instead of showing the trace or reproducing it, it will output the positioning (Lat, Lon) update frequency and save the related data, message by message, on a file named replay_out.csv. Default is False. Can be activated by writing it.
    - --visualizer-http-port (int): The port for the HTTP server for the visualizer (GUI). Default is 8080.
    - --visualizer-server-ip (str): The IP address of the server for the visualizer (GUI). Default is 127.0.0.1
    - --visualizer-server-port (int): The port of the server for the visualizer (GUI). Default is 48110.
    - --enable-CAN (bool): Whether to enable the CAN emulator. Default is False. Can be activated by writing it.
    - --CAN-db (str): The CAN database file. Default is "./data/can_db/motohawk.dbc".
    - --CAN-device (str): The CAN device to write to. Default is "vcan0".
    - --CAN-filename (str): The CAN file to read from. Default is "./data/can_output/can_log.json".
    - --enable-csv (bool): Save the data to a csv file. Default is False. Can be activated by writing it.
    - --csv-filename (str): The csv file to save the data to. Default is "./data/gnss_output/example.csv".
    - --csv-interpolation (bool): Interpolate the data to have fixed information updating. Default is False. Can be activated by writing it.
    - --enable-pcap (bool): Whether to enable the pcap reproduction. Default is False. Can be activated by writing it.
    - --interface (str): The network interface to which write the pcap content. Default is "wlan0".
    - --pcap-filename (str): The pcap file to read from for pcap emulation. Default is "./data/pcap_output/trace.pcapng".
    - --update-datetime (bool): If the emulation of pcap trace must update the packets datetime to the current one. Default is False.
    - --enable-amqp (bool): Whether AMQP messaging is enabled. Default is False. Can be activated by writing it.
    - --amqp-server-ip (str): The IP address of the AMQP server. Default is 127.0.0.1.
    - --amqp-server-port (str): The Port of the AMQP server. Default is 5867.
    - --amqp-topic (str): The Topic to publish messages to on the AMQP server. Default is tracenx.

    Example:
    python3 replay/replay.py --enable-serial --serial-filename ./data/gnss_output/example1.json --server-device ./replay/ttyNewServer --client-device ./replay/ttyNewClient --baudrate 115200 --start-time 0 --end-time 10 --enable-gui --visualizer-http-port 8080 --enable-pcap --interface wlan1 --update-datetime --new-pcap-file new_pcap.pcapng --enable-amqp --amqp-server-ip 127.0.0.1 --amqp-server-port 5867 --amqp-topic tracenx
    """
    args = argparse.ArgumentParser()
    args.add_argument("--enable-serial", action="store_true", help="Enable serial emulator")
    args.add_argument("--serial-filename", type=str, help="The file to read data from", default="./data/gnss_output/example.json")
    args.add_argument("--server-device", type=str, help="The device to write data to", default="./replay/ttyNewServer")
    args.add_argument("--client-device", type=str, help="The device to read data from", default="./replay/ttyNewClient")
    args.add_argument("--baudrate", type=int, help="The baudrate to write", default=115200)
    args.add_argument("--start-time", type=int, help="The timestamp to start the reading in seconds. If not specified, will read from the beginning of the file.", default=None)
    args.add_argument("--end-time", type=int, help="The time to stop reading in seconds, if not specified, will write until the end of the file", default=None)
    args.add_argument("--enable-serial-gui", action="store_true", help="Whether to display the serial GUI. Default is False", default=False)
    args.add_argument("--enable-CAN-gui", action="store_true", help="Whether to display the CAN GUI. Default is False", default=False)
    args.add_argument("--enable-test-rate", action="store_true", help="Test rate mode. Instead of showing the trace or reproducing it, it will output the positioning (Lat, Lon) update frequency and save the related data, message by message, on a file named replay_out.csv. Default is False", default=False)
    args.add_argument("--visualizer-http-port", type=int, help="The port for the HTTP server for the visualizer (GUI). Default is 8080", default=8080)
    args.add_argument("--visualizer-server-ip", type=str, help="The IP address of the server for the visualizer (GUI). Default is 127.0.0.1", default="127.0.0.1")
    args.add_argument("--visualizer-server-port", type=int, help="The port of the server for the visualizer (GUI). Default is 48110", default=48110)
    args.add_argument("--enable-CAN", action="store_true", help="Enable CAN emulator. Default is False", default=False)
    args.add_argument("--CAN-db", type=str, help="The CAN database file", default="./data/can_db/motohawk.dbc")
    args.add_argument("--CAN-device", type=str, help="The CAN device to write to", default="vcan0")
    args.add_argument("--CAN-filename", type=str, help="The CAN file to read from", default="./data/can_output/can_log.json")
    args.add_argument("--enable-csv", action="store_true", help="Save the data to a csv file. Default is False", default=False)
    args.add_argument("--csv-filename", type=str, help="The csv file to save the data to", default="./data/gnss_output/example.csv")
    args.add_argument("--csv-interpolation", action="store_true", help="Interpolate the data to have a fixed information updating. Default is False", default=False)
    args.add_argument("--enable-pcap", action="store_true", help="Enable pcap emulation. Default is False", default=False)
    args.add_argument("--interface", type=str, help="The network interface to which write the pcap content", default="wlan0")
    args.add_argument("--pcap-filename", type=str, help="The pcap file to read the packets for the emulation", default="./data/pcap_output/trace.pcapng")
    args.add_argument("--update-datetime", action="store_true", help="If the emulation of pcap trace must update the packets datetime to the current one. Default is False", default=False)
    args.add_argument("--new-pcap-file", type=str, help="The new pcap file (if needed) with packets with updated datetime", default="")
    args.add_argument("--enable-pcap-gui", action="store_true", help="Whether to display the pcap GUI. Default is False", default=False)
    args.add_argument("--enable-amqp", action="store_true", help="Whether AMQP messaging is enabled. Default is False", default=False)
    args.add_argument("--amqp-server-ip", type=str, help="The IP address of the AMQP server. Default is 127.0.0.1", default="127.0.0.1")
    args.add_argument("--amqp-server-port", type=int, help="The Port of the AMQP server. Default is 5867", default=5867)
    args.add_argument("--amqp-topic", type=str, help="The Topic of the AMQP server. Default is tracenx", default="tracenx")
    args.add_argument("--max-certificates", type=int, help="The maximum number of certificates to manage. Default is 0, which means it will not limit the number of certificates.", default=0)
    args.add_argument("--update-security", action="store_true", help="If set, the script will check and update the security certificates. Default is False", default=False)

    args = args.parse_args()
    # TODO: if enable pcap, read the pcap file and count the certificates and ask
    
    serial = args.enable_serial
    serial_filename = args.serial_filename
    server_device = args.server_device
    client_device = args.client_device
    baudrate = args.baudrate
    assert baudrate == 115200, "Baudrate must be 115200"

    start_time = args.start_time * 1e6 if args.start_time else None
    end_time = args.end_time * 1e6 if args.end_time else None

    enable_serial_gui = args.enable_serial_gui
    enable_CAN_gui = args.enable_CAN_gui
    httpport = args.visualizer_http_port
    server_ip = args.visualizer_server_ip
    server_port = args.visualizer_server_port

    test_rate_enabled = args.enable_test_rate

    CAN = args.enable_CAN
    # CAN = True # For testing purposes
    CAN_db = args.CAN_db
    # CAN_db = "./data/can_db/PCAN.dbc" # For testing purposes
    CAN_device = args.CAN_device
    CAN_filename = args.CAN_filename
    # CAN_filename = "./data/can_output/CANlog.json" # For testing purposes

    csv = args.enable_csv
    csv_filename = args.csv_filename
    csv_interpolation = args.csv_interpolation

    enable_pcap = args.enable_pcap
    interface = args.interface
    pcap_filename = args.pcap_filename
    update_datetime = args.update_datetime
    new_pcap = args.new_pcap_file
    enable_pcap_gui = args.enable_pcap_gui

    enable_amqp = args.enable_amqp
    amqp_server_ip = args.amqp_server_ip
    amqp_server_port = args.amqp_server_port
    amqp_topic = args.amqp_topic
    maxCertificates = args.max_certificates
    update_security = args.update_security

    assert serial > 0 or enable_serial_gui > 0 or test_rate_enabled > 0 or CAN > 0 or csv > 0 or enable_pcap > 0, "At least one of the serial or GUI or test rate or CAN or csv options must be activated"
    CERT_PATH = Path(__file__).resolve().parents[1] / "PKIManager" / "certificates" / "certificates.json"
    if start_time and end_time:
        assert end_time > start_time

    visualizer = None
    fifo_path = None
    serial_process = None
    can_process = None
    test_rate_process = None
    csv_process = None
    gui_process = None
    pcap_process = None

    stop_event = Event()
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, stop_event))


    if enable_pcap and update_datetime and update_security:
        certificates = countCertificates(pcap_filename, args.start_time, args.end_time)
        print(f"The pcap file contains {certificates} certificates")
        active_certificates = count_active_certificates(CERT_PATH, maxCertificates=maxCertificates)
        print(active_certificates)
        for key in active_certificates.keys():
            ECisValid, ATisValid = active_certificates[key]
            if not ECisValid:
                # ask EC and AT certificates
                manager = ECManager()  
                response = ECResponse()
                atManager = ATManager()
                atResponse = ATResponse()
                
                manager.regeneratePEM(key)
                manager.createRequest(key)
                response_file = manager.sendPOST(key)
                try:
                    response.getECResponse(key)
                except RuntimeError as exc:
                    print(f"[ERR] {exc}", file=sys.stderr)
                    sys.exit(1)

                ec = response.m_ecBytesStr
                atManager.m_ECHex = ec
                atManager.regeneratePEM(key)
                atManager.createRequest(key)
                atManager.sendPOST(key)
                atResponse.getATResponse(key)

            elif ECisValid and not ATisValid:
                response = ECResponse()
                atManager = ATManager()
                atResponse = ATResponse()

                try:
                    response.getECResponse(key)
                except RuntimeError as exc:
                    print(f"[ERR] {exc}", file=sys.stderr)
                    sys.exit(1)
                ec = response.m_ecBytesStr
                atManager.m_ECHex = ec
                atManager.regeneratePEM(key)
                atManager.createRequest(key)
                atManager.sendPOST(key)
                atResponse.getATResponse(key)

        if certificates > len(active_certificates):
            print(f"There are not enough active certificates. There are {len(active_certificates)} active certificates.")
            print("Please add new certificates before starting the pcap emulation.")
            exit(1)
        # load json file with the certificates
        filePath = CERT_PATH
        with open(filePath, 'r') as f:
            certificates = json.load(f)
        print(f"Loaded {len(certificates)} certificates from {filePath}")

    if serial:
        assert os.path.exists(serial_filename), "The file does not exist"
        serial_process = Process(
            target=write_serial, args=(stop_event, server_device, client_device, baudrate, serial_filename, start_time, end_time)
        )
        serial_process.start()

    if enable_CAN_gui:
        assert enable_serial_gui, "The serial GUI must be activated to display the CAN GUI"
        assert os.path.exists(CAN_filename), "The file does not exist"
        assert os.path.exists(CAN_db), "The CAN database file does not exist"

    if enable_serial_gui:
        assert os.path.exists(serial_filename), "The file does not exist"
        # Creation of the visualizer object
        visualizer = Visualizer()
        # If GUI modality is activated, start the nodejs server
        fifo_path = "./replay/fifo"
        if not os.path.exists(fifo_path):
            os.mkfifo(fifo_path)
        visualizer.start_nodejs_server(httpport, server_ip, server_port, fifo_path)
        if enable_CAN_gui and not enable_pcap_gui:
            gui_process = Process(
                target=serial_gui, args=(stop_event, serial_filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer, CAN_filename, CAN_db)
            )
        elif enable_CAN_gui and enable_pcap_gui:
            gui_process = Process(
                target=serial_gui, args=(stop_event, serial_filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer, CAN_filename, CAN_db, pcap_filename)
            )
        elif enable_pcap_gui:
            gui_process = Process(
                target=serial_gui, args=(stop_event, serial_filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer, None, None, pcap_filename)
            )
        else:
            gui_process = Process(
                target=serial_gui, args=(stop_event, serial_filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer)
            )

        gui_process.start()
    
    if CAN:
        assert os.path.exists(CAN_filename), "The file does not exist"
        assert os.path.exists(CAN_db), "The CAN database file does not exist"
        can_process = Process(target=write_CAN, args=(stop_event, CAN_device, CAN_filename, CAN_db, start_time, end_time))
        can_process.start()

    if test_rate_enabled:
        assert os.path.exists(serial_filename), "The file does not exist"
        test_rate_process = Process(target=test_rate, args=(stop_event, serial_filename, start_time, end_time))
        test_rate_process.start()
    
    if csv:
        assert os.path.exists(serial_filename), "The file does not exist"
        # Ask the user to insert the agent type
        agent_type = input("Insert the agent type (car, vru): ")
        assert agent_type in ["car", "vru"], "The agent type must be either car or vru"
        agent_id = input("Insert the agent id: ")
        assert agent_id, "The agent id must be inserted"
        csv_process = Process(
            target=csv_conversion, args=(stop_event, serial_filename, csv_filename, csv_interpolation, start_time, end_time, agent_id, agent_type)
        )
        csv_process.start()

    if enable_pcap:
        
        assert os.path.exists(pcap_filename)
        pcap_process = Process(target=write_pcap, args=(stop_event, pcap_filename, interface, start_time, end_time, update_datetime, new_pcap, enable_amqp, amqp_server_ip, amqp_server_port, amqp_topic, certificates, update_security))
        pcap_process.start()

    try:
        if serial:
            serial_process.join()

        if enable_serial_gui:
            gui_process.join()

        if CAN:
            can_process.join()
        
        if test_rate_enabled:
            test_rate_process.join()
        
        if csv:
            csv_process.join()

        if enable_pcap:
            pcap_process.join()

    except KeyboardInterrupt:
        print("Interrupted by user")
        stop_event.set()
        if serial_process: serial_process.join()
        if enable_serial_gui: gui_process.join()
        if CAN: can_process.join()
        if test_rate_enabled: test_rate_process.join()
        if csv: csv_process.join()
        if pcap_process: pcap_process.join()
        

if __name__ == "__main__":
    main()
    # python3 replay/replay.py --enable-pcap --pcap-filename /home/giuseppe/Desktop/TRACEN-X/cattura_MIS_80211p.pcapng --start-time 0 --end-time 60 --new-pcap-file new6.pcapng --update-datetime
