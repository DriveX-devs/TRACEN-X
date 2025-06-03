import argparse
import threading
import os
from visualizer import Visualizer
from csv_conversion_utils import csv_conversion
from test_rate_utils import test_rate
from can_utils import write_CAN
from gui_utils import serial_gui
from serial_utils import write_serial

def main():
    """
    This script reads a json file with the following format:
    
    [
        {
            "timestamp": <time in microseconds>,
            "type": <message type>,
            "data": <message data>
        },
        ...
    ]

    and writes the data to a serial device.

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
    - --http-port (int): The port for the HTTP server. Default is 8080.
    - --server-ip (str): The IP address of the server. Default is 127.0.0.1
    - --server-port (int): The port of the server. Default is 48110.
    - --enable-CAN (bool): Whether to enable the CAN emulator. Default is False. Can be activated by writing it.
    - --CAN-db (str): The CAN database file. Default is "./data/can_db/motohawk.dbc".
    - --CAN-device (str): The CAN device to write to. Default is "vcan0".
    - --CAN-filename (str): The CAN file to read from. Default is "./data/CANlog.log".
    - --enable-csv (bool): Save the data to a csv file. Default is False. Can be activated by writing it.
    - --csv-filename (str): The csv file to save the data to. Default is "./data/examples/example.csv".
    - --csv-interpolation (bool): Interpolate the data to have a fixed information updating. Default is False. Can be activated by writing it.

    Example:
    python3 replay/replay.py --enable-serial --serial-filename ./data/gnss_output/example1.json --server-device ./replay/ttyNewServer --client-device ./replay/ttyNewClient --baudrate 115200 --start-time 0 --end-time 10 --enable-gui --http-port 8080
    """
    args = argparse.ArgumentParser()
    args.add_argument("--enable-serial", action="store_true", help="Enable serial emulator")
    args.add_argument("--serial-filename", type=str, help="The file to read data from", default="./data/gnss_output/example.json")
    args.add_argument("--server-device", type=str, help="The device to write data to", default="./replay/ttyNewServer")
    args.add_argument("--client-device", type=str, help="The device to read data from", default="./replay/ttyNewClient")
    args.add_argument("--baudrate", type=int, help="The baudrate to write", default=115200)
    args.add_argument("--start-time", type=int, help="The timestamp to start the reading in seconds. If not specified, will read from the beginning of the file.", default=None)
    args.add_argument("--end-time", type=int, help="The time to stop reading in seconds, if not specified, will write until the endo fo the file", default=None)
    args.add_argument("--enable-serial-gui", action="store_true", help="Whether to display the serial GUI. Default is False", default=False)
    args.add_argument("--enable-CAN-gui", action="store_true", help="Whether to display the CAN GUI. Default is False", default=False)
    args.add_argument("--enable-test-rate", action="store_true", help="Test rate mode. Instead of showing the trace or reproducing it, it will output the positioning (Lat, Lon) update frequency and save the related data, message by message, on a file named replay_out.csv. Default is False", default=False)
    args.add_argument("--http-port", type=int, help="The port for the HTTP server. Default is 8080", default=8080)
    args.add_argument("--server-ip", type=str, help="The IP address of the server. Default is 127.0.0.1", default="127.0.0.1")
    args.add_argument("--server-port", type=int, help="The port of the server. Default is 48110", default=48110)
    args.add_argument("--enable-CAN", action="store_true", help="Enable CAN emulator", default=False)
    args.add_argument("--CAN-db", type=str, help="The CAN database file", default="./data/can_db/motohawk.dbc")
    args.add_argument("--CAN-device", type=str, help="The CAN device to write to", default="vcan0")
    args.add_argument("--CAN-filename", type=str, help="The CAN file to read from", default="./data/can_output/can_log.json")
    args.add_argument("--enable-csv", action="store_true", help="Save the data to a csv file", default=False)
    args.add_argument("--csv-filename", type=str, help="The csv file to save the data to", default="./data/gnss_output/example.csv")
    args.add_argument("--csv-interpolation", action="store_true", help="Interpolate the data to have a fixed information updating", default=False)

    args = args.parse_args()
    serial = args.enable_serial
    serial_filename = args.serial_filename
    server_device = args.server_device
    client_device = args.client_device
    baudrate = args.baudrate
    start_time = args.start_time * 1e6 if args.start_time else None
    end_time = args.end_time * 1e6 if args.end_time else None
    enable_serial_gui = args.enable_serial_gui
    enable_CAN_gui = args.enable_CAN_gui
    httpport = args.http_port
    server_ip = args.server_ip
    server_port = args.server_port
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

    assert serial > 0 or enable_serial_gui > 0 or test_rate_enabled > 0 or CAN > 0 or csv > 0, "At least one of the serial or GUI or test rate or CAN or csv options must be activated"

    visualizer = None
    fifo_path = None
    serial_thread = None
    can_thread = None
    test_rate_thread = None
    csv_thread = None
    gui_thread = None

    if serial:
        assert os.path.exists(serial_filename), "The file does not exist"
        serial_thread = threading.Thread(
            target=write_serial, args=(server_device, client_device, baudrate, serial_filename, start_time, end_time)
        )
        serial_thread.daemon = True
        serial_thread.start()

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
        if enable_CAN_gui:
            gui_thread = threading.Thread(
                target=serial_gui, args=(serial_filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer, CAN_filename, CAN_db)
            )
        else:
            gui_thread = threading.Thread(
                target=serial_gui, args=(serial_filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer)
            )
        gui_thread.daemon = True
        gui_thread.start()
    
    if CAN:
        assert os.path.exists(CAN_filename), "The file does not exist"
        assert os.path.exists(CAN_db), "The CAN database file does not exist"
        can_thread = threading.Thread(
            target=write_CAN, args=(CAN_device, CAN_filename, CAN_db, start_time, end_time)
        )
        can_thread.daemon = True
        can_thread.start()

    if test_rate_enabled:
        assert os.path.exists(serial_filename), "The file does not exist"
        test_rate_thread = threading.Thread(
            target=test_rate, args=(serial_filename, start_time, end_time)
        )
        test_rate_thread.daemon = True
        test_rate_thread.start()
    
    if csv:
        assert os.path.exists(serial_filename), "The file does not exist"
        # Ask the user to insert the agent type
        agent_type = input("Insert the agent type (car, vru): ")
        assert agent_type in ["car", "vru"], "The agent type must be either car or vru"
        agent_id = input("Insert the agent id: ")
        assert agent_id, "The agent id must be inserted"
        csv_thread = threading.Thread(
            target=csv_conversion, args=(serial_filename, csv_filename, csv_interpolation, start_time, end_time, agent_id, agent_type)
        )
        csv_thread.daemon = True
        csv_thread.start()

    if serial:
        serial_thread.join()

    if enable_serial_gui:
        gui_thread.join()

    if CAN:
        can_thread.join()
    
    if test_rate_enabled:
        test_rate_thread.join()
    
    if csv:
        csv_thread.join()
    

if __name__ == "__main__":
    main()
