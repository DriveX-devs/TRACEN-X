import serial
import time
import json
import argparse
import sys
import signal
from collections import deque
import cantools, can
import cantools.logreader
import threading
import traceback

sys.path.insert(1, './serial_emulator')
                
from serial_emulator import SerialEmulator

TERMINATOR_FLAG = False
CAN_WAIT_TIME = 200 # seconds
NULL_CNT = 500000 # Number of null characters to wait before stopping the serial read

def signal_handler(sig, frame):
    """
    Signal handler for the SIGINT signal.
    """
    global TERMINATOR_FLAG
    print('\nTerminating...');
    TERMINATOR_FLAG = True

def save_message(messages: list, res: str, timestamp: float, message_type: str):
    """
    Saves a message to the provided list of messages.
    
    Parameters:
    - messages (list): The list to which the message will be appended.
    - res (str): The message content.
    - timestamp (float): The timestamp of the message.
    - message_type (str): The type of the message (e.g., "NMEA", "UBX").
    """
    
    try:
        data = {
            "timestamp": timestamp,
            "type": message_type,
            "data": res.hex() if message_type in ["UBX", "Unknown"] else res.decode()
        }
    except:
        data = {
            "timestamp": timestamp,
            "type": "Unknown",
            "data": res.hex()
        }
    finally:
        messages.append(data)

def write_to_file(f, messages: list):
    """
    Writes the list of messages to the specified file in JSON format.\n
    
    Parameters:
    - f (file object): The file object to write to.
    - messages (list): The list of messages to write.
    """
    json_object = json.dumps(list(messages))
    print("Writing to file...")
    f.write(json_object)
    print("Done...")
    f.close()

def setup_file(filename: str):
    """
    Sets up a file for writing by truncating its content.
    
    Parameters:
    - filename (str): The file to write to.

    Returns:
    - f (file object): The file object to write to.
    """
    f = open(filename, "a")
    # Drop the old content of the file
    f.seek(0)
    f.truncate()
    return f

def close_file(f):
    f.close()

def read_CAN_bus(CAN_device: str, CAN_filename: str, CAN_db: str, CAN_log_file_source: str, end_time: int):
    """
    Reads the CAN bus and writes the messages to a file.
    
    Parameters:
    - CAN_device (str): The CAN device to read from.
    - CAN_filename (str): The file to write to.
    - CAN_db (str): The CAN database file.
    - CAN_log_file_source (bool): Wheather the source of the CAN log file is the CAN bus or a file.
    - end_time (int): The time to stop reading in seconds.
    """
    can_messages = deque()
    can_bus = None
    try:
        f = setup_file(CAN_filename)
        print("Reading CAN bus...")
        db_can = cantools.database.load_file(CAN_db)
        message_ids = [m.frame_id for m in db_can.messages]
        flat_time_setted = False
        flat_time = None
        if CAN_log_file_source is None:
            can_bus = can.interface.Bus(channel=CAN_device, interface='socketcan')
            # Set the flat time to the current time if the log file source is the CAN bus
            # If there is no log file source, set the flat time to the current time
            flat_time = time.time() * 1e6
            flat_time_setted = True
            while True:
                message = can_bus.recv(CAN_WAIT_TIME)
                if message.arbitration_id not in message_ids:
                    if not flat_time_setted:
                        flat_time = message.timestamp * 1e6
                        flat_time_setted = True
                    continue
                if message:
                    if not flat_time_setted:
                        flat_time = message.timestamp * 1e6
                        flat_time_setted = True
                    decoded_message = db_can.decode_message(message.arbitration_id, message.data)
                    decoded_message = {k: (v.value if isinstance(v, cantools.database.can.signal.NamedSignalValue) else v) for k, v in decoded_message.items()}
                    object = {
                        "timestamp": message.timestamp * 1e6 - flat_time,
                        "arbitration_id": message.arbitration_id,
                        "data": decoded_message
                    }
                    can_messages.append(object)
                else:
                    # Terminate the thread if no messages are received
                    print("Expired waiting time for CAN bus messages")
                    break
                t = time.time()
                if (end_time is not None and t > end_time) or TERMINATOR_FLAG:
                    break
        else:
            # Read the log file
            flat_time = -1
            with open(CAN_log_file_source, "r") as log_file:
                parser = cantools.logreader.Parser(log_file)
                for message in parser:
                    if message.frame_id not in message_ids:
                        continue
                    if flat_time == -1:
                        flat_time = message.timestamp.timestamp() * 1e6
                    decoded_message = db_can.decode_message(message.frame_id, message.data)
                    decoded_message = {k: (v.value if isinstance(v, cantools.database.can.signal.NamedSignalValue) else v) for k, v in decoded_message.items()}
                    object = {
                        "timestamp": message.timestamp.timestamp() * 1e6 - flat_time,
                        "arbitration_id": message.frame_id,
                        "data": decoded_message
                    }
                    can_messages.append(object)
                    t = time.time()
                    if (end_time is not None and t > end_time) or TERMINATOR_FLAG:
                        break

    except Exception as e:
        print(f"An error occurred in reading CAN bus: {e}")
        traceback.print_exc()
    finally:
        # Check if there are any messages to write
        if len(can_messages) > 0:
            print("Writing CAN messages to file...")
            write_to_file(f, can_messages)
        print("Closing CAN bus...")
        if can_bus is not None:
            can_bus.shutdown()

def read_serial(serial_filename: str, ser: serial.Serial, end_time: int, real_time: bool):
    """
    Reads data from a serial device and writes the messages to a file.

    Parameters:
    - serial_filename (str): The file to write to.
    - ser (serial.Serial): The serial object to read from.
    - end_time (int): The time to stop reading in seconds.
    - real_time (bool): Enable real-time serial emulation.
    """
    f = setup_file(serial_filename)
    messages = deque()
    queue = b''
    ubx_flag = False
    ubx_timestamp = None
    nmea_timestamp = None
    unknown_timestamp = None
    previous_data = b''
    null_cnt = 0

    serial_device = None
    if real_time:
        serial_device = SerialEmulator(device_port='/dev/ttyTestDevice', client_port='/dev/ttyTestClient', baudrate=115200)

    print('Recording GNSS...');
    if end_time is not None:
        end_time = time.time() + end_time

    try:
        first_message = True
        flat_time = time.time() * 1e6
        while True:
            data = ser.read(size=1)
            if real_time:
                serial_device.write(data)
            # print(data)
            if not data:
                null_cnt += 1
            else:
                null_cnt = 0
            if null_cnt > NULL_CNT:
                print("Error. Serial stopped sending data...")
                break
            if first_message:
                # Set the first timestamp in case the first message is an unknown message
                unknown_timestamp = time.time() * 1e6
                first_message = False
            if len(queue) < 1:
                previous_data = data
                queue += data
                continue
            # Read the last two bytes of the queue
            last_two_bytes = previous_data + data
            if last_two_bytes == b'$G':
                # A NMEA message is starting
                if ubx_flag:
                    # If there is a previous UBX message, save it
                    save_message(messages, queue[:-1], ubx_timestamp - flat_time, "UBX")
                elif len(queue) - 1 > 0:
                    # If there is a previous unknown message, save it
                    save_message(messages, queue[:-1], unknown_timestamp - flat_time, "Unknown")
                nmea_timestamp = time.time() * 1e6
                queue = last_two_bytes
                ubx_flag = False
            elif last_two_bytes == b'\r\n':
                # Maybe one message is ending
                if not ubx_flag:
                    # A NMEA message is ending or an unknown message is present
                    first_two_bytes = queue[:2]
                    if first_two_bytes == b'$G':
                        # This is a NMEA message, so we save it
                        save_message(messages, queue + b'\n', nmea_timestamp - flat_time, "NMEA")
                        queue = b''
                        # We don't know the nature of the next message, so we set the unknown timestamp
                        unknown_timestamp = time.time() * 1e6
                    else:
                        # This is an unknown message, so we keep reading
                        queue += data
                else:
                    # This is the continuation of a UBX message, so we keep reading
                    queue += data
            elif last_two_bytes == b'\xb5\x62':
                # A UBX message is starting
                if ubx_flag:
                    # If there is a previous UBX message, save it
                    save_message(messages, queue[:-1], ubx_timestamp - flat_time, "UBX")
                elif len(queue) - 1 > 0:
                    # If there is a previous unknown message, save it
                    save_message(messages, queue[:-1], unknown_timestamp - flat_time, "Unknown")
                ubx_flag = True
                ubx_timestamp = time.time() * 1e6
                queue = last_two_bytes
            else:
                queue += data
            t = time.time()
            if (end_time is not None and t > end_time) or TERMINATOR_FLAG:
                break
            previous_data = data
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Write the messages to the file
        print("Writing GNSS messages to file...")
        write_to_file(f, messages)
        print("Closing serial port...")
        ser.close()

def main():
    """
    Main function to read data from a serial device and save it to a file.
    
    Command-line Arguments:
    - --enable-serial (bool): Enable serial logging. Default is False. Can be activated by writing it.
    - --serial-device (str): The device to read from. Default is "/dev/ttyACM0".
    - --serial-filename (str): The file to write to. Default is "./data/outlog.json".
    - --baudrate (int): The baudrate to read from. Default is 115200.
    - --end-time (int): The time to stop reading in seconds. If not specified, will read indefinitely.
    - --enable-CAN (bool): Enable CAN logging. Default is False. Can be activated by writing it.
    - --CAN-device (str): The CAN device to read from. Default is "vcan0".
    - --CAN-filename (str): The CAN file to write to. Default is "./data/CANlog.json".
    - --CAN-db (str): The CAN database file. Default is "./data/motohawk.dbc".
    - --real-time-serial (bool): Enable real-time serial emulation. Default is False. Can be activated by writing it.

    Example:
    python3 record/record.py --enable_serial --device=/dev/ttyACM0 --serial_filename=./data/outlog.json --baudrate=115200 --end_time=10 --enable_CAN --CAN_device=vcan0 --CAN_filename=./data/CANlog.json --CAN_db=./data/motohawk.db
    """
    args = argparse.ArgumentParser()
    args.add_argument("--enable-serial", action="store_true", help="Enable serial logging")
    args.add_argument("--serial-device", type=str, help="The device to read from", default="/dev/ttyACM0")
    args.add_argument("--serial-filename", type=str, help="The file to write to", default="./data/gnss_output/outlog.json")
    args.add_argument("--baudrate", type=int, help="The baudrate to read from", default=115200)
    args.add_argument("--end-time", type=int, help="The time to stop reading in seconds, if not specified, will read indefinitely", default=None)
    args.add_argument("--enable-CAN", action="store_true", help="Enable CAN logging")
    args.add_argument("--CAN-device", type=str, help="The CAN device to read from", default="vcan0")
    args.add_argument("--CAN-log-file-source", type=str, help="CAN log file to read from", default=None)
    args.add_argument("--CAN-filename", type=str, help="The CAN file to write to", default="./data/can_output/CANlog.json")
    args.add_argument("--CAN-db", type=str, help="The CAN database file", default="./data/can_db/motohawk.dbc")
    args.add_argument("--real-time-serial", action="store_true", help="Enable real-time serial emulation")


    signal.signal(signal.SIGINT, signal_handler)

    args = args.parse_args()
    enable_serial = args.enable_serial
    enable_CAN = args.enable_CAN

    assert enable_serial or enable_CAN, "At least one of serial or CAN logging must be enabled"

    end_time = args.end_time

    candump_thread = None

    if enable_CAN:
        CAN_device = args.CAN_device
        CAN_filename = args.CAN_filename
        CAN_db = args.CAN_db
        CAN_log_file_source = args.CAN_log_file_source
        # Start thread to read CAN bus
        candump_thread = threading.Thread(target=read_CAN_bus, args=(CAN_device, CAN_filename, CAN_db, CAN_log_file_source, end_time))
        # Set the thread as a daemon so it will be killed when the main thread exits
        candump_thread.daemon = True
        candump_thread.start()

    if enable_serial:
        device = args.serial_device
        serial_filename = args.serial_filename
        baudrate = args.baudrate
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
        read_serial(serial_filename, ser, end_time, real_time)

    if enable_CAN:
        candump_thread.join()

if __name__ == "__main__":
    main()
