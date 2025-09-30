import time
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import utils
from serial_emulator import SerialEmulator

def write_serial(stop_event: Any, server_device: str, client_device: str, baudrate: int, input_filename: str, start_time: int, end_time: int):
    """
    Writes the data from the file to the serial device.

    Parameters:
    - stop_event (multiprocessing.Event): The Event object to stop the processes.
    - server_device (str): The path to the serial device that acts as the data sender (e.g., "/dev/pts/3").
    - client_device (str): The path to the paired virtual serial device (acts as receiver), if applicable.
    - baudrate (int): Baud rate for the serial communication (e.g., 115200).
    - input_filename (str): Path to the log file containing data to be replayed over the serial interface.
    - start_time (int): Start time in microseconds from the beginning of the log; data before this time will be skipped.
    - end_time (int): End time in microseconds; data after this time will be ignored.
    """
    try:
        # Creation of the serial emulator
        ser = SerialEmulator(device_port=server_device, client_port=client_device, baudrate=baudrate)
        f = open(input_filename, "r")
        data = json.load(f)
        f.close()

        if start_time:
            data = utils.filter_by_start_time(data, start_time)

        previous_time = 0 if not start_time else start_time

        variable_delta_us_factor = 0

        # start_time_us represents the time in microseconds from the beginning of the messages simulation to the start time selected by the user
        start_time_us = start_time if start_time else 0

        first_send = None
        startup_time = time.time() * 1e6
        for d in data:
            delta_time = d["timestamp"] - previous_time

            # Calculate a variable delta time factor to adjust the time of the serial write to be as close as possible to a real time simulation
            # delta_time_us represents the real time in microseconds from the beginning of the simulation to the current time
            delta_time_us_real = time.time() * 1e6 - startup_time
            # delta_time_us_simulation represents the time in microseconds from the beginning of the messages simulation time to the current message time
            delta_time_us_simulation = d["timestamp"] - start_time_us
            # We want that the time of the serial write is as close as possible to the real time simulation
            # variable_delta_us_factor represents the difference between the simulation time and the real time
            # It should be as close as possible to 0 and it is used to adjust the waiting time for the serial write
            variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
            if variable_delta_us_factor > 0:
                # Wait for the real time to be as close as possible to the simulation time
                # print("Sleeping for:", variable_delta_us_factor / 1e6)
                time.sleep(variable_delta_us_factor / 1e6)
            else:
                # print("Trying to sleep for a negative time, thus not sleeping: ", variable_delta_us_factor / 1e3)
                pass

            message_type = d["type"]
            if message_type == "Unknown":
                continue
            content = d["data"]
            if message_type == "UBX":
                content = bytes.fromhex(content)
            else:
                # For the NMEA messages we need to encode the content for the serial emulator and decode it for the GUI (to obtain a string)
                content = content.encode()

            ser.write(content)
            if first_send is None:
                first_send = time.time()
            previous_time = d["timestamp"]
            if (end_time and time.time() * 1e6 - startup_time > end_time) or stop_event.is_set():
                break

    except Exception as e:
        print(f"Error: {e}")

    finally:
        ser.stop()
        print("Time to send all messages:", time.time() - first_send, "s")
        if start_time:
            print("Difference to the last message:", time.time() - first_send - (d["timestamp"] - start_time) / 1e6,
                  "s")
        else:
            print("Difference to the last message:", time.time() - first_send - d["timestamp"] / 1e6, "s")
