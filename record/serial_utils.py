import utils
import sys
import serial
import time
from collections import deque
from typing import Any

sys.path.insert(1, './serial_emulator')

from serial_emulator import SerialEmulator

def read_serial(barrier: Any, stop_event: Any, serial_filename: str, ser: serial.Serial, end_time: int, real_time: bool):
    """
    Reads data from a serial device and writes the messages to a file.

    Parameters:
    - stop_event (multiprocessing.Event): The Event object to stop the processes.
    - serial_filename (str): The file to write to.
    - ser (serial.Serial): The serial object to read from.
    - end_time (int): The time to stop reading in seconds.
    - real_time (bool): Enable real-time serial emulation.
    """
    f = utils.setup_file(serial_filename)
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

    if barrier:
        barrier.wait()

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
            if null_cnt > utils.NULL_CNT:
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
                    utils.save_message(messages, queue[:-1], ubx_timestamp - flat_time, "UBX")
                elif len(queue) - 1 > 0:
                    # If there is a previous unknown message, save it
                    utils.save_message(messages, queue[:-1], unknown_timestamp - flat_time, "Unknown")
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
                        utils.save_message(messages, queue + b'\n', nmea_timestamp - flat_time, "NMEA")
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
                    utils.save_message(messages, queue[:-1], ubx_timestamp - flat_time, "UBX")
                elif len(queue) - 1 > 0:
                    # If there is a previous unknown message, save it
                    utils.save_message(messages, queue[:-1], unknown_timestamp - flat_time, "Unknown")
                ubx_flag = True
                ubx_timestamp = time.time() * 1e6
                queue = last_two_bytes
            else:
                queue += data
            t = time.time()
            if (end_time is not None and t > end_time) or stop_event.is_set():
                break
            previous_data = data
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Write the messages to the file
        print("Writing GNSS messages to file...")
        utils.write_to_file(f, messages)
        print("Closing serial port...")
        ser.close()
