import utils
import can
import cantools
import time
import json

def write_CAN(device: str, input_filename: str, db_file: str, start_time: int, end_time: int):
    """
    Writes the data from the file to the CAN device.

    Parameters:
    - device (str): The name of the CAN device/interface to send messages to (e.g., "vcan0" or "can0").
    - input_filename (str): Path to the CAN log file (e.g., JSON or ASC format) containing messages to be replayed.
    - db_file (str): Path to the DBC file used for encoding/decoding CAN messages.
    - start_time (int): The start time (in microseconds) relative to the beginning of the capture for replaying messages.
    - end_time (int): The end time (in microseconds) relative to the beginning of the capture; messages after this time will be ignored.

    """
    try:
        first_send = None
        f = open(input_filename, "r")
        data = json.load(f)
        f.close()
        # Filter the data by the start time
        if start_time:
            data = utils.filter_by_start_time(data, start_time)
        # Load the CAN database
        db = cantools.database.load_file(db_file)
        # Create the CAN bus
        bus = can.interface.Bus(channel=device, interface='socketcan')
        previous_time = 0 if not start_time else start_time
        variable_delta_us_factor = 0
        startup_time = time.time() * 1e6
        for d in data:
            delta_time = d["timestamp"] - previous_time
            arbitration_id = d["arbitration_id"]
            content = d["data"]
            # Get the message from the CAN database
            message = db.get_message_by_frame_id(arbitration_id)
            if message:
                # Encode the content of the message
                data = db.encode_message(message.frame_id, content)
                final_message = can.Message(arbitration_id=message.frame_id, data=data, is_extended_id=False)
            start_time_us = start_time if start_time else 0
            # Calculate the delta time in the recording between the current message and the start time
            delta_time_us_simulation = d["timestamp"] - start_time_us
            # Calculate the real time in microseconds from the beginning of the simulation to the current time
            delta_time_us_real = time.time() * 1e6 - startup_time
            # Update the variable_delta_time_us_factor to adjust the time of the CAN write to be as close as possible to a real time simulation
            variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
            if variable_delta_us_factor > 0:
                # Wait for the real time to be as close as possible to the simulation time
                time.sleep(variable_delta_us_factor / 1e6)
            else:
                # print("Trying to sleep for a negative time, thus not sleeping: ", variable_delta_us_factor / 1e3)
                pass
            if message:
                # Write the message to the CAN bus
                if first_send is None:
                    first_send = time.time()
                bus.send(final_message)
            previous_time = d["timestamp"]
            if end_time and time.time() * 1e6 - startup_time > end_time:
                break
    except Exception as e:
        print(f"Error: {e}")
    finally:
        bus.shutdown()
        print("Time to send all messages:", time.time() - first_send, "s")
        if start_time:
            print("Difference to the last message:", time.time() - first_send - d["timestamp"] - start_time / 1e6, "s")
        else:
            print("Difference to the last message:", time.time() - first_send - d["timestamp"] / 1e6, "s")

