import utils
import can
import cantools
import time
import traceback
from collections import deque

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
        f = utils.setup_file(CAN_filename)
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
                message = can_bus.recv(utils.CAN_WAIT_TIME)
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
                    decoded_message = {
                        k: (v.value if isinstance(v, cantools.database.can.signal.NamedSignalValue) else v) for k, v in
                        decoded_message.items()}
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
                if (end_time is not None and t > end_time) or utils.TERMINATOR_FLAG:
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
                    decoded_message = {
                        k: (v.value if isinstance(v, cantools.database.can.signal.NamedSignalValue) else v) for k, v in
                        decoded_message.items()}
                    object = {
                        "timestamp": message.timestamp.timestamp() * 1e6 - flat_time,
                        "arbitration_id": message.frame_id,
                        "data": decoded_message
                    }
                    can_messages.append(object)
                    t = time.time()
                    if (end_time is not None and t > end_time) or utils.TERMINATOR_FLAG:
                        break

    except Exception as e:
        print(f"An error occurred in reading CAN bus: {e}")
        traceback.print_exc()
    finally:
        # Check if there are any messages to write
        if len(can_messages) > 0:
            print("Writing CAN messages to file...")
            utils.write_to_file(f, can_messages)
        print("Closing CAN bus...")
        if can_bus is not None:
            can_bus.shutdown()
