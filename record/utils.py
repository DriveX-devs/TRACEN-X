import json

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