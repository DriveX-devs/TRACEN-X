import math
import sys
import json
import time
import can
import cantools
import pyproj
from decoded_messages import DecodedMessage
from visualizer import Visualizer
import threading
from serial_emulator import SerialEmulator

sys.path.insert(1, './serial_emulator')

CLUSTER_TSHOLD_MS = 20 # In [ms]
MAP_OPENED = False
BUMPER_TO_SENSOR_DISTANCE = 1.54  # In [m]
STANDARD_OBJECT_LENGTH = 4.24  # [m]
STANDARD_OBJECT_WIDTH = 1.81  # [m]

METERS_PER_DEGREE_LATITUDE = 111320
SPEED_THRESHOLD = 15  # [m/s]
AGE_THRESHOLD = 20  # [ms]


def compare_floats(a: float, b: float) -> bool:
    return math.isclose(a, b, rel_tol=1e-8)


def filter_by_start_time(data, start_time: int) -> list:
    start_time_micseconds = start_time
    assert start_time_micseconds < data[-1]["timestamp"], "The start time is greater than the last timestamp in the file"
    return list(filter(lambda x: x["timestamp"] >= start_time_micseconds, data))
