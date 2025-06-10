import utils
import json
import math
import time
import cantools
import pyproj
import threading
from decoded_messages import DecodedMessage
from visualizer import Visualizer
from scapy.all import *
import asn1tools as asn
from typing import Any

MAP_OPENED = False
BTP_LOW = 40
BTP_HIGH = 44
BTP_PORT_HIGH = 2
ETHER_LENGTH = 14

CONVERSION_CONSTANT = 1e7
PERCEIVED_OBJ_CONT_IDX = 5
CONSTANT_PERCEIVED_OBJ = 2

CAM_ID_SET = set()

cpm_asn = "./data/asn/CPM-all.asn"
vam_asn = "./data/asn/VAM-PDU-FullDescription.asn"
cam_asn = "./data/asn/CAM-all-old.asn"
CPM = asn.compile_files(cpm_asn, "uper")
VAM = asn.compile_files(vam_asn, "uper")
CAM = asn.compile_files(cam_asn, "uper")

def manage_map(GNSS_flag: bool, CAN_flag: bool, pcap_flag: bool, fifo_path: str, latitude: float, longitude: float, heading: float, server_ip: str, server_port: int, visualizer: Visualizer, station_id: int = 1, type: int = 5):
    global MAP_OPENED
    try:
        if not MAP_OPENED:
            # Open the map GUI after the nodejs server is ready
            fp = open(fifo_path, 'r')
            info = fp.read()
            print(info)
            if "ready" not in info:
                raise Exception("Error opening map GUI")
            visualizer.open_map_gui(latitude, longitude, server_ip, server_port)
            MAP_OPENED = True
            print("It is possible to open the map GUI at http://localhost:8080")
    except Exception as e:
        print(f"Error opening map GUI: {e}")
        raise e
    try:
        # Send the new object position to the server that will update the map GUI
        visualizer.send_object_udp_message(GNSS_flag, CAN_flag, pcap_flag, latitude, longitude, heading, server_ip, server_port, station_id, type)
    except Exception as e:
        print(f"Error sending UDP message: {e}")
        raise e


def pcap_gui(pcap_filename: str, start_time: int, end_time: int, server_ip: str, server_port: int, fifo_path: str, visualizer: Visualizer):
    pcap = rdpcap(pcap_filename)
    assert pcap, "Pcap file is empty"

    # start_time_us represents the time in microseconds from the beginning of the messages simulation to the start time selected by the user
    start_time_us = start_time if start_time else 0

    base_ts = pcap[0].time  # epoch time in seconds
    startup_time = time.time() * 1e6
    try:
        for i, pkt in enumerate(pcap):
            try:
                pkt_ts_us = int(1e6 * (pkt.time - base_ts))

                if start_time is not None and pkt_ts_us < start_time:
                    continue

                if end_time is not None and pkt_ts_us > end_time:
                    break

                while not MAP_OPENED:
                    startup_time = time.time() * 1e6

                delta_time_us_real = time.time() * 1e6 - startup_time
                delta_time_us_simulation = pkt_ts_us - start_time_us
                variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
                if variable_delta_us_factor > 0:
                    # Wait for the real time to be as close as possible to the simulation time
                    # print("Sleeping for:", variable_delta_us_factor / 1e6)
                    time.sleep(variable_delta_us_factor / 1e6)
                else:
                    # print("Trying to sleep for a negative time, thus not sleeping: ", variable_delta_us_factor / 1e3)
                    pass

                data = raw(pkt)[ETHER_LENGTH:]
                btp = data[BTP_LOW: BTP_HIGH]
                port = int.from_bytes(btp[:BTP_PORT_HIGH], byteorder="big")
                _, ego_lon, _ = visualizer.get_ego_position()
                utm_zone = int((ego_lon + 180) // 6) + 1
                if port == 2009:
                    # CPM
                    cpm_bytes = data[BTP_HIGH:]
                    cpm = CPM.decode("CollectivePerceptionMessage", cpm_bytes)
                    station_id = cpm["header"]["stationId"]
                    ref_lat = cpm["payload"]["managementContainer"]["referencePosition"]["latitude"] / CONVERSION_CONSTANT
                    ref_lon = cpm["payload"]["managementContainer"]["referencePosition"]["longitude"] / CONVERSION_CONSTANT
                    proj = pyproj.Proj(proj='utm', zone=utm_zone, ellps='WGS84', datum='WGS84')
                    ref_x, ref_y = proj(ref_lon, ref_lat)
                    for idx_j, container in enumerate(cpm['payload']['cpmContainers']):
                        if cpm['payload']['cpmContainers'][idx_j]['containerId'] == 1:
                            originating_veh_container = CPM.decode("OriginatingVehicleContainer", cpm["payload"]['cpmContainers'][idx_j]['containerData'])
                            heading = originating_veh_container["orientationAngle"]["value"] / 100
                            if station_id not in CAM_ID_SET:
                                manage_map(GNSS_flag=False, CAN_flag=False, pcap_flag=True,
                                           fifo_path=fifo_path, latitude=ref_lat, longitude=ref_lon,
                                           heading=heading, server_ip=server_ip, server_port=server_port,
                                           visualizer=visualizer,
                                           station_id=station_id, type=6)
                        if cpm['payload']['cpmContainers'][idx_j]['containerId'] == PERCEIVED_OBJ_CONT_IDX:
                            perceived_object_container = CPM.decode("PerceivedObjectContainer", cpm["payload"]['cpmContainers'][idx_j]['containerData'])
                            for idx_i, objs in enumerate(perceived_object_container['perceivedObjects']):
                                obj_id = objs["objectId"]
                                local_y = objs["position"]["yCoordinate"]["value"] / 100
                                local_x = objs["position"]["xCoordinate"]["value"] / 100
                                abs_x = ref_x + local_x + CONSTANT_PERCEIVED_OBJ
                                abs_y = ref_y + local_y + CONSTANT_PERCEIVED_OBJ
                                lon, lat = proj(abs_x, abs_y, inverse=True)
                                manage_map(GNSS_flag=False, CAN_flag=False, pcap_flag=True,
                                           fifo_path=fifo_path, latitude=lat, longitude=lon,
                                           heading=None, server_ip=server_ip, server_port=server_port,
                                           visualizer=visualizer, station_id=obj_id, type=5)

                elif port == 2001:
                    # CAM
                    cam_bytes = data[BTP_HIGH:]
                    cam = CAM.decode("CAM", cam_bytes)
                    station_id = cam["header"]["stationID"]
                    lat = cam["cam"]["camParameters"]["basicContainer"]["referencePosition"]["latitude"] / CONVERSION_CONSTANT
                    lon = cam["cam"]["camParameters"]["basicContainer"]["referencePosition"]["longitude"] / CONVERSION_CONSTANT
                    heading = cam["cam"]["camParameters"]["highFrequencyContainer"][1]["heading"]["headingValue"] / 10
                    while not MAP_OPENED:
                        startup_time = time.time() * 1e6
                    if station_id not in CAM_ID_SET:
                        CAM_ID_SET.add(station_id)
                    manage_map(GNSS_flag=False, CAN_flag=False, pcap_flag=True, fifo_path=fifo_path, latitude=lat, longitude=lon,
                                   heading=heading, server_ip=server_ip, server_port=server_port, visualizer=visualizer,
                                   station_id=station_id, type=6)

                elif port == 2018:
                    # VAM
                    vam_bytes = data[BTP_HIGH:]
                    vam = VAM.decode("VAM", vam_bytes)
                    station_id = vam["header"]["stationId"]
                    lat = vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["latitude"] / CONVERSION_CONSTANT
                    lon = vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["longitude"] / CONVERSION_CONSTANT
                    heading = vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["heading"]["value"] / 10
                    manage_map(GNSS_flag=False, CAN_flag=False, pcap_flag=True, fifo_path=fifo_path, latitude=lat,
                               longitude=lon, heading=heading, server_ip=server_ip, server_port=server_port, visualizer=visualizer,
                               station_id=station_id, type=1)

                elif port == 2002:
                    # TODO DENM
                    continue

            except Exception as e:
                # Malformed packet
                continue
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if visualizer:
            visualizer.stop_server(server_ip, server_port)


def CAN_gui(CAN_filename: str, CAN_db: str, start_time: int, end_time: int, server_ip: str, server_port: int,
            fifo_path: str, visualizer: Visualizer):
    """
    GUI function to display the data on the map.

    Parameters:
    - CAN_filename (str): Path to the CAN log file (e.g., JSON format with decoded CAN messages).
    - CAN_db (str): Path to the DBC file used to decode CAN messages.
    - start_time (int): Start time in microseconds for filtering the data to visualize.
    - end_time (int): End time in microseconds for filtering the data to visualize.
    - server_ip (str): IP address of the server to which data might be streamed.
    - server_port (int): Port on the server for data communication.
    - fifo_path (str): Path to a FIFO pipe used for inter-process communication (e.g., to feed data to another tool).
    - visualizer (Visualizer): Visualizer object responsible for rendering data on the GUI/map.

    """
    try:
        f = open(CAN_filename, "r")
        data = json.load(f)
        f.close()
        # Filter the data by the start time
        if start_time:
            data = utils.filter_by_start_time(data, start_time)
        # Load the CAN database
        db = cantools.database.load_file(CAN_db)
        previous_time = 0 if not start_time else start_time
        variable_delta_us_factor = 0
        startup_time = time.time() * 1e6
        for d in data:
            delta_time = d["timestamp"] - previous_time

            while not MAP_OPENED:
                startup_time = time.time() * 1e6

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

            arbitration_id = d["arbitration_id"]
            content = d["data"]
            # Get the message from the CAN database
            message = db.get_message_by_frame_id(arbitration_id)
            # TODO - handle other types of messages
            if message and 'Object' in message.name:
                angle_left_signal = None
                angle_right_signal = None
                distance_signal = None

                for signal in message.signals:
                    if 'angle' in signal.comment:
                        if 'left' in signal.comment:
                            angle_left_signal = signal
                        elif 'right' in signal.comment:
                            angle_right_signal = signal
                    elif 'distance' in signal.comment:
                        distance_signal = signal
                if content and visualizer.get_ego_position() is not None and angle_left_signal and angle_right_signal and distance_signal:
                    if content[distance_signal.name] != 0.0:
                        ego_lat, ego_lon, ego_heading = visualizer.get_ego_position()
                        distance = content[distance_signal.name]
                        angle_left = content[angle_left_signal.name]
                        angle_right = content[angle_right_signal.name]
                        # Calculate the position of the object
                        dx_v = distance - utils.BUMPER_TO_SENSOR_DISTANCE + utils.STANDARD_OBJECT_LENGTH / 2
                        dist_left = dx_v / math.cos(angle_left)
                        dist_right = dx_v / math.cos(angle_right)
                        dy_left = dist_left * math.sin(angle_left)
                        dy_right = dist_right * math.sin(angle_right)
                        width = dy_right - dy_left
                        dy_v = dy_left + width / 2
                        # ETSI TS 103 324 V2.1.1 (2023-06) demands xDistance and yDistance to be with East as positive x and North as positive y
                        ego_heading_cart = math.radians(
                            90 - ego_heading)  # The heading from the gps is relative to North --> 90 degrees from East
                        dy_c = -dy_v  # Left to the sensor is negative in radar frame but positive in cartesian reference
                        xDistance = dx_v * math.cos(ego_heading_cart) - dy_c * math.sin(ego_heading_cart)
                        yDistance = dx_v * math.sin(ego_heading_cart) + dy_c * math.cos(ego_heading_cart)
                        # Calculate the position of the object in the global reference frame
                        utm_zone = int((ego_lon + 180) // 6) + 1  # Calculate UTM zone based on longitude
                        proj_tmerc = pyproj.Proj(proj='utm', zone=utm_zone, ellps='WGS84', datum='WGS84')
                        # Forward transformation: convert geographic coordinates (lat, lon) to projected (x, y)
                        ego_x, ego_y = proj_tmerc(ego_lon, ego_lat)
                        ego_x += xDistance
                        ego_y += yDistance
                        # Reverse transformation: convert projected (x, y) back to geographic coordinates (lat, lon)
                        lon1, lat1 = proj_tmerc(ego_x, ego_y, inverse=True)
                        manage_map(GNSS_flag=False, CAN_flag=True, pcap_flag=False, fifo_path=fifo_path, latitude=lat1, longitude=lon1,
                                   heading=None, server_ip=server_ip, server_port=server_port, visualizer=visualizer,
                                   station_id=arbitration_id, type=5)
                    pass

            if end_time and time.time() * 1e6 - startup_time > end_time:
                break
    except Exception as e:
        print(f"Error: {e}")

    finally:
        if visualizer:
            visualizer.stop_server(server_ip, server_port)


def serial_gui(stop_event: Any, input_filename: str, start_time: int, end_time: int, server_ip: str, server_port: int, fifo_path: str,
               visualizer: Visualizer, CAN_filename: str = None, CAN_db: str = None, pcap_filename: str = None):
    """
    GUI function to display the data on the map.

    Parameters:
    - stop_event (multiprocessing.Event): The Event object to stop the processes.
    - input_filename (str): Path to the GNSS serial log file (e.g., JSON format).
    - start_time (int): Start time in microseconds for filtering the data to visualize.
    - end_time (int): End time in microseconds for filtering the data to visualize.
    - server_ip (str): IP address of the server to which data may be streamed.
    - server_port (int): Port number for the server communication.
    - fifo_path (str): Path to a FIFO pipe used for inter-process communication.
    - visualizer (Visualizer): Visualizer object responsible for rendering the data on the GUI/map.
    - CAN_filename (str, optional): Path to the CAN log file (if CAN data should be included). Default is None.
    - CAN_db (str, optional): Path to the DBC file used to decode CAN messages. Required if CAN_filename is provided. Default is None.
    - pcap_filename (str, optional): Path to the pcap file. Default is None
    """

    try:
        decoder = DecodedMessage()
        f = open(input_filename, "r")
        data = json.load(f)
        f.close()

        if start_time:
            data = utils.filter_by_start_time(data, start_time)

        previous_time = 0 if not start_time else start_time
        latitude = None
        longitude = None
        heading = None
        variable_delta_us_factor = 0

        first_send = None
        startup_time = time.time() * 1e6

        # If CAN GUI is enabled, start the CAN GUI function in a separate thread
        can_thread = None
        if CAN_filename and CAN_db:
            can_thread = threading.Thread(
                target=CAN_gui, args=(CAN_filename, CAN_db, start_time, end_time, server_ip, server_port, fifo_path, visualizer), daemon=True)
            can_thread.start()

        pcap_thread = None
        if pcap_filename:
            pcap_thread = threading.Thread(
                target=pcap_gui,
                args=(pcap_filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer),
                daemon=True)
            pcap_thread.start()

        for d in data:
            delta_time = d["timestamp"] - previous_time

            delta_time_us_real = time.time() * 1e6 - startup_time
            start_time_us = start_time if start_time else 0
            delta_time_us_simulation = d["timestamp"] - start_time_us
            variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
            if variable_delta_us_factor > 0:
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
                tmp_lat, tmp_lon, tmp_heading, _ = decoder.extract_data(content, message_type)
                if tmp_lat:
                    latitude = tmp_lat
                if tmp_lon:
                    longitude = tmp_lon
                if tmp_heading:
                    heading = tmp_heading
            else:
                content = content.encode()
                tmp_lat, tmp_lon, tmp_heading, _ = decoder.extract_data(content.decode(), message_type)
                if tmp_lat:
                    latitude = tmp_lat
                if tmp_lon:
                    longitude = tmp_lon
                if tmp_heading:
                    heading = tmp_heading

            if first_send is None:
                first_send = time.time()
            previous_time = d["timestamp"]
            if latitude and longitude:
                manage_map(GNSS_flag=True, CAN_flag=False, pcap_flag=False, fifo_path=fifo_path, latitude=latitude, longitude=longitude,
                           heading=heading, server_ip=server_ip, server_port=server_port, visualizer=visualizer)
            if (end_time and time.time() * 1e6 - startup_time > end_time) or stop_event.is_set():
                break
    except Exception as e:
        print(f"Error: {e}")

    finally:
        if visualizer:
            visualizer.stop_server(server_ip, server_port)
        if can_thread:
            can_thread.join()
        if pcap_thread:
            pcap_thread.join()
