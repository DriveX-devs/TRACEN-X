import time
import argparse
import json
import threading
import sys
import numpy as np
import pandas as pd
import math
from decoded_messages import DecodedMessage
from visualizer import Visualizer
import os
import cantools, can
import pyproj

sys.path.insert(1, './serial_emulator')
                
from serial_emulator import SerialEmulator

CLUSTER_TSHOLD_MS = 20 # In [ms]
MAP_OPENED = False
BUMPER_TO_SENSOR_DISTANCE = 1.54  # In [m]
STANDARD_OBJECT_LENGTH = 4.24  # [m]
STANDARD_OBJECT_WIDTH = 1.81  # [m]

UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT = False, False, False, False

METERS_PER_DEGREE_LATITUDE = 111320
SPEED_THRESHOLD = 15  # [m/s]
AGE_THRESHOLD = 20  # [ms]

def compare_floats(a, b):
    return math.isclose(a, b, rel_tol=1e-8)

def filter_by_start_time(data, start_time):
    start_time_micseconds = start_time
    assert start_time_micseconds < data[-1]["timestamp"], "The start time is greater than the last timestamp in the file"
    return list(filter(lambda x: x["timestamp"] >= start_time_micseconds, data))

def set_ubx_flag(ubx_type):
    global UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT
    if ubx_type is not None:
        if ubx_type == "NAV-PVT":
            UBX_NAV_PVT_PRESENT = True
        if ubx_type == "NAV-ATT":
            UBX_NAV_ATT_PRESENT = True
        if ubx_type == "ESF-INS":
            UBX_ESF_INS_PRESENT = True
        if ubx_type == "ESF-RAW":
            UBX_ESF_RAW_PRESENT = True
        
def manage_map(GNSS_flag, CAN_flag, fifo_path, latitude, longitude, heading, server_ip, server_port, visualizer, station_id=1, type=5):
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
        visualizer.send_object_udp_message(GNSS_flag, CAN_flag, latitude, longitude, heading, server_ip, server_port, station_id, type)
    except Exception as e:
        print(f"Error sending UDP message: {e}")
        raise e
    
def print_test_rate_stats(average_update_time, average_update_time_filtered):
    global UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT
    print("Average update periodicity:", average_update_time, "ms")

    print("Average update rate (filtered):", 1e3/average_update_time_filtered, "Hz")
    print("Average update periodicity (filtered):", average_update_time_filtered, "ms")

    print("UBX messages statistics:")
    print("UBX-NAV-PVT present:", UBX_NAV_PVT_PRESENT)
    print("UBX-NAV-ATT present:", UBX_NAV_ATT_PRESENT)
    print("UBX-ESF-INS present:", UBX_ESF_INS_PRESENT)
    print("UBX-ESF-RAW present:", UBX_ESF_RAW_PRESENT)

def csv_conversion(filename, csv_filename, csv_interpolation, start_time, end_time, agent_id=1, agent_type="car"):
    """
    CSV function to store in a csv file the kinematic of the agent over the capture
    """
    decoder = DecodedMessage()
    f = open(filename, "r")
    data = json.load(f)
    f.close()

    df = pd.DataFrame(columns=["agent_id", "agent_type", "timeStamp_posix", "latitude_deg", "longitude_deg", "speed_ms", "heading_deg", "accel_ms2"])

    if start_time:
        data = filter_by_start_time(data, start_time)

    last_update_pos = None
    i = 0
    lat = None
    lon = None
    heading = None
    speed = None
    last_speed = None
    last_speed_time = None
    acc = None
    last_heading = None

    for d in data:
        last_time = d["timestamp"]
        message_type = d["type"]
        if message_type == "Unknown":
            continue
        content = d["data"]
        tmp_lat, tmp_lon, tmp_heading, tmp_speed = None, None, None, None
        if message_type == "UBX":
            content = bytes.fromhex(content)
        tmp_lat, tmp_lon, tmp_heading, tmp_speed = decoder.extract_data(content, message_type)
        if tmp_lat:
            lat = tmp_lat
        if tmp_lon:
            lon = tmp_lon
        if tmp_heading:
            heading = tmp_heading
        if tmp_speed:
            speed = tmp_speed
            acc = (speed - last_speed) / ((d["timestamp"] - last_speed_time) / 1e6) if last_speed else 0
            last_speed = speed
            last_speed_time = d["timestamp"]

        if not lat and not lon and not heading and not speed:
            continue

        if csv_interpolation and speed and last_update_pos:
            if speed > SPEED_THRESHOLD and (d["timestamp"] - last_update_pos) / 1e3 > AGE_THRESHOLD:
                pos_age = d["timestamp"] - last_update_pos
                pos_age /= 1e3
                interp_points = np.floor(pos_age / AGE_THRESHOLD)
                heading_diff = heading - last_heading if last_heading else 0
                for j in range(0, int(interp_points)):
                    t = last_update_pos + (j+1) * (AGE_THRESHOLD * 1e3)
                    delta_t = (t - last_update_pos) / 1e6
                    new_heading = last_heading + j * (heading_diff / interp_points)
                    delta_x = speed * delta_t * math.sin(new_heading)
                    delta_y = speed * delta_t * math.cos(new_heading)
                    new_lat = lat + (delta_y / METERS_PER_DEGREE_LATITUDE)
                    new_lon = lon + (delta_x / (METERS_PER_DEGREE_LATITUDE * math.cos(math.radians(lat))))
                    interp_lat = new_lat
                    if not tmp_lat:
                        lat = interp_lat 
                    interp_lon = new_lon
                    if not tmp_lon:
                        lon = interp_lon
                    interp_heading = new_heading
                    if not tmp_heading:
                        heading = interp_heading
                    last_heading = new_heading
                    df.loc[len(df)] = [agent_id, agent_type, t, interp_lat, interp_lon, speed, interp_heading, acc]
                    last_update_pos = t
                    i += 1

        last_speed = speed if speed else last_speed
        last_heading = heading if heading else last_heading
        if tmp_lat and tmp_lon:
            last_update_pos = d["timestamp"]
        if lat and lon and heading and speed:
            df.loc[len(df)] = [agent_id, agent_type, d["timestamp"], lat, lon, speed, heading, acc]
            i += 1

        if end_time and time.time() * 1e6 - start_time > end_time:
            break

    try:
        print("Saving data to file", csv_filename)
        df.to_csv(csv_filename, index=False)
        print("Data saved successfully")
    except Exception as e:
        print(f"Error: {e}")


def test_rate(filename, start_time, end_time):
    """
    Test rate function that calculates the update rate of the GNSS messages.
    """
    global UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT

    decoder = DecodedMessage()
    f = open(filename, "r")
    data = json.load(f)
    f.close()

    if start_time:
        data = filter_by_start_time(data, start_time)

    previous_time = 0 if not start_time else start_time

    previous_pos_time = previous_time
    delta_pos_time = 0
    average_update_time = 0
    cnt_update_time = 0
    average_update_time_filtered = 0
    cnt_update_time_filtered = 0
    update_timestamps = ["Timestamp_ms"]
    update_periodicities = ["Periodicity_ms"]
    update_rates = ["Rate_Hz"]
    update_msg_type = ["Message_type"]
    update_msg_clustered = ["Clustered"]
    update_msg_same_position = ["Same_pos_as_previous"]
    update_msg_same_speed = ["Same_speed_as_previous"]
    update_msg_lat = ["Latitude"]
    update_msg_lon = ["Longitude"]
    update_msg_heading = ["Heading"]
    update_msg_speed = ["Speed"]

    prev_latitude_deg = -8000
    prev_longitude_deg = -8000
    prev_speed = -8000
    
    startup_time = time.time() * 1e6
    for d in data:
        delta_time = d["timestamp"] - previous_time
        message_type = d["type"]
        if message_type == "Unknown":
            continue
        content = d["data"]
        tmp_lat, tmp_lon, tmp_heading, tmp_speed = None, None, None, None
        if message_type == "UBX":
            content = bytes.fromhex(content)
            ubx_type = decoder.get_ubx_message_type(content)
            set_ubx_flag(ubx_type)
        tmp_lat, tmp_lon, tmp_heading, tmp_speed = decoder.extract_data(content, message_type)
        test_rate_lat = None
        test_rate_lon = None
        test_rate_heading = None
        test_rate_speed = None
        if tmp_lat:
            test_rate_lat = tmp_lat
        if tmp_lon:
            test_rate_lon = tmp_lon
        if tmp_heading:
            test_rate_heading = tmp_heading
        if tmp_speed:
            test_rate_speed = tmp_speed
    
        if not test_rate_lat and not test_rate_lon and not test_rate_heading and not test_rate_speed:
            continue

        delta_pos_time = d["timestamp"] - previous_pos_time

        if message_type == "UBX":
            print("Time since last update (UBX):", delta_pos_time/1e3, "Time:", d["timestamp"]/1e3)
        else:
            print("Time since last update (NMEA):", delta_pos_time/1e3, "Time:", d["timestamp"]/1e3)
        
        if test_rate_lat or test_rate_lon:
            print("Latitude [deg]:", test_rate_lat, "Longitude [deg]:", test_rate_lon)

        previous_pos_time = d["timestamp"]

        cnt_update_time = cnt_update_time + 1
        average_update_time = average_update_time + (delta_pos_time/1e3-average_update_time) / cnt_update_time
        
        # Check if the position update is clustered or not (based on the time and position)
        if test_rate_lat and test_rate_lon:
            if delta_pos_time/1e3 > CLUSTER_TSHOLD_MS or not compare_floats(prev_latitude_deg, test_rate_lat) or not compare_floats(prev_longitude_deg, test_rate_lon):
                cnt_update_time_filtered = cnt_update_time_filtered + 1
                average_update_time_filtered = average_update_time_filtered + (delta_pos_time/1e3-average_update_time_filtered) / cnt_update_time_filtered
                update_msg_clustered.append(0)
            else:
                update_msg_clustered.append(1)

            if compare_floats(prev_latitude_deg, test_rate_lat) and compare_floats(prev_longitude_deg, test_rate_lon):
                update_msg_same_position.append(1)
            else:
                update_msg_same_position.append(0)

            prev_latitude_deg = test_rate_lat
            prev_longitude_deg = test_rate_lon
        else:
            update_msg_clustered.append(-1000)
            update_msg_same_position.append(-1000)
        
        if test_rate_speed:
            if compare_floats(prev_speed, test_rate_speed):
                update_msg_same_speed.append(1)
            else:
                update_msg_same_speed.append(0)
            prev_speed = test_rate_speed

        update_timestamps.append(d["timestamp"]/1e3)

        assert delta_pos_time > 0, "Error: negative time between two messages"
        update_periodicities.append(delta_pos_time/1e3)
        update_rates.append(1e6/(delta_pos_time))

        if message_type == "UBX":
            update_msg_type.append("UBX-NAV-PVT")
        else:
            update_msg_type.append("NMEA-Gx" + content[3:6])

        if test_rate_lat and test_rate_lon:
            update_msg_lat.append(test_rate_lat)
        else:
            update_msg_lon.append(-1000)

        if test_rate_lon:
            update_msg_lon.append(test_rate_lon)
        else:
            update_msg_lat.append(-1000)

        if test_rate_heading:
            update_msg_heading.append(test_rate_heading)
        else:
            update_msg_heading.append(-1000)

        if test_rate_speed:
            update_msg_speed.append(test_rate_speed)
        else:
            update_msg_speed.append(-1000)
    
        previous_time = d["timestamp"]
        if end_time and time.time() * 1e6 - startup_time > end_time:
            break

    try:
        print_test_rate_stats(average_update_time, average_update_time_filtered)
        print("Saving data to file statistics_out.csv")
        np.savetxt(
            'statistics_out.csv', 
            [p for p in zip(update_timestamps, update_msg_type, update_periodicities, update_rates, update_msg_clustered, update_msg_same_position, update_msg_same_speed, update_msg_lat, update_msg_lon, update_msg_heading, update_msg_speed)],
            delimiter=',', fmt='%s'
        )
        print("Data saved successfully")           
    except Exception as e:
        print(f"Error: {e}")

def CAN_gui(CAN_filename, CAN_db, start_time, end_time, server_ip, server_port, fifo_path, visualizer):
    """
    GUI function to display the data on the map.
    """
    f = open(CAN_filename, "r")
    data = json.load(f)
    f.close()
    # Filter the data by the start time
    if start_time:
        data = filter_by_start_time(data, start_time)
    # Load the CAN database
    db = cantools.database.load_file(CAN_db)
    previous_time = 0 if not start_time else start_time
    variable_delta_us_factor = 0
    startup_time = time.time() * 1e6
    for d in data:
        delta_time = d["timestamp"] - previous_time
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
            if content and visualizer.getEgoPosition() is not None and angle_left_signal and angle_right_signal and distance_signal:
                if content[distance_signal.name] != 0.0:
                    ego_lat, ego_lon, ego_heading = visualizer.getEgoPosition()
                    distance = content[distance_signal.name]
                    angle_left = content[angle_left_signal.name]
                    angle_right = content[angle_right_signal.name]
                    # Calculate the position of the object
                    dx_v = distance - BUMPER_TO_SENSOR_DISTANCE + STANDARD_OBJECT_LENGTH / 2
                    dist_left = dx_v / math.cos(angle_left)
                    dist_right = dx_v / math.cos(angle_right)
                    dy_left = dist_left * math.sin(angle_left)
                    dy_right = dist_right * math.sin(angle_right)
                    width = dy_right - dy_left
                    dy_v = dy_left + width / 2
                    # ETSI TS 103 324 V2.1.1 (2023-06) demands xDistance and yDistance to be with East as positive x and North as positive y
                    ego_heading_cart = math.radians(90-ego_heading)  # The heading from the gps is relative to North --> 90 degrees from East
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
                    manage_map(GNSS_flag=False, CAN_flag=True, fifo_path=fifo_path, latitude=lat1, longitude=lon1, heading=None, server_ip=server_ip, server_port=server_port, visualizer=visualizer, station_id=arbitration_id, type=5)
                pass
        start_time_us = start_time if start_time else 0
        # Calculate the delta time in the recording between the current message and the start time
        delta_time_us_simulation = d["timestamp"] - start_time_us
        # Calculate the real time in microseconds from the beginning of the simulation to the current time
        delta_time_us_real = time.time() * 1e6 - startup_time
        # Update the variable_delta_time_us_factor to adjust the time of the CAN write to be as close as possible to a real time simulation
        variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
        try:
            # Wait for the real time to be as close as possible to the simulation time
            time.sleep(variable_delta_us_factor / 1e6)
        except:
            # print("Trying to sleep for a negative time, thus not sleeping: ", variable_delta_us_factor / 1e3)
            pass
        if end_time and time.time() * 1e6 - startup_time > end_time:
            break

def serial_gui(filename, start_time, end_time, server_ip, server_port, fifo_path, visualizer, CAN_filename=None, CAN_db=None):
    """
    GUI function to display the data on the map.
    """

    try:
        decoder = DecodedMessage()
        f = open(filename, "r")
        data = json.load(f)
        f.close()

        if start_time:
            data = filter_by_start_time(data, start_time)

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
            can_thread = threading.Thread(target=CAN_gui, args=(CAN_filename, CAN_db, start_time, end_time, server_ip, server_port, fifo_path, visualizer))
            can_thread.daemon = True
            can_thread.start()

        for d in data:
            delta_time = d["timestamp"] - previous_time
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
            delta_time_us_real = time.time() * 1e6 - startup_time
            start_time_us = start_time if start_time else 0
            delta_time_us_simulation = d["timestamp"] - start_time_us
            variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
            try:
                time.sleep(variable_delta_us_factor / 1e6)
            except:
                print("Trying to sleep for a negative time, thus not sleeping: ", variable_delta_us_factor / 1e3)
            if first_send is None:
                first_send = time.time()
            previous_time = d["timestamp"]
            if latitude and longitude:
                manage_map(GNSS_flag=True, CAN_flag=False, fifo_path=fifo_path, latitude=latitude, longitude=longitude, heading=heading, server_ip=server_ip, server_port=server_port, visualizer=visualizer)
            if end_time and time.time() * 1e6 - startup_time > end_time:
                break
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        if visualizer:
            visualizer.stop_server(server_ip, server_port)
        if can_thread:
            can_thread.join()

def write_serial(server_device, client_device, baudrate, filename, start_time, end_time):
    """
    Writes the data from the file to the serial device.
    """
    try:
        # Creation of the serial emulator
        ser = SerialEmulator(device_port=server_device, client_port=client_device, baudrate=baudrate)
        f = open(filename, "r")
        data = json.load(f)
        f.close()

        if start_time:
            data = filter_by_start_time(data, start_time)

        previous_time = 0 if not start_time else start_time
       
        variable_delta_us_factor = 0

        first_send = None
        startup_time = time.time() * 1e6
        for d in data:
            delta_time = d["timestamp"] - previous_time
            message_type = d["type"]
            if message_type == "Unknown":
                continue
            content = d["data"]
            if message_type == "UBX":
                content = bytes.fromhex(content)
            else:
                # For the NMEA messages we need to encode the content for the serial emulator and decode it for the GUI (to obtain a string)
                content = content.encode()
            # Calculate a variable delta time factor to adjust the time of the serial write to be as close as possible to a real time simulation
            # delta_time_us represents the real time in microseconds from the beginning of the simulation to the current time
            delta_time_us_real = time.time() * 1e6 - startup_time
            # start_time_us represents the time in microseconds from the beginning of the messages simulation to the start time selected by the user
            start_time_us = start_time if start_time else 0
            # delta_time_us_simulation represents the time in microseconds from the beginning of the messages simulation time to the current message time
            delta_time_us_simulation = d["timestamp"] - start_time_us
            # We want that the time of the serial write is as close as possible to the real time simulation
            # variable_delta_us_factor represents the difference between the simulation time and the real time
            # It should be as close as possible to 0 and it is used to adjust the waiting time for the serial write
            variable_delta_us_factor = delta_time_us_simulation - delta_time_us_real
            try:
                # Wait for the real time to be as close as possible to the simulation time
                # print("Sleeping for:", variable_delta_us_factor / 1e6)
                time.sleep(variable_delta_us_factor / 1e6)
            except:
                print("Trying to sleep for a negative time, thus not sleeping: ", variable_delta_us_factor / 1e3)
            ser.write(content)
            if first_send is None:
                first_send = time.time()
            previous_time = d["timestamp"]
            if end_time and time.time() * 1e6 - startup_time > end_time:
                break

    except Exception as e:
        print(f"Error: {e}")

    finally:
        ser.stop()
        print("Time to send all messages:", time.time() - first_send, "s")
        if start_time:
            print("Difference to the last message:", time.time() - first_send - (d["timestamp"] - start_time) / 1e6, "s")
        else:
            print("Difference to the last message:", time.time() - first_send - d["timestamp"] / 1e6, "s")


def write_CAN(device, filename, db_file, start_time, end_time):
    """
    Writes the data from the file to the CAN device.
    """
    try:
        first_send = None
        f = open(filename, "r")
        data = json.load(f)
        f.close()
        # Filter the data by the start time
        if start_time:
            data = filter_by_start_time(data, start_time)
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
            try:
                # Wait for the real time to be as close as possible to the simulation time
                time.sleep(variable_delta_us_factor / 1e6)
            except:
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
    args.add_argument("--enable-gui", action="store_true", help="Whether to display the GUI. Default is False", default=False)
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
    gui = args.enable_gui
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

    assert serial > 0 or gui > 0 or test_rate_enabled > 0 or CAN > 0 or csv > 0, "At least one of the serial or GUI or test rate or CAN or csv options must be activated"

    visualizer = None
    fifo_path = None
    serial_thread = None
    can_thread = None
    test_rate_thread = None
    csv_thread = None
    gui_thread = None

    agent_type = "car"

    if serial:
        assert os.path.exists(serial_filename), "The file does not exist"
        serial_thread = threading.Thread(
            target=write_serial, args=(server_device, client_device, baudrate, serial_filename, start_time, end_time)
        )
        serial_thread.daemon = True
        serial_thread.start()

    if gui:
        assert os.path.exists(serial_filename), "The file does not exist"
        CAN_gui = False
        if os.path.exists(CAN_filename) and os.path.exists(CAN_db):
            CAN_gui = True
        else:
            print("CAN GUI not activated")
        # Creation of the visualizer object
        visualizer = Visualizer()
        # If GUI modality is activated, start the nodejs server
        fifo_path = "./replay/fifo"
        if not os.path.exists(fifo_path):
            os.mkfifo(fifo_path)
        visualizer.start_nodejs_server(httpport, server_ip, server_port, fifo_path)
        if CAN_gui:
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
        csv_thread = threading.Thread(
            target=csv_conversion, args=(serial_filename, csv_filename, csv_interpolation, start_time, end_time, 1, agent_type)
        )
        csv_thread.daemon = True
        csv_thread.start()

    if serial:
        serial_thread.join()

    if gui:
        gui_thread.join()

    if CAN:
        can_thread.join()
    
    if test_rate_enabled:
        test_rate_thread.join()
    
    if csv:
        csv_thread.join()
    

if __name__ == "__main__":
    main()
