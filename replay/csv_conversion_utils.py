import utils
import json
import math
import time
from decoded_messages import DecodedMessage
from typing import Any

def csv_conversion(stop_event: Any, input_filename: str, csv_filename: str, csv_interpolation: bool, start_time: int, end_time: int, agent_id: int = 1, agent_type: str = "car"):
    """
    CSV function to store in a csv file the kinematic of the agent over the capture.

    Parameters:
    - stop_event (multiprocessing.Event): The Event object to stop the processes.
    - input_filename (str): Path to the input log file (e.g., GNSS or sensor data in JSON).
    - csv_filename (str): Path to the output CSV file to store the converted data.
    - csv_interpolation (bool): Whether to interpolate missing or irregular timestamp entries in the dataset.
    - start_time (int): Start time in microseconds for filtering the data to be written.
    - end_time (int): End time in microseconds for filtering the data to be written.
    - agent_id (int, optional): Numerical identifier for the agent being tracked. Default is 1.
    - agent_type (str, optional): Type of agent (e.g., "car", "vru"). Default is "car".
    """
    decoder = DecodedMessage()
    f = open(input_filename, "r")
    data = json.load(f)
    f.close()

    # df = pd.DataFrame(columns=["agent_id", "agent_type", "timeStamp_posix", "latitude_deg", "longitude_deg", "speed_ms", "heading_deg", "accel_ms2"])
    df = {
        "agent_id": [],
        "agent_type": [],
        "timeStamp_posix": [],
        "latitude_deg": [],
        "longitude_deg": [],
        "speed_ms": [],
        "heading_deg": [],
        "accel_ms2": []
    }

    if start_time:
        data = utils.filter_by_start_time(data, start_time)

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
            if speed > utils.SPEED_THRESHOLD and (d["timestamp"] - last_update_pos) / 1e3 > utils.AGE_THRESHOLD:
                pos_age = d["timestamp"] - last_update_pos
                pos_age /= 1e3
                interp_points = math.floor(pos_age / utils.AGE_THRESHOLD)
                heading_diff = heading - last_heading if last_heading else 0
                for j in range(0, int(interp_points)):
                    t = last_update_pos + (j+1) * (utils.AGE_THRESHOLD * 1e3)
                    delta_t = (t - last_update_pos) / 1e6
                    new_heading = last_heading + j * (heading_diff / interp_points)
                    delta_x = speed * delta_t * math.sin(new_heading)
                    delta_y = speed * delta_t * math.cos(new_heading)
                    new_lat = lat + (delta_y / utils.METERS_PER_DEGREE_LATITUDE)
                    new_lon = lon + (delta_x / (utils.METERS_PER_DEGREE_LATITUDE * math.cos(math.radians(lat))))
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
                    # df.loc[len(df)] = [agent_id, agent_type, t, interp_lat, interp_lon, speed, interp_heading, acc]
                    df["agent_id"].append(agent_id)
                    df["agent_type"].append(agent_type)
                    df["timeStamp_posix"].append(t)
                    df["latitude_deg"].append(interp_lat)
                    df["longitude_deg"].append(interp_lon)
                    df["speed_ms"].append(speed)
                    df["heading_deg"].append(interp_heading)
                    df["accel_ms2"].append(acc)
                    last_update_pos = t
                    i += 1

        last_speed = speed if speed else last_speed
        last_heading = heading if heading else last_heading
        if tmp_lat and tmp_lon:
            last_update_pos = d["timestamp"]
        if lat and lon and heading and speed:
            # df.loc[len(df)] = [agent_id, agent_type, d["timestamp"], lat, lon, speed, heading, acc]
            df["agent_id"].append(agent_id)
            df["agent_type"].append(agent_type)
            df["timeStamp_posix"].append(d["timestamp"])
            df["latitude_deg"].append(lat)
            df["longitude_deg"].append(lon)
            df["speed_ms"].append(speed)
            df["heading_deg"].append(heading)
            df["accel_ms2"].append(acc)
            i += 1

        if (end_time and time.time() * 1e6 - start_time > end_time) or stop_event.is_set():
            break

    try:
        print("Saving data to file", csv_filename)
        # df.to_csv(csv_filename, index=False)
        with open(csv_filename, 'w') as f:
            # Write the header
            f.write("agent_id,agent_type,timeStamp_posix,latitude_deg,longitude_deg,speed_ms,heading_deg,accel_ms2\n")
            # Write each row by joining values with commas
            for row in zip(df["agent_id"], df["agent_type"], df["timeStamp_posix"], df["latitude_deg"], df["longitude_deg"], df["speed_ms"], df["heading_deg"], df["accel_ms2"]):
                # Convert all values to strings and join with commas
                line = ','.join(str(value) for value in row)
                f.write(line + '\n')
        print("Data saved successfully")

    except Exception as e:
        print(f"Error: {e}")
