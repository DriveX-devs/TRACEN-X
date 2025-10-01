import utils
import time
import json
from typing import Any
from decoded_messages import DecodedMessage

UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT, UBX_NAV_STATUS_PRESENT = False, False, False, False, False


def set_ubx_flag(ubx_type: str):
    global UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT, UBX_NAV_STATUS_PRESENT
    if ubx_type is not None:
        if ubx_type == "NAV-PVT":
            UBX_NAV_PVT_PRESENT = True
        if ubx_type == "NAV-ATT":
            UBX_NAV_ATT_PRESENT = True
        if ubx_type == "ESF-INS":
            UBX_ESF_INS_PRESENT = True
        if ubx_type == "ESF-RAW":
            UBX_ESF_RAW_PRESENT = True
        if ubx_type == "NAV-STATUS":
            UBX_NAV_STATUS_PRESENT = True


def print_test_rate_stats(average_update_time: float, average_update_time_filtered: float):
    global UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT
    print("Average update periodicity:", average_update_time, "ms")

    print("Average update rate (filtered):", 1e3 / average_update_time_filtered, "Hz")
    print("Average update periodicity (filtered):", average_update_time_filtered, "ms")

    print("UBX messages statistics:")
    print("UBX-NAV-PVT present:", UBX_NAV_PVT_PRESENT)
    print("UBX-NAV-ATT present:", UBX_NAV_ATT_PRESENT)
    print("UBX-ESF-INS present:", UBX_ESF_INS_PRESENT)
    print("UBX-ESF-RAW present:", UBX_ESF_RAW_PRESENT)
    print("UBX-NAV-STATUS present:", UBX_NAV_STATUS_PRESENT)


def test_rate(barrier: Any, stop_event: Any, filename: str, start_time: int, end_time: int):
    """
    Test rate function that calculates the update rate of the GNSS messages.

    Parameters:
    - stop_event (multiprocessing.Event): The Event object to stop the processes.
    - filename (str): Path to the file containing GNSS log data (e.g., JSON format with timestamps).
    - start_time (int): Start time in microseconds; messages with timestamps before this will be ignored.
    - end_time (int): End time in microseconds; messages with timestamps after this will be ignored.
    """
    global UBX_NAV_PVT_PRESENT, UBX_NAV_ATT_PRESENT, UBX_ESF_INS_PRESENT, UBX_ESF_RAW_PRESENT

    decoder = DecodedMessage()
    f = open(filename, "r")
    data = json.load(f)
    f.close()

    if start_time:
        data = utils.filter_by_start_time(data, start_time)

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

    if barrier:
        barrier.wait()

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
            print("Time since last update (UBX):", delta_pos_time / 1e3, "Time:", d["timestamp"] / 1e3)
        else:
            print("Time since last update (NMEA):", delta_pos_time / 1e3, "Time:", d["timestamp"] / 1e3)

        if test_rate_lat or test_rate_lon:
            print("Latitude [deg]:", test_rate_lat, "Longitude [deg]:", test_rate_lon)

        previous_pos_time = d["timestamp"]

        cnt_update_time = cnt_update_time + 1
        average_update_time = average_update_time + (delta_pos_time / 1e3 - average_update_time) / cnt_update_time

        # Check if the position update is clustered or not (based on the time and position)
        if test_rate_lat and test_rate_lon:
            if (delta_pos_time / 1e3 > utils.CLUSTER_TSHOLD_MS or not
            utils.compare_floats(prev_latitude_deg, test_rate_lat) or not
            utils.compare_floats(prev_longitude_deg, test_rate_lon)):
                cnt_update_time_filtered = cnt_update_time_filtered + 1
                average_update_time_filtered = average_update_time_filtered + (
                        delta_pos_time / 1e3 - average_update_time_filtered) / cnt_update_time_filtered
                update_msg_clustered.append(0)
            else:
                update_msg_clustered.append(1)

            if utils.compare_floats(prev_latitude_deg, test_rate_lat) and utils.compare_floats(prev_longitude_deg,
                                                                                               test_rate_lon):
                update_msg_same_position.append(1)
            else:
                update_msg_same_position.append(0)

            prev_latitude_deg = test_rate_lat
            prev_longitude_deg = test_rate_lon
        else:
            update_msg_clustered.append(-1000)
            update_msg_same_position.append(-1000)

        if test_rate_speed:
            if utils.compare_floats(prev_speed, test_rate_speed):
                update_msg_same_speed.append(1)
            else:
                update_msg_same_speed.append(0)
            prev_speed = test_rate_speed
        else:
            update_msg_same_speed.append(0)

        update_timestamps.append(d["timestamp"] / 1e3)

        assert delta_pos_time > 0, "Error: negative time between two messages"
        update_periodicities.append(delta_pos_time / 1e3)
        update_rates.append(1e6 / (delta_pos_time))

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
        if (end_time and time.time() * 1e6 - startup_time > end_time) or stop_event.is_set():
            break
    try:
        print_test_rate_stats(average_update_time, average_update_time_filtered)
        print("Saving data to file statistics_out.csv")
        with open('statistics_out.csv', 'w') as f:
            # Write each row by joining values with commas
            for row in zip(update_timestamps, update_msg_type, update_periodicities, update_rates,
                           update_msg_clustered, update_msg_same_position, update_msg_same_speed,
                           update_msg_lat, update_msg_lon, update_msg_heading, update_msg_speed):
                # Convert all values to strings and join with commas
                line = ','.join(str(value) for value in row)
                f.write(line + '\n')
        print("Data saved successfully")
    except Exception as e:
        print(f"Error: {e}")
