import socket
import time
from typing import Any
import asn1tools as asn
from scapy.all import *
from copy import  deepcopy
from proton import Message
from proton.reactor import Container
from proton.handlers import MessagingHandler

# Normal packet (without security layer) constants
GEONET_LENGTH = 40
ETHER_LENGTH = 14
GEONET_TS_LOW = 20
GEONET_TS_HIGH = 24
BTP_LOW = 40
BTP_HIGH = 44
BTP_PORT_HIGH = 2

# Security packet constants
ETH_SRC_ADDR = 6
SECURITY_PAD = 7
BTP_PAD = 4
SOURCE_ADDR_PAD = 6
TIMESTAMP_PAD = 4
PAYLOAD_PAD = 6
BTPS = {
    b"\x07\xd2\x00\x00": "DENM",
    b"\x07\xd1\x00\x00": "CAM",
    b"\x07\xd9\x00\x00": "CPM",
    b"\x07\xe2\x00\x00": "VAM",
}
LENGTH_CAM_WITH_CERTIFICATE = 300
LENGTH_DENM_WITH_CERTIFICATE = 600
SECURITY_TAIL_WO_CERTIFICATE = 86
SECURITY_TAIL = SECURITY_TAIL_WO_CERTIFICATE + 151  # 151 bytes for the certificate
# TODO DENM have a headerInfo of 21 bytes instead of 11
SECURITY_TAIL_DENM = SECURITY_TAIL + 10  # 10 bytes for the headerInfo

# General facility constants
TIME_SHIFT = 1072915200000
TS_MAX1 = 4294967296
MODULO_WRAP = 4398046511103
MODULO_CAM_VAM_DENM = 65536
PURPOSES = ["GeoNet", "CPM", "CAM", "VAM", "DENM"]

# Load the ASN1 files before starting the process
cpm_asn = "./data/asn/CPM-all.asn"
vam_asn = "./data/asn/VAM-PDU-FullDescription.asn"
cam_asn = "./data/asn/CAM-all-old.asn"
denm_asn = "./data/asn/DENM-all-old.asn"
CPM = asn.compile_files(cpm_asn, "uper")
VAM = asn.compile_files(vam_asn, "uper")
CAM = asn.compile_files(cam_asn, "uper")
DENM = asn.compile_files(denm_asn, "uper")

class AMQPSender(MessagingHandler):
    def __init__(self, server, port, topic):
        super().__init__()
        self.server = server
        self.port = port
        self.topic = topic
        self.sender = None
        self.container = Container(self)

    def on_start(self, event) -> None:
        try:
            conn = event.container.connect(f"{self.server}:{self.port}")
            self.sender = event.container.create_sender(conn, self.topic)
        except Exception as e:
            print(f"Error: {e}")
            exit(-1)

    def send_message(self, raw_bytes: bytes, message_id: str, properties: dict = None) -> bool:
        success = True
        try:
            if self.sender:
                msg = Message(
                    id=message_id,
                    body=raw_bytes,
                    properties=properties or {},
                    content_type="application/octet-stream"
                )
                self.sender.send(msg)
        except Exception as e:
            print(f"Sending error: {e}")
            success = False
        finally:
            return success

    def run(self) -> None:
        self.container.run()

    def stop(self) -> None:
        self.container.stop()


def compute_properties():
    # TODO
    return {}


def get_timestamp_ms(purpose: str) -> int:

    assert purpose in PURPOSES, f"Verify that the purpose for timestamp computation is in {PURPOSES}"

    if purpose == "CPM" or purpose == "GeoNet":
        try:
            now = time.clock_gettime_ns(time.CLOCK_TAI)
        except AttributeError:
            print("CLOCK_TAI not supported on this platform.")
            exit(-1)
        except OSError as e:
            print("Cannot get the current microseconds TAI timestamp:", e)
            exit(-1)
        except Exception as e:
            print(f"Error: {e}")
            exit(-1)
        
        # Convert to seconds + microseconds
        seconds = now // 1e9
        microseconds = round((now % 1e9) / 1e3)
        
        # Adjust for overflow due to rounding
        if microseconds > 999_999:
            seconds += 1
            microseconds = 0

        # Compute total milliseconds
        millis = math.floor((seconds * 1e6 + microseconds) / 1e3)

        # Apply ITS epoch and ETSI wraparound
        return int((millis - TIME_SHIFT) % MODULO_WRAP) if purpose == "CPM" else int((millis - TIME_SHIFT) % TS_MAX1)
    elif purpose == "VAM" or purpose == "CAM" or purpose == "DENM":
        try:
            now = int(time.time() * 1e3)
        except Exception as e:
            print(f"Error: {e}")
            exit(-1)
        return (now - TIME_SHIFT) % MODULO_CAM_VAM_DENM
    
    return -1


def write_pcap(stop_event: Any, input_filename: str, interface: str, start_time: int, end_time: int, update_datetime: bool, new_pcap: str, enable_amqp: bool, amqp_server_ip: str, amqp_server_port: int, amqp_topic: str):
    """
    Sends packets from a pcap file to a network interface within a given time window.

    Parameters:
    - stop_event (multiprocessing.Event): The Event object to stop the processes.
    - input_filename (str): Path to the pcap file.
    - interface (str): Network interface to send packets through.
    - start_time (int): Start time in microseconds.
    - end_time (int): End time in microseconds.
    - new_pcap (str): New pcap file to write the reproduced packets
    - enable_amqp (bool): Whether AMQP messaging is enabled
    - amqp_server_ip (str): IP address of the AMQP server
    - amqp_server_port (str): Port of the AMQP server
    - amqp_topic (str): Topic to publish messages to on the AMQP server
    """

    if enable_amqp:
        amqp_sender = AMQPSender(amqp_server_ip, amqp_server_port, amqp_topic)
        amqp_thread = threading.Thread(target=amqp_sender.run, daemon=True)
        amqp_thread.start()

    pcap = rdpcap(input_filename)
    assert pcap, "Pcap file is empty"

    # start_time_us represents the time in microseconds from the beginning of the messages simulation to the start time selected by the user
    start_time_us = start_time if start_time else 0

    # Socket preparation
    sock = None
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
    except Exception as e:
        print(f"Error: {e}")

    base_ts = pcap[0].time  # epoch time in seconds
    startup_time = time.time() * 1e6
    try:
        for i, pkt in enumerate(pcap):
            pkt_ts_us = int(1e6 * (pkt.time - base_ts))

            if stop_event and stop_event.is_set():
                break

            if start_time is not None and pkt_ts_us < start_time:
                continue

            if end_time is not None and pkt_ts_us > end_time:
                break

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

            new_pkt = None
            if update_datetime:
                raw_part = None
                try:
                    # Extract the Ethernet II part
                    ether_part = raw(pkt)[:ETHER_LENGTH]
                    # Take the rest ot the packet
                    data = raw(pkt)[ETHER_LENGTH:]
                    # Check if the security layer is active
                    security = False if data[:1] == b'\x11' else True
                    # Set the fields for pkt reconstruction to None to check if they will be filled properly
                    found = False
                    facilities = None
                    port = None
                    btp = None
                    new_geonet = None
                    tail_security = None
                    if not security:
                        # Packet without the security layer
                        # Extract the GeoNet and calculate the new timestamp
                        geonet = data[:GEONET_LENGTH]
                        current_timestamp = get_timestamp_ms(purpose="GeoNet")
                        assert current_timestamp > 0, "Error in time calculation"
                        current_timestamp = current_timestamp.to_bytes(4, byteorder="big", signed=False)
                        # Build the new geonet with the updated timestamp
                        new_geonet = geonet[:GEONET_TS_LOW] + current_timestamp + geonet[GEONET_TS_HIGH:]
                        # Isolate BTP to retrieve the port number
                        btp = data[BTP_LOW : BTP_HIGH]
                        port = int.from_bytes(btp[:BTP_PORT_HIGH], byteorder="big")
                        # Take the rest of the packet (Facilities layer)
                        facilities = data[BTP_HIGH:]
                    else:
                        # Isolate ethe security tail and the rest of the packet
                        if LENGTH_CAM_WITH_CERTIFICATE <= len(pkt) <= LENGTH_DENM_WITH_CERTIFICATE:
                            tail_security = data[-SECURITY_TAIL:]
                            data = data[:-SECURITY_TAIL]
                        elif len(pkt) > LENGTH_DENM_WITH_CERTIFICATE:
                            tail_security = data[-SECURITY_TAIL_DENM:]
                            data = data[:-SECURITY_TAIL_DENM]
                        else:
                            tail_security = data[-SECURITY_TAIL_WO_CERTIFICATE:]
                            data = data[:-SECURITY_TAIL_WO_CERTIFICATE]
                        # Take the source MAC address from the Ethernet II
                        source_addr = ether_part[ETH_SRC_ADDR:-2]
                        timestamp_idx = 0
                        payload_length = None
                        found = False  # Put "found" to False
                        while True:
                            # Search through the packet to find a match for the repetition of the source MAC address (repeated in the GeoNet)
                            if timestamp_idx + SOURCE_ADDR_PAD > len(data):
                                break
                            # Take 6 bytes slice
                            it = data[timestamp_idx:timestamp_idx+SOURCE_ADDR_PAD]
                            if it == source_addr:
                                found = True
                                payload_idx = deepcopy(timestamp_idx)
                                # We know that the Payload Length is exactly 6 bytes behind the Source MAC Address position
                                payload_idx -= PAYLOAD_PAD
                                # Read Payload Length (used after)
                                payload_length = int.from_bytes(data[payload_idx: payload_idx+2], byteorder="big")
                                # Update the Timestamp index after the Source MAC Address so that it is possible to insert the new timestamp
                                timestamp_idx += SOURCE_ADDR_PAD
                                break
                            else:
                                timestamp_idx += 1

                        if found:
                            # Use the starting point of the BTP to retrieve the GeoNet, then update the timestamp
                            btp_payload = data[-payload_length:]
                            btp = btp_payload[:BTP_PAD]
                            facilities = btp_payload[BTP_PAD:]
                            geonet = data[:payload_length]
                            current_timestamp = get_timestamp_ms(purpose="GeoNet")
                            assert current_timestamp > 0, "Error in time calculation"
                            current_timestamp = current_timestamp.to_bytes(4, byteorder="big", signed=False)
                            # If all the searches went well we can create the New GeoNet
                            new_geonet = geonet[:timestamp_idx] + current_timestamp + geonet[timestamp_idx+len(current_timestamp):]
                            # Extract the BTP to know the port
                            port = int.from_bytes(btp[:2], byteorder="big")

                    if not new_geonet or not btp or not facilities or not port:
                        # From both cases (with and without security layer), we need some basic information
                        # Otherwise, the packet is treated as not known and will be normally sent
                        new_pkt = raw(pkt)
                    else:
                        mex_encoded = None
                        if port == 2009:
                            # CPM, modify the Reference Time
                            cpm = CPM.decode("CollectivePerceptionMessage", facilities)
                            old_reference_time = cpm["payload"]["managementContainer"]["referenceTime"]
                            new_reference_time = get_timestamp_ms(purpose="CPM")
                            assert new_reference_time > 0, "Error in time calculation"
                            cpm["payload"]["managementContainer"]["referenceTime"] = new_reference_time

                            # TODO to test
                            if "InterferenceManagementZones" in cpm["payload"]:
                                zones = cpm["payload"]["InterferenceManagementZones"]
                                for zone in zones:
                                    if "managementInfo" in zone:
                                        for info in zone["managementInfo"]:
                                            if "expiryTime" in info:
                                                old_expiry_time = info["expiryTime"]
                                                delta = old_expiry_time - old_reference_time
                                                info["expiryTime"] = new_reference_time + delta
                        
                            # TODO to test
                            if "ProtectedCommunicationZonesRSU" in cpm["payload"]:
                                zones = cpm["payload"]["ProtectedCommunicationZonesRSU"]
                                for zone in zones:
                                    if "expiryTime" in zone:
                                        old_expiry_time = zone["expiryTime"]
                                        delta = old_expiry_time - old_reference_time
                                        zone["expiryTime"] = new_reference_time + delta

                            mex_encoded = CPM.encode("CollectivePerceptionMessage", cpm)

                        elif port == 2001:
                            # CAM, modify the Generation Delta Time
                            cam = CAM.decode("CAM", facilities)
                            old_reference_time = cam["cam"]["generationDeltaTime"]
                            new_reference_time = get_timestamp_ms(purpose="CAM")
                            assert new_reference_time > 0, "Error in time calculation"
                            cam["cam"]["generationDeltaTime"] = new_reference_time
                            if not cam["cam"]["camParameters"]["highFrequencyContainer"][1]["curvatureCalculationMode"]:
                                cam["cam"]["camParameters"]["highFrequencyContainer"][1]["curvatureCalculationMode"] = "unavailable"

                            # TODO to test
                            if "InterferenceManagementZones" in cam["cam"]:
                                zones = cam["cam"]["InterferenceManagementZones"]
                                for zone in zones:
                                    if "managementInfo" in zone:
                                        management_info_list = zone["managementInfo"]
                                        for info in management_info_list:
                                            if "expiryTime" in info:
                                                old_expiry = info["expiryTime"]
                                                delta = old_expiry - old_reference_time
                                                info["expiryTime"] = new_reference_time + delta

                            # TODO to test
                            if "ProtectedCommunicationZonesRSU" in cam["cam"]:
                                zones = cam["cam"]["ProtectedCommunicationZonesRSU"]
                                for zone in zones:
                                    if "expiryTime" in zone:
                                        old_expiry_time = zone["expiryTime"]
                                        delta = old_expiry_time - old_reference_time
                                        zone["expiryTime"] = new_reference_time + delta

                            mex_encoded = CAM.encode("CAM", cam)

                        elif port == 2018:
                            # VAM, modify the Generation Delta Time
                            vam = VAM.decode("VAM", facilities)
                            old_reference_time = vam["vam"]["generationDeltaTime"]
                            new_reference_time = get_timestamp_ms(purpose="VAM")
                            assert new_reference_time > 0, "Error in time calculation"
                            vam["vam"]["generationDeltaTime"] = new_reference_time

                            # TODO to test
                            if "InterferenceManagementZones" in vam["vam"]:
                                zones = vam["vam"]["InterferenceManagementZones"]
                                for zone in zones:
                                    if "managementInfo" in zone:
                                        management_info_list = zone["managementInfo"]
                                        for info in management_info_list:
                                            if "expiryTime" in info:
                                                old_expiry = info["expiryTime"]
                                                delta = old_expiry - old_reference_time
                                                info["expiryTime"] = new_reference_time + delta

                            mex_encoded = VAM.encode("VAM", vam)

                        elif port == 2002:
                            denm = DENM.decode("DENM", facilities)
                            old_reference_time = denm["denm"]["management"]["detectionTime"]
                            new_reference_time = get_timestamp_ms(purpose="DENM")
                            assert new_reference_time > 0, "Error in time calculation"
                            denm["denm"]["management"]["detectionTime"] = new_reference_time
                            denm["denm"]["management"]["referenceTime"] = new_reference_time

                            # TODO to test
                            if "ProtectedCommunicationZonesRSU" in denm["denm"]:
                                zones = denm["denm"]["ProtectedCommunicationZonesRSU"]
                                for zone in zones:
                                    if "expiryTime" in zone:
                                        old_expiry_time = zone["expiryTime"]
                                        delta = old_expiry_time - old_reference_time
                                        zone["expiryTime"] = new_reference_time + delta

                            mex_encoded = DENM.encode("DENM", denm)

                        assert mex_encoded is not None, "Something went wrong in the message modifications"

                        # Build the new packet
                        raw_part = new_geonet + btp + mex_encoded
                        if ether_part and raw_part:
                            new_pkt = ether_part + raw_part
                        if security:
                            # Add the Security Tail
                            new_pkt = new_pkt + tail_security

                except Exception as e:
                    print(f"Error while processing packet {i}: {e}")
                    continue
            else:
                new_pkt = raw(pkt)

            assert new_pkt is not None, "Something went wrong in new packet building"

            assert sock is not None, "Something went wrong in socket creation or binding"

            if new_pcap != "":
                wrpcap(new_pcap, new_pkt, append=True)

            try:
                sock.send(new_pkt)
                if enable_amqp:
                    # Send the packet to the AMQP broker
                    properties = compute_properties()
                    succ = amqp_sender.send_message(new_pkt, message_id=f"packet{i+1}", properties=properties)
                    if not succ:
                        print("ERROR on message sending to the AMQP broker!")
            except Exception as e:
                print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        print(f"Pcap reproduction on interface {interface} terminated")
        if enable_amqp:
            amqp_sender.stop()
            amqp_thread.join()


# write_pcap(input_filename="/home/diego/TRACEN-X/VAMsTX_231219_161928.pcapng", interface="enp0s31f6", start_time=None, end_time=None, update_datetime=True)

write_pcap(stop_event=None, input_filename="cattura_MIS_80211p.pcapng", interface="enp0s31f6", start_time=None, end_time=None, update_datetime=True, new_pcap="/mnt/xtra/TRACEN-X/new_pcap.pcap", enable_amqp=False, amqp_server_ip="", amqp_server_port=0, amqp_topic="")