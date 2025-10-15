import socket
import time
import threading
from typing import Any
import asn1tools as asn
from scapy.all import *
from scapy.layers.l2 import Ether
from proton import Message
from proton.reactor import Container
from proton.handlers import MessagingHandler
from utils import countCertificates
from utils.Security import Security
import glob

# Normal packet (without security layer) constants
GEONET_LENGTH = 40
BASICHEADER = 4
ETHER_LENGTH = 14
GEONET_TS_LOW = 20
GEONET_TS_HIGH = 24
BTP_LOW = 40
BTP_HIGH = 44
BTP_PORT_HIGH = 2

# General facility constants
TIME_SHIFT = 1072915200000
TS_MAX1 = 4294967296
MODULO_WRAP = 4398046511103
MODULO_CAM_VAM_DENM = 65536
PURPOSES = ["GeoNet", "CPM", "CAM", "VAM", "DENM"]

cpm_asn = "./data/asn/CPM-all.asn"
vam_asn = "./data/asn/VAM-PDU-FullDescription.asn"
cam_asn = "./data/asn/CAM-all-old.asn"
denm_asn = "./data/asn/DENM-all-old.asn"
security_folder = "./data/asn/security/"

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
            self.sender = event.container.create_sender(conn, "topic://" + self.topic)
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


def compute_properties(security_enabled: bool = None, port: int = None, StationID: int = None) -> dict:
    properties = {
        "security": "unsecured" if security_enabled is False else "secured" if security_enabled is True else "unknown",
        "sent_to_broker_at": int(time.time() * 1e3),
        "purpose": "V2X message",
        "destination_port": port if port is not None else "unknown",
        "station_id": StationID if StationID is not None else "unknown" 
    }
    return properties


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
        millis = int((seconds * 1e6 + microseconds) / 1e3)

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


def write_pcap(barrier: Any, stop_event: Any, input_filename: str, interface: str, start_time: int, end_time: int, update_datetime: bool, new_pcap: str, enable_amqp: bool, amqp_server_ip: str, amqp_server_port: int, amqp_topic: str, certificates: dict, update_security: bool) -> None:
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

    CPM = asn.compile_files(cpm_asn, "uper")
    VAM = asn.compile_files(vam_asn, "uper")
    CAM = asn.compile_files(cam_asn, "uper")
    DENM = asn.compile_files(denm_asn, "uper")
    asn_files = glob.glob(os.path.join(security_folder, "*.asn"))
    SECURITY = asn.compile_files(asn_files, 'oer')
    
    security = Security()
    LastAssigned = 0
    VehicleDict = {}

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
        print("Warning: raw socket unavailable, packets will not be sent on the interface.")

    base_ts = pcap[0].time  # epoch time in seconds

    # Flush the new_pcap if present
    if new_pcap != "" and os.path.exists(new_pcap):
        os.remove(new_pcap)

    if barrier:
        barrier.wait()
    
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
            port = None
            security_enabled = None
            StationID = None
            if update_datetime:
                raw_part = None
                try:
                    # Extract the Ethernet II part
                    ether_part = raw(pkt)[:ETHER_LENGTH]
                    # Take the rest ot the packet
                    data = raw(pkt)[ETHER_LENGTH:]
                    # Check if the security layer is active
                    security_enabled = False if data[:1] == b'\x11' else True
                    # Set the fields for pkt reconstruction to None to check if they will be filled properly
                    facilities = None
                    port = None
                    btp = None
                    new_geonet = None
                    
                    if not security_enabled:
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
                        pack = raw(pkt)
                        EtherAndBasic = pack[:ETHER_LENGTH+BASICHEADER]
                        DecodedPacket = SECURITY.decode("Ieee1609Dot2Data", pack[18:])
                        payload_data = DecodedPacket['content'][1]['tbsData']['payload']['data']
                        payload_choice, UnsecuredData = payload_data['content']
                        Signer = DecodedPacket['content'][1]['signer'][0]  # header
                        if Signer == 'digest':
                            isCertificate = False
                        elif Signer == 'certificate':
                            isCertificate = True
                        else:
                            raise ValueError(f"Unknown signer type {Signer}")
                        
                        Htype = UnsecuredData[1]
                        if Htype == 80:  # GeoNet
                            # SHB case CAMs
                            TSPOS = 16
                            CurrentTime = get_timestamp_ms(purpose="GeoNet")
                            assert CurrentTime > 0, "Error in time calculation"
                            CurrentTime_bytes = CurrentTime.to_bytes(4, byteorder="big", signed=False)
                        elif Htype == 64:  # GeoScoped
                            # GeoScoped case DENMs
                            TSPOS = 20
                            CurrentTime = get_timestamp_ms(purpose="GeoNet")
                            assert CurrentTime > 0, "Error in time calculation"
                            CurrentTime_bytes = CurrentTime.to_bytes(4, byteorder="big", signed=False)
                        else:
                            raise ValueError(f"Unknown Header Type {Htype}")
                        UnsecuredDataUpdate = bytearray(UnsecuredData)
                        UnsecuredDataUpdate[TSPOS:TSPOS+4] = CurrentTime_bytes
                        # Search for the BTP
                        plength = int.from_bytes(UnsecuredDataUpdate[4:6], byteorder="big")
                        payload_offset = len(UnsecuredDataUpdate) - plength
                        payload = UnsecuredDataUpdate[payload_offset:]
                        new_geonet = bytes(UnsecuredDataUpdate[:payload_offset])
                        btp = payload[:4]
                        port = int.from_bytes(btp[:BTP_PORT_HIGH], byteorder="big")
                        facilities = payload[4:]

                    should_update_security = update_security
                    mtype = None
                    StationID = None

                    if not new_geonet or not btp or not facilities or not port:
                        new_pkt = raw(pkt)
                    else:
                        mex_encoded = None
                        if port == 2009:
                            mtype = 'CPM'
                            should_update_security = False
                            # CPM, modify the Reference Time
                            cpm = CPM.decode("CollectivePerceptionMessage", facilities)
                            StationID = cpm['header']['stationID']
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
                            
                            if security_enabled and should_update_security:
                                if StationID not in VehicleDict.keys():
                                    VehicleDict[StationID] = LastAssigned
                                    LastAssigned += 1

                            mex_encoded = CPM.encode("CollectivePerceptionMessage", cpm)

                        elif port == 2001:
                            # CAM, modify the Generation Delta Time
                            mtype = 'CAM'
                            cam = CAM.decode("CAM", facilities)
                            StationID = cam['header']['stationID']
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
                            if security_enabled and should_update_security:
                                if StationID not in VehicleDict.keys():
                                    VehicleDict[StationID] = LastAssigned
                                    LastAssigned += 1

                        elif port == 2018:
                            mtype = 'VAM'
                            should_update_security = False
                            # VAM, modify the Generation Delta Time
                            vam = VAM.decode("VAM", facilities)
                            StationID = vam['header']['stationID']
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
                            mtype = 'DENM'
                            denm = DENM.decode("DENM", facilities)
                            StationID = denm['header']['stationID']
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
                            
                            if security_enabled and should_update_security:
                                gen_loc = DecodedPacket["content"][1]["tbsData"]["headerInfo"]["generationLocation"]
                                if StationID not in VehicleDict.keys():
                                    VehicleDict[StationID] = LastAssigned
                                    LastAssigned += 1
                            mex_encoded = DENM.encode("DENM", denm)

                        assert mex_encoded is not None, "Something went wrong in the message modifications"

                        # Build the new packet
                        raw_part = new_geonet + btp + mex_encoded
                        
                        if ether_part and raw_part:
                            new_pkt = ether_part + raw_part
                        if security_enabled:
                            # rebuild the security layer
                            new_payload = btp + mex_encoded
                            UnsecuredDataUpdate[payload_offset:] = new_payload
                            
                            if should_update_security:
                                if not certificates:
                                    raise ValueError("Certificates are required to rebuild secured packets")
                                if StationID is None:
                                    raise ValueError("StationID is required to rebuild secured packets")
                                vehicle_idx = VehicleDict[StationID] % len(certificates)
                                vehicle_key = str(vehicle_idx)
                                if vehicle_key not in certificates or 'AT' not in certificates[vehicle_key]:
                                    raise KeyError(f"Missing AT certificate for vehicle {vehicle_key}")
                                certificate = certificates[vehicle_key]['AT']
                                SecuredPacket = security.createSecurePacket(bytes(UnsecuredDataUpdate), certificate, vehicle_idx, isCertificate, mtype, gen_loc if mtype == "DENM" else None)
                                new_pkt = EtherAndBasic + SecuredPacket
                            
                            if not should_update_security:
                                payload_data['content'] = (payload_choice, bytes(UnsecuredDataUpdate))
                                new_pkt = EtherAndBasic + SECURITY.encode("Ieee1609Dot2Data", DecodedPacket)

                except Exception as e:
                    print(f"Error while processing packet {i}: {e}")
                    continue
            else:
                new_pkt = raw(pkt)

            assert new_pkt is not None, "Something went wrong in new packet building"

            if new_pcap != "":
                wrpcap(new_pcap, Ether(new_pkt), append=True)
            if sock:
                try:
                    sock.send(new_pkt)
                    if enable_amqp:
                        # Send the packet to the AMQP broker (excluding first 14 bytes of any Ethernet II "dummy" header)
                        properties = compute_properties(security_enabled, port, StationID)
                        succ = amqp_sender.send_message(new_pkt[ETHER_LENGTH:], message_id=f"packet{i+1}", properties=properties)
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
        if sock is not None:
            sock.close()
