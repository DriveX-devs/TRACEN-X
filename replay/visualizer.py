import socket
import os

class Visualizer:

    def __init__(self):
        self.ego_lat = None
        self.ego_lon = None
        self.ego_heading = None

    def open_map_gui(self, lat: float, lon: float, server_ip: str, server_port: int):
        """
        Opens the map GUI.
        """
        message = f"map,{lat},{lon}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode(), (server_ip, server_port))
        except Exception as e:
            print(f"Error sending UDP message: {e}")
            raise e

    def start_nodejs_server(self, httpport: int, ip: str, port: int, fifo_path: str):
        """
        Starts the nodejs server for the vehicle visualizer.
        """
        try:
            os.system(f"node ./vehicle_visualizer/server.js {httpport} {ip} {port} {fifo_path} &")
        except Exception as e:
            print(f"Error starting nodejs server: {e}")
            raise e

    def send_object_udp_message(self, GNSS_flag: bool, CAN_flag: bool, lat: float, lon: float, heading: float, server_ip: str, server_port: int, station_id: int = 1, type: int = 5):
        """
        Sends a UDP message with the latitude, longitude, and heading to the specified server.
        """
        assert GNSS_flag or CAN_flag, "At least one of GNSS_flag or CAN"
        
        if not heading:
            heading = 361
        message = f"object,{station_id},{lat},{lon},{type},{heading}"
        if GNSS_flag:
            self.ego_lat = lat
            self.ego_lon = lon
            self.ego_heading = heading
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode(), (server_ip, server_port))
        except Exception as e:
            print(f"Error sending UDP message: {e}")
            raise e

    def stop_server(self, server_ip: str, server_port: int):
        """
        Stops the nodejs server for the vehicle visualizer.
        """
        message = f"terminate"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode(), (server_ip, server_port))
        except Exception as e:
            print(f"Error stopping nodejs server: {e}")
            raise e

    def get_ego_position(self) -> tuple:
        if self.ego_lat is None or self.ego_lon is None or self.ego_heading is None:
            return None
        else:
            return self.ego_lat, self.ego_lon, self.ego_heading
