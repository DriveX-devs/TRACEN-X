import socket, os

class Visualizer:

    def __init__(self):
        self.ego_lat = None
        self.ego_lon = None
        self.ego_heading = None

    def open_map_gui(self, lat, lon, server_ip, server_port):
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

    def start_nodejs_server(self, httpport, ip, port, fifo_path):
        """
        Starts the nodejs server for the vehicle visualizer.
        """
        try:
            os.system(f"node ./vehicle_visualizer/server.js {httpport} {ip} {port} {fifo_path} &")
        except Exception as e:
            print(f"Error starting nodejs server: {e}")
            raise e

    def send_object_udp_message(self, GNSS_flag, CAN_flag, lat, lon, heading, server_ip, server_port, station_id=1, type=5):
        """
        Sends a UDP message with the latitude, longitude, and heading to the specified server.
        """
        assert GNSS_flag or CAN_flag, "At least one of GNSS_flag or CAN"
        id = -1
        station_type = -1
        if GNSS_flag:
            id = 1
            station_type = 5
        elif CAN_flag:
            id = 2
            station_type = type
        if not heading:
            heading = 361
        message = f"object,{id},{lat},{lon},{station_type},{heading}"
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

    def stop_server(self, server_ip, server_port):
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

    def getEgoPosition(self):
        if self.ego_lat is None or self.ego_lon is None or self.ego_heading is None:
            return None
        else:
            return self.ego_lat, self.ego_lon, self.ego_heading
