import subprocess, serial, time, os

class SerialEmulator(object):
    def __init__(self, device_port='./ttyNewDevice', client_port='./ttyNewClient', baudrate=115200):
        self.device_port = device_port
        self.client_port = client_port
        cmd=['/usr/bin/socat','-d','-d','PTY,link=%s,raw,echo=0' %
                self.device_port, 'PTY,link=%s,raw,echo=0' % self.client_port]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            print("Error: Could not create virtual serial port")
            raise serial.SerialException
        time.sleep(1)
        self.serial_server = serial.Serial(
            self.device_port, 
            baudrate=baudrate, 
            rtscts=True, 
            dsrdtr=True, 
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=0
        )
        self.serial_client = serial.Serial(
            self.client_port, 
            baudrate=baudrate, 
            rtscts=True, 
            dsrdtr=True, 
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=0
        )
        print("Serial client options:")
        print(self.serial_client)
        self.err = ''
        self.out = ''

    def write(self, out):
        try: 
            ret = self.serial_server.write(out)
            # print(ret)
        except:
            raise serial.SerialTimeoutException

    def read(self):
        try:
            data = self.serial_client.read(1)
            return data
        except:
            raise serial.SerialTimeoutException

    def __del__(self):
        self.stop()

    def stop(self):
        self.proc.kill()
        self.out, self.err = self.proc.communicate()