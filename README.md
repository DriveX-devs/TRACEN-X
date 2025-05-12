# TRACEN-X: Telemetry Replay and Analysis of CAN bus and External Navigation data

<div align="center">

<img src="TRACEN-X_logo_v3.png" width="500"/>
  
</div>

<\br>

This project is designed to record and replay GNSS serial data, specifically handling NMEA and UBX messages, and CAN Bus data. 

It consists of three main scripts: `record/record.py`, `replay/replay.py`, and `merge_traces/union.py`.

## Features

- **record/record.py**: Reads data from a Serial Device and/or a CAN Bus and saves it to a JSON file.
- **replay/replay.py**: Reads data from JSON files and emulates in real-time a Serial Device and/or a CAN Bus. If desired, it displays a GUI to visualize the vehicle and the objects perceived.
- **replay/decoded_messages.py**: Utility class to decode NMEA messages to extract latitude, longitude, and heading of vehicle.
- **replay/vehicle_visualizer**: GUI to visualize the vehicle and the objects perceived.
- **serial_emulator/serial_emulator.py**: Utility class to emulate a serial device using `socat`.
- **merge_traces/union.py**: Utility class to merge multiple csv traces into a single one.

## Requirements

- Python 3.x
- pyserial (for serial recording and reproducing)
- pyproj (for GUI mode)
- nodejs (for GUI mode)
- socat (for serial emulation)
- cantools (for CAN Bus recording and reproducing)
- [Optional] can-utils (for testing CAN Bus features with "canplayer" and "candump")

## Installation

1. Clone the repository:
    ```sh
        git clone https://github.com/Diegomangasco/GNSS-Parser-Reproducer.git
        cd GNSS-Parser-Reproducer
    ```
2. Upgrade pip
    ```sh
       python3 -m pip install --upgrade pip
    ```
3. [Optional] Set environmental variable for embedded systems (e.g. On Board Units) to work correclty with cantools package:
    ```sh
        MSGPACK_PUREPYTHON=1 pip3 install --no-cache-dir cantools
    ```
4. Install the required Python packages:
   ```sh
       pip install -r requirements
   ```

5. [Optional] Install the required Python packages:
    ```sh
        pip install pyserial
        pip install cantools
        pip install pyproj
    ```

6. Ensure `socat` is installed on your system:
    ```sh
        sudo apt-get install socat
    ```

7. Ensure `nodejs` is installed on your system (**IMPORTANT**: ensure to have at least v12.22.9; if you have an older version, you need to upgrade it manually following the instructions available [here](https://nodejs.org/en/download/).
    ```sh
        sudo apt install nodejs
    ```

8. Install the npm packages:
    ```sh
        cd replay/vehicle_visualizer
        npm install
    ```

9. Prepare the virtual CAN Bus for the emulation:
    ```sh
        sudo ip link add dev vcan0 type vcan
        sudo ip link set up vcan0       
    ```

10. [Optional] Install the can-utils packages (just if you want to test with "canplayer" and "candump"):
    ```sh
        sudo apt install can-utils
    ```

## Usage

The detailed usage of the scripts can be found by running the following commands:
```sh
    python3 record/record.py --help
    python3 replay/replay.py --help
    python3 merge_traces/union.py --help
```

### Record

Example of usage for the record script:
```sh
    python3 record/record.py --enable_serial --device=/dev/ttyACM0 --serial_filename=./data/outlog.json --baudrate=115200 --end_time=50 --enable_CAN --CAN_device=vcan0 --CAN_filename=./data/CANlog.json --CAN_db=./data/motohawk.dbc
```

Follow the instructions inside the script to select the desired options.

### Replay

Example of usage for the replay script:
```sh
    python3 replay/replay.py --enable-serial --serial-filename ./data/gnss_output/example1.json --server-device ./replay/ttyNewServer --client-device ./replay/ttyNewClient --baudrate 115200 --start-time 10 --end-time 50 --enable-gui --http-port 8080
    
```

### Merge Traces

Example of usage for the merge traces script:
```sh
    python3 union.py --csv_files trace1.csv trace2.csv trace3.csv --output merged.csv --file_reference trace1.csv
```

Follow the instructions inside the script to select the desired options.

## Authors
- **Diego Gasco** - Politecnico di Torino - diego.gasco@polito.it
- **Carlos Mateo Risma Carletti** - Politecnico di Torino - carlos.rismacarletti@polito.it
- **Francesco Raviglione** - Politecnico di Torino - francesco.raviglione@polito.it
- **Marco Rapelli** - Politecnico di Torino - marco.rapelli@polito.it
- **Claudio Casetti** - Politecnico di Torino - claudio.casetti@polito.it

## Work-in-progress for the first release
- [ ] Enable the reliable usage of baud rates higher than 115200
- [X] Make the record script more robust to issues that may stop the recording of the trace, making it save anyway what has been captured until that moment
- [X] CAN Database parsing
- [X] GUI for CAN objects
