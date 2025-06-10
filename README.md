# TRACEN-X: Telemetry Replay and Analysis of CAN bus and External Navigation data

<div align="center">

<img src="TRACEN-X_logo_v3.png" width="500"/>
  
</div>

<br/><br/>

## Authors
- **Diego Gasco** - Politecnico di Torino - diego.gasco@polito.it
- **Carlos Mateo Risma Carletti** - Politecnico di Torino - carlos.rismacarletti@polito.it
- **Francesco Raviglione** - Politecnico di Torino - francesco.raviglione@polito.it
- **Marco Rapelli** - Politecnico di Torino - marco.rapelli@polito.it
- **Claudio Casetti** - Politecnico di Torino - claudio.casetti@polito.it

## Description

This project is designed to record and replay multiple data sources to recreate the field test conditions of a vehicel in a controlled environment (e.g. in laboratory).
The supported data sources include:
- Serial Device (GNSS receiver)
- CAN Bus (vehicle sensors)
- V2X messages (Vehicle-to-Everything communication)

With TRACEN-X, each one of these data sources can be recorded and saved with a specific script, and then replayed in real-time to emulate the original conditions of the field test.
The project also includes a GUI to visualize the vehicle and the objects perceived during the replay phase.

It consists of three main scripts: `record/record.py`, `replay/replay.py`, and `merge_traces/union.py`.

The `record` script captures data from one or multiple data sources and save the content with timing information.

The `replay` script reads these stored files and emulates the data sources in real-time, through a serial device, a CAN Bus, and a network interface. There is also the option for displaying a Web GUI for visualization.

The `merge_traces` script allows merging multiple CSV traces into a single one.

## Requirements

### Software Requirements
- Linux-based operating system (e.g., Ubuntu, Debian, etc.)
- Python 3.x
- socat (for serial emulation)
- [Optional] can-utils (for testing CAN Bus features with "canplayer" and "candump")

### Python Packages
- pyserial (for serial recording and reproducing)
- pyproj (for GUI mode)
- nodejs (for GUI mode)
- cantools (for CAN Bus recording and reproducing)
- asn1tools (for V2X messages recording and reproducing)
- scapy (for V2X messages recording and reproducing)


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
    pip install asn1tools
    pip install scapy
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
python3 record/record.py --enable-serial --device=/dev/ttyACM0 --serial-filename=./data/outlog.json --baudrate=115200 --end-time=10 --enable-CAN --CAN-device=vcan0 --CAN-filename=./data/CANlog.json --CAN-db=./data/motohawk.db --enable-pcap --interface=wlan1 --pcap-filename=./data/pcap_output/trace2.pcapng
```

Follow the instructions inside the script to select the desired options.

### Replay

Example of usage for the replay script:
```sh
python3 replay/replay.py --enable-serial --serial-filename ./data/gnss_output/example1.json --server-device ./replay/ttyNewServer --client-device ./replay/ttyNewClient --baudrate 115200 --start-time 0 --end-time 10 --enable-gui --http-port 8080 --enable-pcap --interface=wlan1 --update-datetime --new-pcap-file=new_pcap.pcapng
```

### Merge Traces

Example of usage for the merge traces script:
```sh
python merge_traces/union.py --csv-files trace1.csv trace2.csv trace3.csv --output merged.csv --file-reference trace1.csv
```

Follow the instructions inside the script to select the desired options.

## Work-in-progress for the first release
- [ ] Enable the reliable usage of baud rates higher than 115200
- [ ] Enable the GUI reproduction of objects perceived from V2X messages
- [ ] Enable the GUI reproduction of diverse objectes perceived through the CAN Bus
- [X] Make the record script more robust to issues that may stop the recording of the trace, making it save anyway what has been captured until that moment
- [X] CAN Database parsing
- [X] GUI for CAN objects
