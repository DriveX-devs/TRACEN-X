// Required modules
const fs = require('fs');
const path = require('path');
const express = require('express');
const http = require('http');
const dgram = require('dgram');
const socketIo = require('socket.io');

var mapmsg = null;

// Read the server port as a command line option
const server_argv = process.argv.slice(2);
if (server_argv.length != 4) {
    console.error("VehicleVisualizer: Error. Four arguments are expected and " + server_argv.length.toString() + " were specified.");
    process.exit(1);
} else {
    console.log("VehicleVisualizer: HTTP server listening on port: " + server_argv[0]);
    console.log("VehicleVisualizer: UDP socket bound at: " + server_argv[1] + ":" + server_argv[2]);
}

// Create a new HTTP server with express.static
const app = express();
app.use(express.static(path.join(__dirname, '/')));
const server = http.Server(app);

// Create a UDP socket to receive the data
const udpSocket = dgram.createSocket('udp4');

// Bind the socket to the loopback address/interface
udpSocket.bind({
    address: server_argv[1],
    port: server_argv[2]
});

// This callback is called when the UDP socket starts "listening" for new packets
udpSocket.on('listening', () => {
    const address = udpSocket.address();
    console.log('VehicleVisualizer: UDP connection ready at %s:%s', address.address, address.port);
    fs.writeFileSync(server_argv[3], 'ready'); // Write to the FIFO

});

// Initialize socket.io
const io = socketIo(server);

// socket.io connection callback (called every time a client connects)
io.on('connection', (socket) => {
    console.log('VehicleVisualizer: A user is connected to the web interface');
    console.log(mapmsg);
    io.sockets.send(mapmsg);
});

// As a new packet is received, its content is forwarded to the client (i.e. the browser) via socket.io
udpSocket.on('message', (msg, rinfo) => {
    try {
        const msg_fields = msg.toString().split(',');

        // console.log(msg.toString());
    
        if (msg_fields[0] === "map") {
            if (msg_fields.length !== 3) {
                console.error("Error: received a corrupted map draw message from GNSS-Parser-Reproducer.");
                process.exit(1);
            }
            else {
                console.log("VehicleVisualizer: Map draw message received from GNSS-Parser-Reproducer.");
                mapmsg = msg.toString();
            }
        } else if (msg_fields[0] === "map_areas") {
            if (msg_fields.length !== 9) {
                console.error("Error: received a corrupted map draw message from GNSS-Parser-Reproducer (map_areas type).");
                process.exit(1);
            }
            else {
                console.log("VehicleVisualizer: Map draw message received from GNSS-Parser-Reproducer.");
                mapmsg = msg.toString();
            }
        } else if (msg_fields[0] === "terminate") {
            console.log("VehicleVisualizer: The server received a terminate message. The execution will be terminated.");
            process.exit(0);
        } else if (msg_fields[0] == "object") {
            const lat = parseFloat(msg_fields[2]);
            const lon = parseFloat(msg_fields[3]);
            const heading = parseFloat(msg_fields[5]);
            // console.log(`Received data - Lat: ${lat}, Lon: ${lon}, Heading: ${heading}`);
            io.sockets.send(msg.toString());
        } else {
            console.error("Error: received a corrupted message.");
        }
    } catch (e) {
        console.error("Error parsing UDP message:", e);
    }
});

// Start the HTTP server on the specified port (i.e. on port server_argv[0])
server.listen(server_argv[0], () => {
    console.log("VehicleVisualizer: Listening on *:" + server_argv[0]);
});