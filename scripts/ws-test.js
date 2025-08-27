// Description: WebSocket client test script.

const WebSocket = require('ws');

const socket = new WebSocket(
    'wss://localhost:18080/ue_reg',
    {
        rejectUnauthorized: false
    }

);

socket.onopen = () => {
    console.log("Connected to WebSocket");
    // socket.send("Hello, server!");
    // ssend ping message: messageType: 9
    let data = {
        "stage": 1,
        "supi": "imsi-2089300007487",
    }
    socket.send(JSON.stringify(data));
    // socket.send("ping");


};

socket.onmessage = (event) => {
    console.log("Message from server:", event.data);
};

socket.onclose = () => {
    console.log("Disconnected from WebSocket");
};