const mqtt = require("mqtt");
const axios = require("axios");
const utf8 = require("crypto-js/enc-utf8");
const hex = require("crypto-js/enc-hex");
const base64 = require("crypto-js/enc-base64");
const AES = require("crypto-js/aes");

/***************** Utility methods ****************/

const getMqConfigIP = async (transport) => {
  const response = await axios.get(
    `http://192.168.81.233/brms/api/v1.1/config/mq/${transport}`
  );
  return response.data;
};

/**
 * aesDecrypt
 * AES decrypt
 * @param {*} word
 * @param {*} secretKey
 * @param {*} secretVector
 * @return {*} string
 */
function aesDecrypt(word, secretKey, secretVector) {
  const key = utf8.parse(secretKey);
  const iv = utf8.parse(secretVector);
  const encryptedHexWord = hex.parse(word);
  const srcs = base64.stringify(encryptedHexWord);
  const decrypt = AES.decrypt(srcs, key, { iv });
  const decryptedWord = decrypt.toString(utf8);
  return decryptedWord.toString();
}

/********************************************************
 * !! MAIN PART BEGIN !! *
 ********************************************************/

const protocol = "wss"; // Assume that the protocol is wss
const config = {}; // global mq config info
let mq;

/**
 * getMqConfig
 * Get Mq config
 */
async function getMqConfig() {
  const {
    addr,
    username,
    password: encryptedPassword,
  } = await getMqConfigIP(protocol);

  // Replace with your logic to retrieve secretKey and secretVector from cache
  const secretKey = "yourSecretKey";
  const secretVector = "yourSecretVector";

  // Decrypt mq password
  const password = aesDecrypt(encryptedPassword, secretKey, secretVector);

  // Set mq config info
  config.addr = addr;
  config.username = username;
  config.password = password;
  config.protocol = protocol;
}

/**
 * connectMq
 * Connect mq and subscribe to topic
 */
async function connectMq() {
  await getMqConfig();
  const { protocol, addr, username, password } = config;
  const [host, port] = addr.split(":");
  const uri = `${protocol}://${host}:${port}`;
  const clientId = "xxxxxx-xxxxxxy-0xxxxxx";

  /*********************************************
   * Connect and get mq instance *
   *********************************************/
  mq = mqtt.connect(uri, { username, password, clientId });

  /*********************************************
   * Subscribe and Receive *
   *********************************************/
  const topicName = "mq.alarm.msg.topic.1";

  // Subscribe
  mq.subscribe(topicName, function (err) {
    if (!err) console.log("Subscribed successfully!");
  });

  // Receive messages
  mq.on("message", (topic, message) => {
    console.log(topic, message.toString());
  });
}

// Connect to MQTT broker and subscribe
connectMq()
  .then(() => {
    console.log("Connected to MQTT broker and subscribed to topic.");
  })
  .catch((error) => {
    console.error("Error connecting to MQTT broker:", error);
  });

/********************************************************
 * !! MAIN PART END !! *
 ********************************************************/

const express = require("express");
const app = express();

const port = 4952;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
