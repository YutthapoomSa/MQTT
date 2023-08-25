const mqtt = require("mqtt");
const axios = require("axios");
const utf8 = require("crypto-js/enc-utf8");
const hex = require("crypto-js/enc-hex");
const base64 = require("crypto-js/enc-base64");
const AES = require("crypto-js/aes");
const md5Encrypt = require("crypto-js/md5");
// ─────────────────────────────────────────────────────────────────────────────

/********* Utility methods ****************/
const PUBLIC_KEY = "MIIBI....B";
const PRIVATE_KEY = "MIIBI....P";
const CLIENT_TYPE = "WINPC_V2";
const md5 = (val) => {
  return md5Encrypt(val).toString();
};

const authorize = async (data) => {
  return axios.post(
    "http://10.160.200.200/brms/api/v1.0/accounts/authorize",
    data
  );
};

const keepalive = async (data) => {
  return axios.put(
    "http://10.160.200.200/brms/api/v1.0/accounts/keepalive",
    data
  );
};

const updateToken = async (data) => {
  return axios.post(
    "http://10.160.200.200/brms/api/v1.0/accounts/updateToken",
    data
  );
};

/**
 * setItem
 * The function to cache data locally
 * @param {*} key
 * @param {*} data
 */
function setItem(key, data) {
  localStorage.setItem(key, data);
}

/********* Utility methods END ************/
/********************************************************
 * !! MAIN PART BEGIN !! *
 ********************************************************/
/**
 * firstLogin
 * First Login. Get information about encryption
 *
 * @param {*} username
 * @return {*}
 * @memberof Session
 */
async function firstLogin(username) {
  try {
    await authorize({
      userName: username,
      ipAddress: "10.160.200.200",
      clientType: CLIENT_TYPE,
    });
  } catch ({ realm, encryptType, publickey, randomKey }) {
    return { realm, encryptType, publickey, randomKey };
  }
}

/**
 * login (main)
 *
 * @param {*} username
 * @param {*} password
 * @return {*} undefined | Promise
 * When some error occurs, a Rejected promise is thrown to the outer layer
 * @memberof Session
 */
async function login() {
  const username = "system";
  const password = "CCTV@Fwh65";

  try {
    const firsetLoginResult = await firstLogin();

    const { realm, encryptType, publickey, randomKey } = firsetLoginResult;

    const $$signature = md5(
      username + ":" + realm + ":" + md5(md5(username + md5(password)))
    );
    const signature = md5($$signature + ":" + randomKey);

    setItem("firstRejectPublicKey", publickey);
    setItem("$$signature", $$signature);

    const dataSecondLogin = await secondLogin({
      mac: "00:15:5D:02:26:02",
      signature,
      userName: username,
      randomKey,
      publicKey: publickey,
      encryptType,
      ipAddress: "192.168.81.233",
      clientType: CLIENT_TYPE,
      userType: 0,
    });

    const { code, desc, data, token, secretKey, secretVector } =
      dataSecondLogin;

    if (code && code !== 1000) {
      // If code is not equal to 1000
      return await Promise.reject({ code, data, desc });
    } else if (token) {
      setItem("token", token); // token
      setItem("secretKey", secretKey); // secretKey
      setItem("secretVector", secretVector); // secretVector
    }
  } catch ({ code, data, desc }) {
    // Other kinds of exception handling
    return await Promise.reject({ code, data, desc });
  }
}

/**
 * keep alive
 */
async function doKeepAlive() {
  const token = getItem("token");
  keepalive({
    token,
  });
}

/**
 * UpdateToken
 */
async function doUpdateToken() {
  const $$signature = getItem("$$signature");
  const token = getItem("token");
  const signature = md5($$signature + ":" + token);
  const { token: updatedToken } = await updateToken({ signature });
  setItem("token", updatedToken);
}

/********* Call login function ************/
const username = "system";
const password = "CCTV@Fwh65";
login(username, password);
/********* Call login function ************/

/*********** Keepalive and update ************/
const KEEP_ALIVE_TIME = 22 * 1000;
const RESET_TOKEN_TIME = 22 * 60 * 1000;
setInterval(async () => {
  await doKeepAlive();
}, KEEP_ALIVE_TIME);
setInterval(async () => {
  await doUpdateToken();
}, RESET_TOKEN_TIME);
/********* Keepalive and update END **********/

// ─────────────────────────────────────────────────────────────────────────────

/***************** Utility methods ****************/

const getMqConfigIP = async (transport) => {
  console.log('http://10.160.200.200/brms/api/v1.1/config/mq/' + transport);
  const response = await axios.get(
    `http://10.160.200.200/brms/api/v1.1/config/mq/${transport}`
  );
  console.log(response.data)
  return response.data;
};

/**
* getItem
* The function to get data from cache
* @param {*} key 
*/
function getItem(key) {
  return localStorage.getItem(key);
}
// const value =  localStorage.getItem("key");
// console.log(value);
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
async function getMqConf() {
  try {
    const {
      addr,
      username,
      password: encryptedPassword,
    } = await getMqConfigIP(protocol);

    console.log("ADDR  => ", addr)
    // const secretKey = "yourSecretKey";
    // const secretVector = "yourSecretVector";

    const decryptedPassword = aesDecrypt(encryptedPassword, secretKey, secretVector);

    config.addr = addr;
    config.username = username;
    config.password = decryptedPassword;
    config.protocol = protocol;
  } catch (error) {
    console.error("Error getting MQ config:", error);
  }
}



/**
 * connectMq
 * Connect mq and subscribe to topic
 */
async function connectMq() {
  try {
    await getMqConf();
    const { protocol, addr, username, password } = config;
    const [host, port] = addr.split(":");
    const uri = `${protocol}://${host}:${port}`;
    const clientId = "xxxxxx-xxxxxxy-0xxxxxx";

    mq = mqtt.connect(uri, { username, password, clientId });

    const topicName = "mq.alarm.msg.topic.1";

    mq.on("connect", () => {
      mq.subscribe(topicName, function (err) {
        if (!err) console.log("Subscribed successfully!");
      });
    });

    mq.on("message", (topic, message) => {
      console.log("log =>> ", topic, message.toString());
    });
  } catch (error) {
    console.error("Error connecting to MQTT broker:", error);
  }
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

// const express = require("express");
// const app = express();

// const port = 4952;
// app.listen(port, () => {
//   console.log(`Server running on port ${port}`);
// });
