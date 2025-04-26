const WebSocket = require('ws');
const { ethers } = require('ethers');
const { sendDiscordAlert } = require('./alerts');

let wsInstance = null;

const cooldown = 60 * 1000;

const startMonitoring = (io, config) => {
  if (!config || !config.privateKey || !config.walletAddress || !config.webhookUrl) {
    throw new Error('Missing required config for monitoring');
  }

  const { privateKey, walletAddress, webhookUrl, tokens, minSize } = config;
  const id = walletAddress.toLowerCase();

  if (!Array.isArray(tokens) || tokens.length === 0) {
    throw new Error('Tokens array is required and non-empty');
  }
  if (typeof minSize !== 'number' || minSize <= 0) {
    throw new Error('minSize must be a positive number');
  }

  const tokenFilters = tokens.map(t => t.toUpperCase());
  const minTriggerSize = minSize;

  let lastAlert = {};
  let reconnectAttempts = 0;
  const maxReconnectAttempts = Infinity;
  const reconnectDelay = 5000;

  const fillMatchesCriteria = (fill) => {
    const { coin, sz, dir } = fill;
    const size = parseFloat(sz);
    const now = Date.now();

    return (
      tokenFilters.includes(coin) &&
      size >= minTriggerSize &&
   //   ["Open Long", "Close Long", "Reduce Position"].includes(dir) &&
      (!lastAlert[coin] || now - lastAlert[coin] > cooldown)
    );
  };

  const parseFill = (fill) =>
    `${fill.dir} ${fill.coin} | Size: ${fill.sz} | Price: ${fill.px} | PnL: ${fill.closedPnl ?? 'N/A'}`;

  const connect = () => {
    try {
      if (reconnectAttempts >= maxReconnectAttempts) {
        console.log(`[${id}] Reached max reconnection attempts (${maxReconnectAttempts}). Resetting counter.`);
        reconnectAttempts = 0;
      }

      wsInstance = new WebSocket("wss://api.hyperliquid-testnet.xyz/ws");

      wsInstance.on('open', async () => {
        console.log(`[${id}] WebSocket connected to Hyperliquid`);
        reconnectAttempts = 0;

        try {
          await authenticate(wsInstance, privateKey, walletAddress, id);
          subscribe(wsInstance, walletAddress, id);
        } catch (error) {
          console.error(`[${id}] Authentication error:`, error);
          wsInstance.close();
        }
      });

      wsInstance.on('message', (data) => {
        try {
          const json = JSON.parse(data.toString());
          //console.log(json);
          if (json.channel === 'user' && json.data?.fills?.length) {
            const fill = json.data.fills[0];
            //console.log(fill);
            if (fillMatchesCriteria(fill)) {
              lastAlert[fill.coin] = Date.now();
              const msg = parseFill(fill);
              console.log(`[${id}] ALERT:`, msg);

              io.emit('fill_alert', `[${id}] ${msg}`);

              // sending alert
              sendDiscordAlert(msg, webhookUrl);
            }
          }
        } catch (err) {
          console.error(`[${id}] Parsing error:`, err);
        }
      });

      wsInstance.on('close', () => {
        reconnectAttempts++;
        const delay = reconnectDelay * Math.min(reconnectAttempts, 5);
        console.log(`[${id}] Disconnected from Hyperliquid. Reconnecting (attempt ${reconnectAttempts}) in ${delay / 1000}s...`);
        setTimeout(connect, delay);
      });

      wsInstance.on('error', (err) => {
        console.error(`[${id}] WebSocket error:`, err);
      });
    } catch (error) {
      console.error(`[${id}] Connection setup error:`, error);
      reconnectAttempts++;
      setTimeout(connect, reconnectDelay);
    }
  };

  connect();

  return { wsInstance };
};

const authenticate = async (ws, privateKey, walletAddress, id) => {
  try {
    const wallet = new ethers.Wallet(privateKey);
    const timestamp = Date.now();
    const msg = `hyperliquid_${timestamp}`;

    const signature = await wallet.signMessage(msg);

    const authPayload = {
      method: "subscribe",
      subscription: {
        type: "user",
        user: walletAddress
      },
      signature,
      timestamp
    };

    ws.send(JSON.stringify(authPayload));
    console.log(`[${id}] Authentication payload sent`);
  } catch (error) {
    console.error(`[${id}] Authentication error:`, error);
    throw error;
  }
};

const subscribe = (ws, walletAddress, id) => {
  try {
    const msg = {
      method: "subscribe",
      subscription: {
        type: "userEvents",
        user: walletAddress
      }
    };
    ws.send(JSON.stringify(msg));
    console.log(`[${id}] Subscription payload sent`);
  } catch (error) {
    console.error(`[${id}] Subscription error:`, error);
    ws.close();
  }
};

module.exports = { startMonitoring };