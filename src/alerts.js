const https = require('https');

function sendDiscordAlert(message, webhookUrl) {
  try {
    if (!webhookUrl) {
      console.error("Discord webhook URL not provided");
      return;
    }

    const webhookUrlObj = new URL(webhookUrl);

    const alertData = {
      username: 'Hyperliquid Monitor',
      avatar_url: 'https://i.imgur.com/AfFp7pu.png',
      content: `**🚨 Trade Alert:** ${message}`
    };

    const data = JSON.stringify(alertData);

    const options = {
      hostname: webhookUrlObj.hostname,
      path: webhookUrlObj.pathname + webhookUrlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    };

    const req = https.request(options, (res) => {
      if (res.statusCode === 204) {
        console.log('✅ Discord alert sent successfully!');
      } else {
        let responseData = '';
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        res.on('end', () => {
          console.error(`❌ Failed to send Discord alert. Status Code: ${res.statusCode}`, responseData);
        });
      }
    });

    req.on('error', (error) => {
      console.error('❌ Error sending Discord alert:', error);
    });

    req.write(data);
    req.end();
  } catch (error) {
    console.error('❌ Error preparing Discord alert:', error);
  }
}

module.exports = { sendDiscordAlert };