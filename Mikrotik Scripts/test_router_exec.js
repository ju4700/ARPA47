const https = require('https');

const body = JSON.stringify({
  router: 'earth',
  command: '/ip/firewall/filter/print',
  args: ['?chain=forward']
});

const options = {
  hostname: 'monitor.linkupbd.online',
  path: '/api/router/exec',
  method: 'POST',
  headers: {
    'Authorization': 'Bearer Linkup_Secure_Cron_Key_2026_XyZ',
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body)
  }
};

const req = https.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => data += chunk);
  res.on('end', () => {
    console.log('Status:', res.statusCode);
    try {
      const parsed = JSON.parse(data);
      if (parsed.result) {
        // Print forward chain rules in a readable way
        const rules = parsed.result;
        console.log(`\nTotal forward chain rules: ${rules.length}\n`);
        rules.forEach((r, i) => {
          console.log(`[${i}] .id=${r['.id']} | action=${r.action} | src=${r['src-address'] || '-'} | dst=${r['dst-address'] || '-'} | disabled=${r.disabled || 'false'} | comment=${r.comment || '-'}`);
        });
      } else {
        console.log(data);
      }
    } catch(e) {
      console.log(data);
    }
  });
});

req.on('error', (e) => console.error('Error:', e.message));
req.write(body);
req.end();
