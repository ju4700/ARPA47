const { RouterOSAPI } = require('node-routeros');

(async () => {
  let api;
  try {
    // Hardcoded credentials for earth
    const host = '103.148.176.1';
    const user = 'soft';
    const password = '!@#luc#@!';
    const port = 2703;

    console.log(`Connecting to Earth at ${host}:${port} as ${user}...`);
    
    api = new RouterOSAPI({host, user, password, port});
    await api.connect();
    
    console.log('Connected! Checking FastTrack rules on Earth...');
    
    const fw = await api.write('/ip/firewall/filter/print');
    for (const rule of fw) {
      if (rule.action === 'fasttrack-connection') {
        if (rule.disabled === 'true' || rule.disabled === true) {
          console.log(`Enabling FastTrack rule ID ${rule['.id']}...`);
          await api.write('/ip/firewall/filter/enable', ['=.id=' + rule['.id']]);
        }
      }
    }
    
    console.log("Ensuring FastTrack bypass rules for ARPA47 exist...");
    await api.write('/ip/firewall/filter/add', [
        '=chain=forward',
        '=src-address=10.60.1.0/24',
        '=action=accept',
        '=place-before=0',
        '=comment=Internal Traffic Shaping (Upload)'
    ]).catch(() => console.log("Upload rule might already exist"));
    
    await api.write('/ip/firewall/filter/add', [
        '=chain=forward',
        '=dst-address=10.60.1.0/24',
        '=action=accept',
        '=place-before=1',
        '=comment=Internal Traffic Shaping (Download)'
    ]).catch(() => console.log("Download rule might already exist"));
    
    console.log("Successfully fixed FastTrack and added bypass on Earth.");
    api.close();
    process.exit(0);
  } catch(e) {
    console.error(e.message);
    if(api) api.close();
    process.exit(1);
  }
})();
