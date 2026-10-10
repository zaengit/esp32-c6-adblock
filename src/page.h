#pragma once
// Compact, dependency-free dashboard served from the ESP32-C6.

const char LOGIN_PAGE[] PROGMEM = R"LOGIN(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#2c2c2c">
<title>Sign in · C6 AdBlock</title>
<style>
:root{color-scheme:dark;--bg:#2c2c2c;--panel:#3e3e3e;--line:#555;--text:#f5f5f5;--muted:#b7bdc5;--accent:#78b8ff;--accent-strong:#3b82f6}
*{box-sizing:border-box}
body{min-height:100vh;margin:0;display:grid;place-items:center;padding:22px;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.login{width:min(420px,100%);padding:30px;background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:0 18px 60px #0003}
.brand{margin:0 0 26px;font-size:14px;font-weight:750;letter-spacing:.02em}
.brand span{display:block;margin-top:3px;color:var(--muted);font-size:12px;font-weight:400;letter-spacing:0}
.eyebrow{margin:0 0 7px;color:var(--accent);font-size:10px;font-weight:800;letter-spacing:.15em}
h1{margin:0;font-size:27px;letter-spacing:-.035em}
.intro{margin:7px 0 22px;color:var(--muted);font-size:13px}
label{display:block;margin:14px 0 6px;font-size:12px;font-weight:650}
input{width:100%;min-height:43px;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--text);font:inherit}
input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button{width:100%;margin-top:20px;padding:11px 14px;border:1px solid var(--accent);border-radius:9px;background:var(--accent);color:#08111e;font:inherit;font-weight:750;cursor:pointer}
button:hover{background:var(--accent-strong);border-color:var(--accent-strong)}
button:disabled{opacity:.65;cursor:wait}
#login-message{min-height:20px;margin:12px 0 0;color:#fbbf24;font-size:12px}
</style>
</head>
<body>
<main class="login">
  <p class="brand">C6 AdBlock<span>Local DNS filtering dashboard</span></p>
  <p class="eyebrow">DEVICE ACCESS</p>
  <h1>Sign in</h1>
  <p class="intro">Enter the username and password configured for this device.</p>
  <form id="login-form">
    <label for="login-user">Username</label>
    <input id="login-user" name="username" type="text" autocomplete="username" required>
    <label for="login-pass">Password</label>
    <input id="login-pass" name="password" type="password" autocomplete="current-password" required>
    <button id="login-button" type="submit">Sign in</button>
    <p id="login-message" role="status" aria-live="polite"></p>
  </form>
</main>
<script>
const form=document.getElementById('login-form'),button=document.getElementById('login-button'),message=document.getElementById('login-message');
form.addEventListener('submit',async event=>{
  event.preventDefault();button.disabled=true;message.textContent='Signing in…';
  const body=new URLSearchParams({username:document.getElementById('login-user').value,password:document.getElementById('login-pass').value});
  try{
    const response=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'c6-adblock'},body:body.toString(),cache:'no-store'});
    if(!response.ok){message.textContent=response.status===401?'Username or password is incorrect.':'Could not sign in. Try again.';button.disabled=false;return}
    window.location.replace('/');
  }catch(_){message.textContent='Could not reach the device. Check the connection and try again.';button.disabled=false}
});
</script>
</body>
</html>)LOGIN";

const char PAGE[] PROGMEM = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#2c2c2c">
<title>C6 AdBlock</title>
<style>
:root{color-scheme:dark;--bg:#2c2c2c;--panel:#3e3e3e;--panel2:#2c2c2c;--line:#2c2c2c;--text:#f5f5f5;--muted:#f5f5f5;--btn-ink:#08111e;--accent:#78b8ff;--accent-strong:#3b82f6;--accent-soft:#1f3851;--accent-line:#365a7a;--success:#4ade80;--success-strong:#22c55e;--success-soft:#173b2d;--success-line:#2b6849;--warning:#fbbf24;--warning-strong:#f59e0b;--warning-soft:#493718;--warning-line:#795c25;--danger:#f87171;--danger-strong:#ef4444;--danger-soft:#48232a;--danger-line:#713940;--custom:#c4b5fd;--custom-soft:#322c4d;--custom-line:#514579}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button{color:var(--btn-ink);background:var(--accent);border:1px solid var(--accent);border-radius:9px;padding:9px 13px;font-weight:700;cursor:pointer}
button:hover,input::file-selector-button:hover{background:var(--accent-strong);border-color:var(--accent-strong)}
.btn-primary{color:var(--btn-ink);background:var(--accent);border-color:var(--accent)}
.btn-primary:hover{background:var(--accent-strong);border-color:var(--accent-strong)}
.btn-success{color:var(--btn-ink);background:var(--success);border-color:var(--success)}
.btn-success:hover{background:var(--success-strong);border-color:var(--success-strong)}
.btn-warning{color:var(--btn-ink);background:var(--warning);border-color:var(--warning)}
.btn-warning:hover{background:var(--warning-strong);border-color:var(--warning-strong)}
.btn-danger{color:var(--btn-ink);background:var(--danger);border-color:var(--danger)}
.btn-danger:hover{background:var(--danger-strong);border-color:var(--danger-strong)}
.btn-neutral{color:var(--text);background:var(--panel);border-color:var(--line)}
.btn-neutral:hover{background:#555;border-color:#666}
button:disabled{opacity:1;cursor:wait}
button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
input,select{color:var(--text);background:#2c2c2c;border:1px solid #3e3e3e;border-radius:8px;padding:9px 11px;min-height:39px}
input::file-selector-button{color:var(--btn-ink);background:var(--accent);border:1px solid var(--accent);border-radius:9px;padding:5px 8px;font:inherit;font-weight:700}
input::placeholder{color:#9299a2;opacity:1}
a,a:visited{color:var(--accent)}
.ppu{height:68px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 max(24px,calc((100vw - 1240px)/2));border-bottom:1px solid #3e3e3e;background:var(--bg)}
.llz{display:flex;align-items:center;gap:12px;min-width:0}
.llz strong{display:block;font-size:15px;letter-spacing:.01em}
.llz small{display:block;color:var(--muted);font-size:12px}
.hkt{display:flex;align-items:center;gap:10px}
.tvy{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px}
.tvy::before{content:"";width:7px;height:7px;border-radius:50%;background:#8b949e}
.tvy.tkw{color:var(--accent)}
.tvy.tkw::before{background:var(--accent);box-shadow:0 0 0 3px rgba(120,184,255,.15)}
.vsi{width:min(1240px,calc(100% - 48px));margin:0 auto;padding:30px 0 54px}
.page-intro{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin:0 0 20px}
.page-intro h1{margin:0;font-size:clamp(29px,4vw,40px);line-height:1.08;letter-spacing:-.045em}
.page-intro p:not(.cjw){margin:8px 0 0;color:var(--muted);font-size:13px}
.overview-link{display:inline-flex;align-items:center;gap:8px;flex:none;margin-bottom:3px;padding:9px 12px;border:1px solid #555;border-radius:9px;background:transparent;color:var(--accent);font:inherit;font-size:12px;font-weight:700;cursor:pointer}
.overview-link:hover{background:var(--panel);border-color:#666}
.section-tabs{display:flex;align-items:center;gap:3px;width:max-content;max-width:100%;margin:0 0 22px;padding:4px;border:1px solid #3e3e3e;border-radius:12px;background:var(--panel2)}
.section-tabs button{flex:0 0 auto;padding:8px 14px;border-color:transparent;border-radius:8px;background:transparent;color:var(--muted);font-size:12px;font-weight:650;white-space:nowrap}
.section-tabs button:hover{border-color:transparent;background:var(--panel);color:var(--text)}
.section-tabs button[aria-selected=true]{border-color:var(--line);background:var(--panel);color:var(--text)}
.tab-panel{min-width:0}
.tab-panel[hidden]{display:none!important}
.vcp{display:none;margin-bottom:18px;padding:13px 16px;border:1px solid #3e3e3e;background:#2c2c2c;border-radius:12px;color:#f5f5f5}
.cjw{margin:0 0 8px;color:var(--accent);font-weight:700;font-size:11px;letter-spacing:.14em}
h1{margin:0;font-size:clamp(30px,5vw,48px);line-height:1.08;letter-spacing:-.045em}
.kmu{background:var(--panel);border:1px solid var(--line);border-radius:16px}
.wlj{min-height:100%;padding:22px;display:flex;flex-direction:column;justify-content:space-between}
.etr{display:flex;align-items:center;gap:12px}
.etr small{color:var(--muted);font-size:10px;font-weight:700;letter-spacing:.13em}
.wlj h2{margin:5px 0 6px;font-size:20px;letter-spacing:-.025em}
.wlj p{margin:0;color:var(--muted);font-size:12px}
.vza{display:flex;gap:9px;margin-top:22px}
.vza select{flex:1;min-width:0}
.vsf{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:0 0 14px}
.xpk{min-height:126px;padding:18px 19px;display:flex;flex-direction:column;justify-content:space-between}
.aig{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;font-weight:600}
.qwh{margin-top:auto;padding-top:10px;font-size:clamp(24px,2.6vw,31px);font-weight:750;letter-spacing:-.035em;font-variant-numeric:tabular-nums}
.npe{margin-top:1px;color:#f5f5f5;font-size:11px}
.qlk{margin:20px 0}
.operational-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(280px,.8fr);gap:18px;align-items:stretch;margin:22px 0}
.operational-grid .use-guide{margin:0}
.operational-grid .wlj{min-height:100%}
.qdn{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:19px 20px 13px}
.qdn h2{margin:0;font-size:18px;letter-spacing:-.02em}
.qdn p:not(.cjw){margin:4px 0 0;color:var(--muted);font-size:12px}
.badge{display:inline-flex;align-items:center;justify-content:center;padding:4px 8px;border:1px solid transparent;border-radius:999px;font-size:10px;font-weight:800;line-height:1.2;white-space:nowrap}
.badge-info{color:var(--accent);background:var(--accent-soft);border-color:var(--accent-line)}
.badge-success{color:var(--success);background:var(--success-soft);border-color:var(--success-line)}
.badge-warning{color:var(--warning);background:var(--warning-soft);border-color:var(--warning-line)}
.badge-danger{color:var(--danger);background:var(--danger-soft);border-color:var(--danger-line)}
.badge-custom{color:var(--custom);background:var(--custom-soft);border-color:var(--custom-line)}
.badge-neutral{color:var(--muted);background:#343434;border-color:#555}
.ovx{gap:7px;padding:6px 9px;letter-spacing:.12em}
.rgf{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 20px;padding:11px 0;border-top:1px solid #2c2c2c;border-bottom:1px solid #2c2c2c}
.tik{display:inline-flex;align-items:center;gap:8px;color:#f5f5f5;font-size:12px;cursor:pointer}
.tik input{min-height:0;accent-color:var(--accent-strong)}
.rle{display:flex;align-items:center;gap:12px}
.eue{color:var(--muted);font-size:11px}
.ozx{padding:6px 10px;font-size:11px}
.osw{padding:0 20px;color:var(--text);font-size:11px}
.aem{padding:4px 20px 10px}
.log-pages{display:none;justify-content:center;align-items:center;gap:10px;padding:0 16px 15px}
.log-pages button{padding:6px 10px;font-size:11px}
.log-pages button:disabled{opacity:.45;cursor:default}
.log-pages span{min-width:115px;color:var(--muted);font-size:11px;text-align:center;font-variant-numeric:tabular-nums}
.pgy{display:grid;grid-template-columns:74px minmax(0,1fr) auto;align-items:center;gap:14px;padding:12px 0;border-bottom:1px solid #2c2c2c}
.pgy:last-child{border-bottom:0}
.nos{color:#f5f5f5;font-size:11px;font-variant-numeric:tabular-nums}
.gri{overflow:hidden;color:var(--text);font-size:13px;font-weight:650;text-overflow:ellipsis;white-space:nowrap}
.nxp{margin-top:3px;color:var(--muted);font-size:11px}
.isd{padding:4px 8px}
.pwe{padding:26px 10px;text-align:center;color:var(--muted);font-size:12px}
.bpn{margin:0;padding:0 20px 16px;color:#f5f5f5;font-size:11px}
.vhl{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}
.plh{overflow:hidden}
.plh .qdn{padding-bottom:15px}
.awd{overflow:auto}
table{width:100%;border-collapse:collapse;white-space:nowrap}
th,td{padding:10px 16px;text-align:left;border-top:1px solid #2c2c2c;font-size:12px}
th{color:#f5f5f5;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
td{color:#f5f5f5}
.oug{font-variant-numeric:tabular-nums}
.lea{color:var(--text)}
.mou{color:var(--accent)}
.wis{display:inline-flex;margin-left:6px;padding:2px 6px;font-size:9px}
.dzi{padding:5px 8px;font-size:10px}
.vtc{display:flex;gap:8px;padding:0 18px 14px}
.vtc input{flex:1;min-width:0}
.njv{padding:8px 18px 18px;color:var(--muted);font-size:12px}
.nee{margin-top:30px;scroll-margin-top:18px}
.uxr{margin:0 0 12px;color:var(--muted);font-size:11px;font-weight:800;letter-spacing:.14em}
.ymv{padding:0 18px 17px;border-top:1px solid #2c2c2c}
.hotspot-card{grid-column:auto}
#reset-config{margin-top:14px}
.hotspot-summary{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px;padding:0 18px 15px}
.hotspot-summary>div{min-width:0}
.hotspot-summary small{display:block;color:var(--muted);font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.hotspot-summary strong{display:block;overflow-wrap:anywhere;font-size:14px}
.hotspot-enabled{margin-top:14px}
.hotspot-form input[type=text],.hotspot-form input[type=password]{min-width:220px;flex:1}
#hotspot-message{min-height:16px}
.access-label{display:block;margin:8px 0 4px;color:var(--muted);font-size:11px;font-weight:650}
.access-form .fam{margin-top:6px}
.use-guide{margin:22px 0}
.guide-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:0 18px 18px}
.guide-step{min-width:0;padding:15px;border:1px solid #2c2c2c;border-radius:12px;background:#343434}
.guide-step h3{margin:0 0 8px;font-size:14px}
.guide-step ol{margin:0;padding-left:19px;color:var(--muted);font-size:12px}
.guide-step li+li{margin-top:6px}
.guide-values{display:flex;align-items:flex-end;flex-wrap:wrap;gap:14px;margin-top:12px}
.guide-value{display:flex;min-width:0;flex-direction:column;gap:2px}
.guide-value small{color:var(--muted);font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.guide-value strong{overflow-wrap:anywhere;font-size:13px;font-variant-numeric:tabular-nums}
.guide-step-note{margin:10px 0 0;color:var(--muted);font-size:11px}
.guide-link{display:inline-flex;width:fit-content;align-items:center;margin-top:12px;padding:0;border:0;border-radius:0;background:transparent;color:var(--accent);font:inherit;font-size:12px;font-weight:650;text-align:left;text-decoration:underline;cursor:pointer}
.guide-link:hover{border-color:transparent;background:transparent}
.fam{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-top:14px}
.fam input[type=text],.fam input[type=url]{min-width:220px;flex:1}
.fva{margin:8px 0 0;color:var(--muted);font-size:11px}
.cjc{max-width:100%;font-size:11px}
.gnd:not(.badge){color:var(--muted);font-size:11px}
.dwe{margin-top:30px;color:#f5f5f5;text-align:center;font-size:11px}
@media(max-width:1020px){.operational-grid{grid-template-columns:1fr}.wlj{min-height:0}.vza{flex-direction:row}.vza select{min-width:0}}
@media(max-width:760px){.ppu{height:62px;padding:0 16px}.vsi{width:calc(100% - 28px);padding-top:22px}.page-intro{margin-bottom:16px}.section-tabs{width:max-content;max-width:100%;overflow-x:auto}.vsf{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.xpk{min-height:112px;padding:14px}.qwh{font-size:23px}.vhl{grid-template-columns:1fr;gap:13px}.guide-grid{grid-template-columns:1fr;padding-right:12px;padding-left:12px}.qdn{padding:16px}.rgf{margin:0 16px}.aem{padding-right:16px;padding-left:16px}.osw,.bpn{padding-right:16px;padding-left:16px}.tvy span:last-child{display:none}}
@media(max-width:500px){.ppu{padding:0 12px}.llz{gap:8px}.hkt{gap:7px}.hkt button{padding:7px 9px;font-size:11px}.page-intro{align-items:flex-start;flex-direction:column;gap:12px}.page-intro h1{font-size:30px}.section-tabs button{padding:7px 9px;font-size:11px}.operational-grid{gap:13px}.wlj{padding:17px}.vza{align-items:stretch;flex-direction:column}.vza select{min-width:100%}.pgy{grid-template-columns:52px minmax(0,1fr);gap:8px}.pgy .isd{grid-column:2;justify-self:start}.rgf{align-items:flex-start;flex-direction:column}.rle{width:100%;justify-content:space-between}.hotspot-summary{grid-template-columns:1fr 1fr}.hotspot-summary>div:first-child{grid-column:1/-1}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
</style>
</head>
<body>
<header class="ppu">
  <div class="llz"><div><strong>C6 AdBlock</strong><small id="host">Connecting to device…</small></div></div>
  <div class="hkt">
    <div class="tvy" id="connection"><span id="connection-label">Connecting</span></div>
    <button id="logout" class="btn-neutral" type="button">Log out</button>
    <button id="refresh" class="btn-primary" type="button">Refresh</button>
  </div>
</header>
<main class="vsi">
  <div id="credwarn" class="vcp"><b>Default credentials are active.</b> Review the Dashboard login and DNS hotspot credentials in Device Management before using this device on a trusted network.</div>

  <section class="page-intro" aria-labelledby="page-title">
    <div><p class="cjw">C6 NETWORK DASHBOARD</p><h1 id="page-title">Network overview</h1><p>Monitor DNS protection, connected devices, and device health.</p></div>
    <button class="overview-link" type="button" data-open-tab="activity">View live activity <span aria-hidden="true">↓</span></button>
  </section>
  <div class="section-tabs" role="tablist" aria-label="Dashboard sections">
    <button id="tab-overview" type="button" role="tab" aria-selected="true" aria-controls="panel-overview" data-tab="overview">Overview</button>
    <button id="tab-activity" type="button" role="tab" aria-selected="false" aria-controls="panel-activity" data-tab="activity" tabindex="-1">Activity</button>
    <button id="tab-network" type="button" role="tab" aria-selected="false" aria-controls="panel-network" data-tab="network" tabindex="-1">Clients &amp; rules</button>
    <button id="tab-management" type="button" role="tab" aria-selected="false" aria-controls="panel-management" data-tab="management" tabindex="-1">Device management</button>
  </div>

  <div class="tab-panel" id="panel-overview" role="tabpanel" aria-labelledby="tab-overview" tabindex="0">
  <section class="vsf" id="overview" aria-label="Network summary">
    <article class="kmu xpk"><div class="aig">Blocked requests</div><div class="qwh mou" id="sblocked">—</div><div class="npe">Since device boot</div></article>
    <article class="kmu xpk"><div class="aig">Allowed requests</div><div class="qwh lea" id="sallowed">—</div><div class="npe">Forwarded or cached</div></article>
    <article class="kmu xpk"><div class="aig">Blocklist</div><div class="qwh" id="sdomains">—</div><div class="npe">Domains loaded in flash</div></article>
    <article class="kmu xpk"><div class="aig">Clients</div><div class="qwh" id="sclients">—</div><div class="npe">Seen by this device</div></article>
  </section>

  <section class="vsf" aria-label="Device health">
    <article class="kmu xpk"><div class="aig">WiFi</div><div class="qwh" id="srssi">—</div></article>
    <article class="kmu xpk"><div class="aig">Temperature</div><div class="qwh" id="stemp">—</div></article>
    <article class="kmu xpk"><div class="aig">Free RAM</div><div class="qwh" id="sheap">—</div></article>
    <article class="kmu xpk"><div class="aig">Uptime</div><div class="qwh" id="suptime">—</div></article>
  </section>

  <section class="operational-grid" aria-label="Filtering setup">
  <section class="kmu use-guide" aria-labelledby="use-guide-title">
    <div class="qdn"><div><p class="cjw">QUICK SETUP</p><h2 id="use-guide-title">Connect devices to AdBlock</h2><p>Choose how you want devices to use this DNS filter.</p></div></div>
    <div class="guide-grid">
      <article class="guide-step">
        <h3>1. Connect to the C6 hotspot</h3>
        <ol>
          <li>Join the hotspot from your phone, computer, or other device.</li>
          <li>Enter the password configured in DNS hotspot settings.</li>
          <li>Stay connected to use filtered DNS and internet through the ESP32-C6.</li>
        </ol>
        <div class="guide-values" aria-live="polite">
          <div class="guide-value"><small>Hotspot SSID</small><strong id="guide-ap-ssid">—</strong></div>
          <div class="guide-value"><small>Hotspot address</small><strong id="guide-ap-ip">—</strong></div>
          <span class="badge badge-warning" id="guide-ap-status">Loading</span>
        </div>
        <p class="guide-step-note" id="guide-ap-note" role="status">Checking hotspot status…</p>
        <button class="guide-link" type="button" data-open-tab="management" data-focus="hotspot-card">Open DNS hotspot settings</button>
      </article>
      <article class="guide-step">
        <h3>2. Use AdBlock on your router Wi-Fi</h3>
        <ol>
          <li>Keep your devices connected to the usual Wi-Fi network.</li>
          <li>In the router's LAN or DHCP settings, set the DNS address handed out to devices to this ESP32-C6 address:</li>
        </ol>
        <div class="guide-values" aria-live="polite">
          <div class="guide-value"><small>ESP32-C6 Wi-Fi IP</small><strong id="guide-router-ip">—</strong></div>
        </div>
        <p class="guide-step-note" id="guide-router-note" role="status">Checking Wi-Fi connection…</p>
        <button class="guide-link" type="button" data-open-tab="management" data-focus="wifi-card">Open Wi-Fi connection settings</button>
      </article>
    </div>
  </section>

  <article class="kmu wlj" id="blockbar">
    <div>
      <div class="etr"><div><small>DNS FILTER</small><h2 id="blockstate">Blocking active</h2></div></div>
      <p id="control-copy">Blocked requests receive a local sinkhole response.</p>
    </div>
    <div class="vza">
      <select id="pausedur" aria-label="Pause duration"><option value="30">30 seconds</option><option value="300" selected>5 minutes</option><option value="1800">30 minutes</option><option value="0">Until resumed</option></select>
      <button id="pausebtn" class="btn-warning" type="button">Pause filtering</button>
    </div>
  </article>
  </section>
  </div>

  <div class="tab-panel" id="panel-activity" role="tabpanel" aria-labelledby="tab-activity" tabindex="0" hidden>
  <section class="kmu qlk" id="activity">
    <div class="qdn">
      <div><p class="cjw">LIVE ACTIVITY</p><h2>Blocked requests</h2><p>Recent domains stopped by the filter or a client rule.</p></div>
      <span class="ovx badge badge-success">LIVE</span>
    </div>
    <div class="rgf">
      <label class="tik"><input id="save-logs" type="checkbox"> Save on this browser</label>
      <div class="rle"><span class="eue" id="log-count">No saved events</span><button class="ozx btn-danger" id="clear-logs" type="button">Clear history</button></div>
    </div>
    <div class="osw" id="log-note" role="status"></div>
    <div class="pwe" id="log-empty">Waiting for a blocked request…</div>
    <div class="aem" id="log-list" aria-live="polite"></div>
    <nav class="log-pages" id="log-pages" aria-label="Blocked request pages">
      <button class="btn-neutral" id="log-prev" type="button" aria-label="Previous page">Previous</button>
      <span id="log-page-status" role="status">Showing 0–0 of 0</span>
      <button class="btn-neutral" id="log-next" type="button" aria-label="Next page">Next</button>
    </nav>
    <p class="bpn">The device keeps the latest 12 events in RAM. This browser can keep up to 200 received events in localStorage; no event log is written to device flash.</p>
  </section>
  </div>

  <div class="tab-panel" id="panel-network" role="tabpanel" aria-labelledby="tab-network" tabindex="0" hidden>
  <section class="vhl qlk" id="network">
    <article class="kmu plh">
      <div class="qdn"><div><p class="cjw">DEVICES</p><h2>Network clients</h2><p>Request totals seen by the DNS filter.</p></div></div>
      <div class="awd"><table id="ct"><thead><tr><th>Client</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody><tr><td colspan="4" class="pwe">No clients yet</td></tr></tbody></table></div>
    </article>
    <article class="kmu plh">
      <div class="qdn"><div><p class="cjw">RULES</p><h2>Custom blocked domains</h2><p>Block a domain and its subdomains.</p></div></div>
      <form class="vtc" id="domain-form"><input id="dom" placeholder="ads.example.com" autocomplete="off" aria-label="Domain to block"><button class="btn-primary" type="submit">Add rule</button></form>
      <div id="custom-empty" class="njv">No custom domains yet.</div>
      <div class="awd"><table id="cl"><tbody></tbody></table></div>
    </article>
  </section>
  </div>

  <div class="tab-panel" id="panel-management" role="tabpanel" aria-labelledby="tab-management" tabindex="0" hidden>
  <section class="nee" id="management">
    <p class="uxr">DEVICE MANAGEMENT</p>
    <div class="vhl">
      <article class="kmu plh hotspot-card" id="hotspot-card">
        <div class="qdn"><div><h2>DNS hotspot</h2><p>Manage the Wi-Fi network served by this device.</p></div><span class="gnd badge badge-warning" id="hotspot-status">Loading</span></div>
        <div class="hotspot-summary" aria-live="polite">
          <div><small>Network name</small><strong id="hotspot-ssid-value">—</strong></div>
          <div><small>Hotspot address</small><strong id="hotspot-ip">—</strong></div>
          <div><small>Connected devices</small><strong id="hotspot-clients">—</strong></div>
        </div>
        <form id="hotspot-form" class="ymv hotspot-form">
          <label class="tik hotspot-enabled"><input id="hotspot-enabled" type="checkbox"> Enable hotspot</label>
          <div class="fam"><input id="hotspot-ssid" type="text" maxlength="32" required autocomplete="off" placeholder="Hotspot name" aria-label="Hotspot name"></div>
          <p class="fva">The name can be 1–32 bytes.</p>
          <div class="fam"><input id="hotspot-password" type="password" minlength="8" maxlength="63" autocomplete="new-password" placeholder="New password" aria-label="New hotspot password"><button id="save-hotspot" class="btn-primary" type="submit">Save hotspot settings</button></div>
          <p class="fva">Use 8–63 characters. Leave blank to keep the current password. Saving restarts the device; connected hotspot devices will disconnect briefly.</p>
          <p class="gnd" id="hotspot-message" role="status"></p>
        </form>
      </article>
      <article class="kmu plh">
        <div class="qdn"><div><h2>Blocklist updates</h2><p>Upload a blocklist or set its automatic update source.</p></div><span class="gnd badge badge-warning" id="ustat">Not configured</span></div>
        <div class="ymv">
          <form id="upf" class="fam"><input type="file" id="blf" accept=".bin" class="cjc" aria-label="Blocklist file"><button class="btn-primary" type="submit">Upload blocklist</button><span id="upmsg" class="gnd"></span></form>
          <p class="fva">Build blocklist.bin with tools/build_blocklist.py, then upload it here.</p>
          <div class="fam"><input id="uurl" type="url" placeholder="https://host/blocklist.bin" aria-label="Blocklist update URL"><label for="uiv" class="fva">Every</label><input id="uiv" type="number" min="1" value="24" style="width:76px"><span class="fva">hours</span><button id="save-update" class="btn-primary" type="button">Save URL</button><button id="fetch-now" class="btn-primary" type="button">Fetch now</button></div>
          <p class="fva">The device downloads a prebuilt blocklist on this schedule.</p>
        </div>
      </article>
      <article class="kmu plh">
        <div class="qdn"><div><h2>Firmware update</h2><p>Install new firmware over the network.</p></div><span class="gnd badge badge-custom">OTA</span></div>
        <div class="ymv">
          <form id="fwf" class="fam"><input type="file" id="fwb" accept=".bin" class="cjc" aria-label="Firmware file"><button class="btn-warning" type="submit">Flash firmware</button><span id="fwmsg" class="gnd"></span></form>
          <p class="fva">Upload .pio/build/c6/firmware.bin. The device verifies the image and reboots.</p>
        </div>
      </article>
      <article class="kmu plh" id="wifi-card">
        <div class="qdn"><div><h2>Wi-Fi connection</h2><p>Connect this device to a router or access point.</p></div><span class="gnd badge badge-warning" id="wifi-status">Loading</span></div>
        <div class="hotspot-summary" aria-live="polite">
          <div><small>Current network</small><strong id="wifi-ssid">—</strong></div>
          <div><small>Station IP</small><strong id="wifi-ip">—</strong></div>
          <div><small>Signal</small><strong id="wifi-rssi">—</strong></div>
        </div>
        <form id="wifi-form" class="ymv">
          <div class="fam"><input id="wifi-name" type="text" maxlength="32" required autocomplete="off" placeholder="Wi-Fi name (SSID)" aria-label="Wi-Fi name"></div>
          <div class="fam"><input id="wifi-password" type="password" minlength="8" maxlength="63" autocomplete="new-password" placeholder="Wi-Fi password" aria-label="Wi-Fi password"><button class="btn-primary" type="submit">Connect and restart</button></div>
          <p class="fva">Enter the network password, or leave it blank for an open network. If the credentials do not work, the setup access point will reopen.</p>
          <p class="gnd" id="wifi-message" role="status"></p>
        </form>
      </article>
      <article class="kmu plh">
        <div class="qdn"><div><h2>Dashboard login</h2><p>Change the credentials used to open this dashboard.</p></div><span class="badge badge-info">ACCESS</span></div>
        <form id="dashboard-credentials-form" class="ymv access-form">
          <label class="access-label" for="dashboard-username">Username</label>
          <div class="fam"><input id="dashboard-username" type="text" maxlength="32" required autocomplete="username" aria-label="Dashboard username"></div>
          <label class="access-label" for="dashboard-password">New password</label>
          <div class="fam"><input id="dashboard-password" type="password" minlength="8" maxlength="63" autocomplete="new-password" placeholder="New password" aria-label="New dashboard password"><button class="btn-primary" type="submit">Save login settings</button></div>
          <p class="fva">Leave blank to keep the current password. Password is never shown here. Saving signs out all dashboard sessions; sign in again with the updated credentials.</p>
          <p class="gnd" id="dashboard-credentials-message" role="status"></p>
        </form>
      </article>
      <article class="kmu plh">
        <div class="qdn"><div><h2>Reset pabrik firmware</h2><p>Hapus pengaturan tersimpan dan mulai ulang dengan pengaturan bawaan firmware.</p></div><span class="badge badge-danger">RESET</span></div>
        <div class="ymv">
          <p class="fva">Reset ini menghapus Wi-Fi, akun dashboard, pengaturan hotspot, domain kustom, daftar blokir klien, dan jadwal update; firmware serta blocklist tetap ada. Setelah mulai ulang, perangkat menggunakan pengaturan bawaan yang tertanam di firmware.</p>
          <button id="reset-config" class="btn-danger" type="button">Reset pabrik</button>
          <p class="gnd" id="reset-config-message" role="status"></p>
        </div>
      </article>
    </div>
  </section>
  </div>
  <footer class="dwe">C6 AdBlock runs on your device. Dashboard updates stay on your local network.</footer>
</main>
<script>
const CSRF_HDRS={'X-Requested-With':'c6-adblock'};
const LOG_KEY='c6adblock.logs.v1',CURSOR_KEY='c6adblock.cursor.v1',BOOT_KEY='c6adblock.boot.v1',SAVE_KEY='c6adblock.save.v1';
const MAX_LOGS=200,PAGE_SIZE=10;
const REASON_CLASS={custom:'badge-custom',client:'badge-danger',list:'badge-danger'};
let logs=[],seen=new Set(),cursor=0,boot=0,saveEnabled=false,polling=false,missed=0,logPage=1;
let hotspotRunning=false,hotspotEnabled=true,hotspotFormDirty=false,dashboardCredentialsDirty=false,updateConfigDirty=false;
const byId=id=>document.getElementById(id);
const tabButtons=Array.from(document.querySelectorAll('[role="tab"][data-tab]'));
function activateTab(name,moveFocus=false){
  const selected=tabButtons.find(tab=>tab.dataset.tab===name);
  if(!selected)return;
  for(const tab of tabButtons){
    const active=tab===selected;
    tab.setAttribute('aria-selected',String(active));
    tab.tabIndex=active?0:-1;
    const panel=byId(tab.getAttribute('aria-controls'));
    if(panel)panel.hidden=!active;
  }
  if(moveFocus)selected.focus();
}
tabButtons.forEach((tab,index)=>{
  tab.addEventListener('click',()=>activateTab(tab.dataset.tab));
  tab.addEventListener('keydown',event=>{
    let next=index;
    if(event.key==='ArrowRight')next=(index+1)%tabButtons.length;
    else if(event.key==='ArrowLeft')next=(index+tabButtons.length-1)%tabButtons.length;
    else if(event.key==='Home')next=0;
    else if(event.key==='End')next=tabButtons.length-1;
    else return;
    event.preventDefault();
    activateTab(tabButtons[next].dataset.tab,true);
  });
});
document.querySelectorAll('[data-open-tab]').forEach(button=>{
  button.addEventListener('click',()=>{
    activateTab(button.dataset.openTab);
    const target=byId(button.dataset.focus||'');
    if(target){
      const behavior=window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth';
      window.requestAnimationFrame(()=>target.scrollIntoView({behavior,block:'center'}));
    }
  });
});
activateTab('overview');
const fmt=n=>Number(n||0).toLocaleString();
const safeGet=k=>{try{return localStorage.getItem(k)}catch(_){return null}};
function setUpdateStatus(value){
  const status=String(value||'Not configured'),normalized=status.toLowerCase(),element=byId('ustat');
  element.textContent=status;
  element.classList.remove('badge-success','badge-warning','badge-danger','badge-neutral');
  const badge=normalized.startsWith('ok:')?'badge-success':/could not|failed|^http\b|bad data|error/.test(normalized)?'badge-danger':/fetching|no url set|not configured/.test(normalized)?'badge-warning':'badge-neutral';
  element.classList.add(badge);
}
function renderHotspot(hotspot){
  hotspotRunning=hotspot.running===true;
  const enabled=hotspot.enabled===true;
  hotspotEnabled=enabled;
  const status=byId('hotspot-status');
  status.textContent=!enabled?'Disabled':hotspotRunning?'Active':'Not running';
  status.classList.remove('badge-success','badge-warning','badge-danger','badge-neutral');
  status.classList.add(!enabled?'badge-neutral':hotspotRunning?'badge-success':'badge-warning');
  byId('hotspot-ssid-value').textContent=hotspot.ssid||'—';
  byId('hotspot-ip').textContent=hotspotRunning?(hotspot.ip||'—'):'—';
  byId('hotspot-clients').textContent=fmt(hotspot.clients||0);
  if(!hotspotFormDirty){
    byId('hotspot-enabled').checked=enabled;
    byId('hotspot-ssid').value=hotspot.ssid||'';
  }
}
function renderWifi(stats){
  const connected=stats.wifiConnected===true,status=byId('wifi-status');
  status.textContent=connected?'Connected':'Disconnected';
  status.classList.remove('badge-success','badge-warning','badge-danger','badge-neutral');
  status.classList.add(connected?'badge-success':'badge-warning');
  byId('wifi-ssid').textContent=stats.wifiSsid||(connected?'Hidden network':'Not connected');
  byId('wifi-ip').textContent=connected?(stats.ip||'—'):'—';
  byId('wifi-rssi').textContent=connected?stats.rssi+' dBm':'—';
}
function renderDashboardCredentials(stats){
  if(!dashboardCredentialsDirty&&document.activeElement!==byId('dashboard-username'))
    byId('dashboard-username').value=stats.webUser||'';
}
function renderUseGuide(stats){
  const hotspot=stats.hotspot||{},running=hotspot.running===true,enabled=hotspot.enabled===true,connected=stats.wifiConnected===true;
  const apStatus=byId('guide-ap-status');
  byId('guide-ap-ssid').textContent=hotspot.ssid||'—';
  byId('guide-ap-ip').textContent=running?(hotspot.ip||'—'):'—';
  apStatus.textContent=running?'Active':enabled?'Not running':'Disabled';
  apStatus.classList.remove('badge-success','badge-warning','badge-danger','badge-neutral');
  apStatus.classList.add(running?'badge-success':enabled?'badge-warning':'badge-neutral');
  byId('guide-ap-note').textContent=running
    ?'Use the password saved in DNS hotspot settings. The hotspot is ready for devices to join.'
    :enabled?'The hotspot is enabled but not running. Check the Wi-Fi connection below.'
      :'The hotspot is disabled. Enable it in DNS hotspot settings to use this option.';
  byId('guide-router-ip').textContent=connected?(stats.ip||'—'):'Not connected';
  byId('guide-router-note').textContent=connected
    ?'Set this as the DNS address your router hands out to devices. Then reconnect devices or renew their DHCP lease. Reserve the C6 IP in the router so it stays stable.'
    :'Connect the C6 to your router first, then use its station IP here as the DNS server.';
}
function loadLocalLogs(){try{const v=JSON.parse(safeGet(LOG_KEY)||'[]');return Array.isArray(v)?v.slice(-MAX_LOGS):[]}catch(_){return []}}
logs=loadLocalLogs();
for(const item of logs)if(item.key)seen.add(item.key);
cursor=Number(safeGet(CURSOR_KEY))||0;
boot=Number(safeGet(BOOT_KEY))||0;
saveEnabled=safeGet(SAVE_KEY)!=='0';
byId('save-logs').checked=saveEnabled;

function persistStreamState(){try{localStorage.setItem(CURSOR_KEY,String(cursor));localStorage.setItem(BOOT_KEY,String(boot))}catch(_){}}
function persistLogs(){
  if(!saveEnabled)return;
  try{localStorage.setItem(LOG_KEY,JSON.stringify(logs.slice(-MAX_LOGS)));byId('log-note').textContent='Saved privately in this browser.'}
  catch(_){byId('log-note').textContent='Browser storage is full or unavailable; new events are shown for this session only.'}
}
function renderLogs(){
  const list=byId('log-list');list.replaceChildren();
  byId('log-empty').style.display=logs.length?'none':'block';
  byId('log-count').textContent=logs.length?fmt(logs.length)+' event'+(logs.length===1?'':'s')+(saveEnabled?' saved here':' in this session'):'No events saved';
  const pageCount=Math.max(1,Math.ceil(logs.length/PAGE_SIZE));
  logPage=Math.min(logPage,pageCount);
  const firstIndex=(logPage-1)*PAGE_SIZE;
  const pageItems=logs.slice().reverse().slice(firstIndex,firstIndex+PAGE_SIZE);
  byId('log-pages').style.display=pageCount>1?'flex':'none';
  byId('log-page-status').textContent='Showing '+(logs.length?firstIndex+1:0)+'–'+Math.min(firstIndex+PAGE_SIZE,logs.length)+' of '+fmt(logs.length);
  byId('log-prev').disabled=logPage===1;
  byId('log-next').disabled=logPage===pageCount;
  for(const item of pageItems){
    const row=document.createElement('article');row.className='pgy';
    const time=document.createElement('time');time.className='nos';time.textContent=new Date(item.receivedAt||Date.now()).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const main=document.createElement('div');
    const domain=document.createElement('div');domain.className='gri';domain.textContent=item.domain||'(unknown domain)';
    const detail=document.createElement('div');detail.className='nxp';detail.textContent=(item.ip||'Unknown client')+' · '+(item.reason==='custom'?'Custom rule':item.reason==='client'?'Banned client':'Blocklist');
    main.append(domain,detail);
    const reason=document.createElement('span');reason.className='isd badge '+(REASON_CLASS[item.reason]||'badge-info');reason.textContent=item.reason==='custom'?'CUSTOM':item.reason==='client'?'CLIENT':'BLOCKLIST';
    row.append(time,main,reason);list.append(row);
  }
}
byId('log-prev').addEventListener('click',()=>{if(logPage>1){logPage--;renderLogs()}});
byId('log-next').addEventListener('click',()=>{if(logPage<Math.ceil(logs.length/PAGE_SIZE)){logPage++;renderLogs()}});
renderLogs();
if(!saveEnabled)byId('log-note').textContent='New events are not being saved to this browser.';

async function loadStats(){
  try{
    const response=await fetch('/stats.json',{cache:'no-store'});
    if(response.status===401){window.location.replace('/');return}
    if(!response.ok)throw new Error('offline');
    const s=await response.json();
    byId('connection').classList.add('tkw');byId('connection-label').textContent='Device online';
    byId('host').textContent='http://'+s.ip;
    byId('credwarn').style.display=s.defcreds?'block':'none';
    byId('sblocked').textContent=fmt(s.blocked);byId('sallowed').textContent=fmt(s.allowed);
    byId('sdomains').textContent=fmt(s.domains);byId('sclients').textContent=fmt(s.clients.length);
    byId('srssi').textContent=s.rssi+' dBm';byId('stemp').textContent=s.temp+' °C';
    byId('sheap').textContent=fmt(Math.round(s.heap/1024))+' KB';byId('suptime').textContent=s.uptime;
    renderWifi(s);
    renderDashboardCredentials(s);
    renderUseGuide(s);
    const on=s.blocking!==false;
    byId('blockstate').textContent=on?'Blocking active':(s.resumeIn>0?'Paused · resumes in '+s.resumeIn+'s':'Blocking paused');
    byId('control-copy').textContent=on?'Blocked requests receive a local sinkhole response.':'Blocklist filtering is paused; client bans still apply.';
    byId('blockbar').style.borderColor='var(--line)';
    byId('pausebtn').textContent=on?'Pause filtering':'Resume filtering';
    byId('pausebtn').classList.toggle('btn-warning',on);
    byId('pausebtn').classList.toggle('btn-success',!on);
    byId('pausedur').style.display=on?'':'none';
    if(!updateConfigDirty){byId('uurl').value=s.upurl||'';byId('uiv').value=s.upiv||24}
    setUpdateStatus(s.upstat||'Not configured');
    renderHotspot(s.hotspot||{});
    renderClients(s.clients||[]);renderCustom(s.custom||[]);
  }catch(_){
    byId('connection').classList.remove('tkw');byId('connection-label').textContent='Reconnecting';
  }
}
function renderClients(clients){
  const body=byId('ct').tBodies[0];body.replaceChildren();
  if(!clients.length){const row=body.insertRow();const cell=row.insertCell();cell.colSpan=4;cell.className='pwe';cell.textContent='No clients yet';return}
  clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed));
  for(const client of clients){
    const row=body.insertRow(),name=row.insertCell(),blocked=row.insertCell(),allowed=row.insertCell(),action=row.insertCell();
    name.textContent=client.ip;
    if(client.banned){const tag=document.createElement('span');tag.className='wis badge badge-danger';tag.textContent='BANNED';name.append(tag)}
    blocked.className='oug mou';blocked.textContent=fmt(client.blocked);
    allowed.className='oug lea';allowed.textContent=fmt(client.allowed);
    const btn=document.createElement('button');btn.type='button';btn.className='dzi eln '+(client.banned?'btn-success':'btn-danger');btn.dataset.ip=client.ip;btn.textContent=client.banned?'Unban':'Ban';action.append(btn);
  }
}
function renderCustom(domains){
  const body=byId('cl').tBodies[0];body.replaceChildren();
  byId('custom-empty').style.display=domains.length?'none':'block';
  for(const domain of domains){
    const row=body.insertRow(),name=row.insertCell(),action=row.insertCell();name.textContent=domain;
    const btn=document.createElement('button');btn.type='button';btn.className='dzi tvm btn-success';btn.dataset.domain=domain;btn.textContent='Remove';action.append(btn);
  }
}
async function pollLogs(){
  if(polling||document.hidden)return;polling=true;
  try{
    const response=await fetch('/events.json?after='+encodeURIComponent(cursor)+'&boot='+encodeURIComponent(boot),{cache:'no-store'});
    if(response.status===401){window.location.replace('/');return}
    if(!response.ok)throw new Error('offline');
    const data=await response.json();
    if(Number(data.boot)!==boot){boot=Number(data.boot)||0;cursor=0}
    if(data.lost){missed+=Number(data.lost);byId('log-note').textContent=fmt(missed)+' event'+(missed===1?'':'s')+' missed while this browser was not connected; device history is limited to 12.'}
    let added=0;
    for(const event of (data.events||[])){
      const key=String(boot)+':'+String(event.id);if(seen.has(key))continue;
      const item={key:key,id:event.id,domain:event.domain,ip:event.ip,reason:event.reason,deviceAt:event.at,receivedAt:Date.now()};
      logs.push(item);seen.add(key);added++;
    }
    if(logs.length>MAX_LOGS){logs=logs.slice(-MAX_LOGS);seen=new Set(logs.map(item=>item.key))}
    cursor=Number(data.latest)||0;persistStreamState();
    if(added){renderLogs();persistLogs()}
  }catch(_){/* Retry on the next short poll. */}
  finally{polling=false}
}

async function api(url,options={}){
  const headers=Object.assign({},options.headers||{},CSRF_HDRS);
  const response=await fetch(url,Object.assign({},options,{headers,cache:'no-store'}));
  if(response.status===401){window.location.replace('/');throw new Error('login required')}
  return response;
}
async function refreshAll(){await Promise.all([loadStats(),pollLogs()])}
byId('refresh').addEventListener('click',refreshAll);
byId('logout').addEventListener('click',async()=>{
  try{await api('/logout',{method:'POST'})}catch(_){return}
  window.location.replace('/');
});
byId('pausebtn').addEventListener('click',async()=>{
  const paused=byId('pausebtn').textContent.startsWith('Resume');
  const url=paused?'/resume':'/pause?s='+encodeURIComponent(byId('pausedur').value);
  try{const r=await api(url);if(!r.ok)throw new Error();await loadStats()}catch(_){byId('control-copy').textContent='Could not update filtering. Check the device connection.'}
});
byId('domain-form').addEventListener('submit',async event=>{
  event.preventDefault();const input=byId('dom'),domain=input.value.trim();if(!domain)return;
  try{const r=await api('/addblock?d='+encodeURIComponent(domain));if(!r.ok)throw new Error();input.value='';await loadStats()}catch(_){byId('custom-empty').textContent='Could not add rule. Check the device connection.';byId('custom-empty').style.display='block'}
});
byId('ct').addEventListener('click',async event=>{
  const button=event.target.closest('.eln');if(!button)return;
  try{const r=await api('/ban?ip='+encodeURIComponent(button.dataset.ip));if(r.ok)await loadStats()}catch(_){}
});
byId('cl').addEventListener('click',async event=>{
  const button=event.target.closest('.tvm');if(!button)return;
  try{const r=await api('/unblock?d='+encodeURIComponent(button.dataset.domain));if(r.ok)await loadStats()}catch(_){}
});
byId('save-logs').addEventListener('change',event=>{
  saveEnabled=event.target.checked;
  try{localStorage.setItem(SAVE_KEY,saveEnabled?'1':'0')}catch(_){}
  byId('log-note').textContent=saveEnabled?'Saved privately in this browser.':'New events are not being saved to this browser.';
  if(saveEnabled)persistLogs();renderLogs();
});
byId('clear-logs').addEventListener('click',()=>{
  logs=[];seen.clear();try{localStorage.removeItem(LOG_KEY)}catch(_){}
  byId('log-note').textContent='Local history cleared.';renderLogs();
});
byId('uurl').addEventListener('input',()=>{updateConfigDirty=true});
byId('uiv').addEventListener('input',()=>{updateConfigDirty=true});
byId('save-update').addEventListener('click',async()=>{
  const url='/setupdate?u='+encodeURIComponent(byId('uurl').value.trim())+'&h='+encodeURIComponent(parseInt(byId('uiv').value,10)||24);
  try{const r=await api(url);if(!r.ok)throw new Error();updateConfigDirty=false;await loadStats()}catch(_){setUpdateStatus('Could not save URL')}
});
byId('dashboard-username').addEventListener('input',()=>{dashboardCredentialsDirty=true});
byId('dashboard-credentials-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const form=new URLSearchParams();
  form.set('username',byId('dashboard-username').value);
  form.set('password',byId('dashboard-password').value);
  byId('dashboard-credentials-message').textContent='Saving login settings…';
  try{
    const response=await api('/dashboard-credentials',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:form.toString()});
    const message=await response.text();
    if(!response.ok)throw new Error(message||'Could not save login settings');
    byId('dashboard-password').value='';
    byId('dashboard-credentials-message').textContent='Saved. Sign in again with the updated credentials.';
    window.setTimeout(()=>window.location.replace('/'),600);
  }catch(error){
    byId('dashboard-credentials-message').textContent=error.message&&error.message!=='Failed to fetch'?error.message:'Could not save login settings. Check the device connection.';
  }
});
byId('reset-config').addEventListener('click',async()=>{
  const confirmed=confirm('Hapus semua pengaturan tersimpan dan mulai ulang ke pengaturan bawaan firmware? Firmware dan blocklist tetap ada.');
  if(!confirmed)return;
  const button=byId('reset-config');button.disabled=true;
  byId('reset-config-message').textContent='Menghapus pengaturan dan memulai ulang…';
  try{
    const response=await api('/reset-config',{method:'POST'});
    const message=await response.text();
    if(!response.ok)throw new Error(message||'Pengaturan perangkat gagal direset');
    byId('reset-config-message').textContent='Pengaturan tersimpan dihapus. Setelah mulai ulang, perangkat menggunakan pengaturan bawaan firmware.';
    window.setTimeout(()=>window.location.replace('/'),1200);
  }catch(error){
    byId('reset-config-message').textContent=error.message&&error.message!=='Failed to fetch'?error.message:'Perangkat sedang mulai ulang atau tidak dapat dijangkau.';
    button.disabled=false;
  }
});
byId('hotspot-enabled').addEventListener('change',()=>{hotspotFormDirty=true});
['hotspot-ssid','hotspot-password'].forEach(id=>byId(id).addEventListener('input',()=>{hotspotFormDirty=true}));
byId('hotspot-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const enabled=byId('hotspot-enabled').checked;
  if(!enabled&&hotspotEnabled&&!confirm('Disabling the hotspot disconnects devices using it, including this browser if it is connected through the hotspot. Continue?')){
    byId('hotspot-enabled').checked=hotspotEnabled;return;
  }
  const form=new URLSearchParams();
  form.set('ssid',byId('hotspot-ssid').value);
  form.set('password',byId('hotspot-password').value);
  form.set('enabled',enabled?'1':'0');
  byId('hotspot-message').textContent='Saving hotspot settings…';
  try{
    const response=await api('/hotspot',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:form.toString()});
    const message=await response.text();
    if(!response.ok)throw new Error(message||'Could not save hotspot settings');
    byId('hotspot-password').value='';
    byId('hotspot-message').textContent='Saved. The device is restarting; reconnect after it comes back online.';
  }catch(error){
    byId('hotspot-message').textContent=error.message&&error.message!=='Failed to fetch'?error.message:'Connection lost; the device may be restarting. Reconnect and check the hotspot settings.';
  }
});
byId('wifi-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const form=new URLSearchParams();
  form.set('ssid',byId('wifi-name').value);
  form.set('password',byId('wifi-password').value);
  byId('wifi-message').textContent='Saving Wi-Fi credentials…';
  try{
    const response=await api('/wifi',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:form.toString()});
    const message=await response.text();
    if(!response.ok)throw new Error(message||'Could not save Wi-Fi credentials');
    byId('wifi-password').value='';
    byId('wifi-message').textContent='Saved. The device is restarting and will connect to the selected network.';
  }catch(error){
    byId('wifi-message').textContent=error.message&&error.message!=='Failed to fetch'?error.message:'Connection lost; the device may be restarting. Reconnect and check the Wi-Fi settings.';
  }
});
byId('fetch-now').addEventListener('click',async()=>{
  const currentUrl=byId('uurl').value.trim();
  if(updateConfigDirty&&!currentUrl){setUpdateStatus('no url set');return}
  const query=currentUrl?'?u='+encodeURIComponent(currentUrl)+'&h='+encodeURIComponent(parseInt(byId('uiv').value,10)||24):'';
  setUpdateStatus('Fetching…');
  try{const r=await api('/fetchnow'+query);if(!r.ok)throw new Error();const status=await r.text();if(currentUrl)updateConfigDirty=false;setUpdateStatus(status);await loadStats()}catch(_){setUpdateStatus('Fetch failed')}
});
byId('upf').addEventListener('submit',async event=>{
  event.preventDefault();const file=byId('blf').files[0];if(!file)return;
  byId('upmsg').textContent='Uploading '+(file.size/1048576).toFixed(2)+' MB…';
  const form=new FormData();form.append('f',file);
  try{const r=await api('/upload',{method:'POST',body:form});byId('upmsg').textContent=r.ok?'Updated':'Failed: '+await r.text();await loadStats()}catch(_){byId('upmsg').textContent='Upload failed'}
  byId('blf').value='';
});
byId('fwf').addEventListener('submit',async event=>{
  event.preventDefault();const file=byId('fwb').files[0];if(!file)return;
  byId('fwmsg').textContent='Flashing '+(file.size/1048576).toFixed(2)+' MB…';
  const form=new FormData();form.append('f',file);
  try{const r=await api('/update',{method:'POST',body:form});byId('fwmsg').textContent=r.ok?'Rebooting; reconnect in about 15 seconds.':'Failed: '+await r.text()}
  catch(_){byId('fwmsg').textContent='Device is rebooting; reconnect in about 15 seconds.'}
});
refreshAll();
window.setInterval(()=>{if(!document.hidden)loadStats()},5000);
window.setInterval(pollLogs,2000);
</script>
</body>
</html>)HTML";
