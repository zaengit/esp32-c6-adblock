#pragma once
// Compact, dependency-free dashboard served from the ESP32-C6.

const char PAGE[] PROGMEM = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#2c2c2c">
<title>C6 AdBlock</title>
<style>
:root{color-scheme:dark;--bg:#2c2c2c;--panel:#3e3e3e;--panel2:#2c2c2c;--line:#2c2c2c;--text:#f5f5f5;--muted:#f5f5f5}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button{color:var(--text);background:#3e3e3e;border:1px solid #2c2c2c;border-radius:9px;padding:9px 13px;cursor:pointer}
button:hover{background:#2c2c2c;border-color:#3e3e3e}
button:disabled{opacity:1;cursor:wait}
button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid #3e3e3e;outline-offset:2px}
input,select{color:var(--text);background:#2c2c2c;border:1px solid #3e3e3e;border-radius:8px;padding:9px 11px;min-height:39px}
input::file-selector-button{color:var(--text);background:#3e3e3e;border:1px solid #2c2c2c;border-radius:5px;padding:5px 8px}
input::placeholder{color:#f5f5f5}
a,a:visited{color:var(--text)}
.ppu{height:68px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 max(20px,calc((100vw - 1160px)/2));border-bottom:1px solid #3e3e3e;background:var(--bg)}
.llz{display:flex;align-items:center;gap:12px;min-width:0}
.llz strong{display:block;font-size:15px;letter-spacing:.01em}
.llz small{display:block;color:var(--muted);font-size:12px}
.hkt{display:flex;align-items:center;gap:10px}
.tvy{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px}
.tvy.tkw{color:var(--text)}
.vsi{width:min(1160px,100% - 40px);margin:0 auto;padding:34px 0 60px}
.vcp{display:none;margin-bottom:18px;padding:13px 16px;border:1px solid #3e3e3e;background:#2c2c2c;border-radius:12px;color:#f5f5f5}
.rdn{display:grid;grid-template-columns:1.2fr .8fr;gap:24px;align-items:stretch;margin-bottom:22px}
.art{padding:18px 0}
.cjw{margin:0 0 8px;color:var(--text);font-weight:700;font-size:11px;letter-spacing:.14em}
h1{margin:0;font-size:clamp(30px,5vw,48px);line-height:1.08;letter-spacing:-.045em}
.art>p:not(.cjw){max-width:540px;margin:15px 0;color:var(--muted);font-size:15px}
.bef{display:inline-flex;align-items:center;gap:9px;margin-top:9px;padding:8px 12px;background:#3e3e3e;border:1px solid #2c2c2c;border-radius:999px;color:#f5f5f5;font-size:12px}
.kmu{background:var(--panel);border:1px solid var(--line);border-radius:16px}
.wlj{padding:21px 22px;display:flex;flex-direction:column;justify-content:space-between}
.etr{display:flex;align-items:center;gap:12px}
.etr small{color:var(--muted);font-size:10px;font-weight:700;letter-spacing:.13em}
.wlj h2{margin:4px 0 5px;font-size:19px}
.wlj p{margin:0;color:var(--muted);font-size:12px}
.vza{display:flex;gap:9px;margin-top:18px}
.vza select{flex:1;min-width:0}
.vfj{color:var(--text);background:var(--panel2);border-color:var(--line);font-weight:700}
.vfj:hover{background:var(--panel);border-color:var(--line)}
.vsf{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.xpk{padding:17px 18px}
.aig{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px}
.qwh{margin-top:8px;font-size:27px;font-weight:700;letter-spacing:-.035em;font-variant-numeric:tabular-nums}
.npe{margin-top:1px;color:#f5f5f5;font-size:11px}
.qlk{margin:22px 0}
.qdn{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:19px 20px 13px}
.qdn h2{margin:0;font-size:18px;letter-spacing:-.02em}
.qdn p:not(.cjw){margin:4px 0 0;color:var(--muted);font-size:12px}
.ovx{display:inline-flex;align-items:center;gap:7px;padding:6px 9px;border-radius:999px;background:#3e3e3e;border:1px solid #2c2c2c;color:#f5f5f5;font-size:10px;font-weight:800;letter-spacing:.12em}
.rgf{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 20px;padding:11px 0;border-top:1px solid #2c2c2c;border-bottom:1px solid #2c2c2c}
.tik{display:inline-flex;align-items:center;gap:8px;color:#f5f5f5;font-size:12px;cursor:pointer}
.tik input{min-height:0;accent-color:var(--panel)}
.rle{display:flex;align-items:center;gap:12px}
.eue{color:var(--muted);font-size:11px}
.ozx{padding:6px 10px;background:var(--panel);color:var(--muted);font-size:11px}
.osw{padding:0 20px;color:var(--text);font-size:11px}
.aem{padding:4px 20px 10px}
.pgy{display:grid;grid-template-columns:74px minmax(0,1fr) auto;align-items:center;gap:14px;padding:12px 0;border-bottom:1px solid #2c2c2c}
.pgy:last-child{border-bottom:0}
.nos{color:#f5f5f5;font-size:11px;font-variant-numeric:tabular-nums}
.gri{overflow:hidden;color:var(--text);font-size:13px;font-weight:650;text-overflow:ellipsis;white-space:nowrap}
.nxp{margin-top:3px;color:var(--muted);font-size:11px}
.isd{padding:4px 8px;border-radius:999px;background:#2c2c2c;color:#f5f5f5;font-size:10px;white-space:nowrap}
.isd.ktp{background:#3e3e3e;color:#f5f5f5}
.isd.frz{background:#3e3e3e;color:#f5f5f5}
.isd.dvl{background:#2c2c2c;color:#f5f5f5}
.pwe{padding:26px 10px;text-align:center;color:var(--muted);font-size:12px}
.bpn{margin:0;padding:0 20px 16px;color:#f5f5f5;font-size:11px}
.vhl{display:grid;grid-template-columns:1.1fr .9fr;gap:16px}
.plh{overflow:hidden}
.plh .qdn{padding-bottom:15px}
.awd{overflow:auto}
table{width:100%;border-collapse:collapse;white-space:nowrap}
th,td{padding:10px 16px;text-align:left;border-top:1px solid #2c2c2c;font-size:12px}
th{color:#f5f5f5;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
td{color:#f5f5f5}
.oug{font-variant-numeric:tabular-nums}
.lea,.mou{color:var(--text)}
.wis{display:inline-block;margin-left:6px;padding:2px 6px;border-radius:5px;background:#2c2c2c;color:#f5f5f5;font-size:9px;font-weight:800}
.dzi{padding:5px 8px;font-size:10px}
.vtc{display:flex;gap:8px;padding:0 18px 14px}
.vtc input{flex:1;min-width:0}
.njv{padding:8px 18px 18px;color:var(--muted);font-size:12px}
.nee{margin-top:22px}
.uxr{margin:0 0 12px;color:var(--muted);font-size:11px;font-weight:800;letter-spacing:.14em}
.ymv{padding:0 18px 17px;border-top:1px solid #2c2c2c}
.fam{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-top:14px}
.fam input[type=text],.fam input[type=url]{min-width:220px;flex:1}
.fva{margin:8px 0 0;color:var(--muted);font-size:11px}
.cjc{max-width:100%;font-size:11px}
.gnd{color:var(--muted);font-size:11px}
.dwe{margin-top:27px;color:#f5f5f5;text-align:center;font-size:11px}
@media(max-width:760px){.ppu{height:62px;padding:0 16px}.vsi{width:calc(100% - 28px);padding-top:22px}.rdn{grid-template-columns:1fr;gap:13px}.art{padding:7px 0}.art>p:not(.cjw){margin:10px 0}.wlj{padding:17px}.vsf{grid-template-columns:repeat(2,1fr);gap:9px}.xpk{padding:14px}.qwh{font-size:23px}.vhl{grid-template-columns:1fr}.qdn{padding:16px}.rgf{margin:0 16px}.aem{padding-right:16px;padding-left:16px}.osw,.bpn{padding-right:16px;padding-left:16px}.tvy span:last-child{display:none}}
@media(max-width:420px){.ppu{padding:0 12px}.llz{gap:8px}.hkt{gap:7px}.hkt button{padding:7px 9px;font-size:11px}.pgy{grid-template-columns:52px minmax(0,1fr);gap:8px}.pgy .isd{grid-column:2;justify-self:start}.rgf{align-items:flex-start;flex-direction:column}.rle{width:100%;justify-content:space-between}.vza{flex-wrap:wrap}.vza select{min-width:100%}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
</style>
</head>
<body>
<header class="ppu">
  <div class="llz"><div><strong>C6 AdBlock</strong><small id="host">Connecting to device…</small></div></div>
  <div class="hkt">
    <div class="tvy" id="connection"><span id="connection-label">Connecting</span></div>
    <button id="refresh" type="button">Refresh</button>
  </div>
</header>
<main class="vsi">
  <div id="credwarn" class="vcp"><b>Default credentials are active.</b> Set real WEB_PASS and OTA_PASS values in secrets.h before using this device on a trusted network.</div>

  <section class="rdn">
    <div class="art">
      <p class="cjw">YOUR NETWORK, QUIETER</p>
      <h1>Less noise.<br>More control.</h1>
      <p>DNS filtering for your home network, running locally on this ESP32-C6.</p>
      <div class="bef"><span id="hero-status">Filtering is active</span></div>
    </div>
    <article class="kmu wlj" id="blockbar">
      <div>
        <div class="etr"><div><small>DNS FILTER</small><h2 id="blockstate">Blocking active</h2></div></div>
        <p id="control-copy">Blocked requests receive a local sinkhole response.</p>
      </div>
      <div class="vza">
        <select id="pausedur" aria-label="Pause duration"><option value="30">30 seconds</option><option value="300" selected>5 minutes</option><option value="1800">30 minutes</option><option value="0">Until resumed</option></select>
        <button id="pausebtn" class="vfj" type="button">Pause filtering</button>
      </div>
    </article>
  </section>

  <section class="vsf" aria-label="Network summary">
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

  <section class="kmu qlk" id="activity">
    <div class="qdn">
      <div><p class="cjw">LIVE ACTIVITY</p><h2>Blocked requests</h2><p>Recent domains stopped by the filter or a client rule.</p></div>
      <span class="ovx">LIVE</span>
    </div>
    <div class="rgf">
      <label class="tik"><input id="save-logs" type="checkbox"> Save on this browser</label>
      <div class="rle"><span class="eue" id="log-count">No saved events</span><button class="ozx" id="clear-logs" type="button">Clear history</button></div>
    </div>
    <div class="osw" id="log-note" role="status"></div>
    <div class="pwe" id="log-empty">Waiting for a blocked request…</div>
    <div class="aem" id="log-list" aria-live="polite"></div>
    <p class="bpn">The device keeps the latest 12 events in RAM. This browser can keep up to 200 received events in localStorage; no event log is written to device flash.</p>
  </section>

  <section class="vhl qlk">
    <article class="kmu plh">
      <div class="qdn"><div><p class="cjw">DEVICES</p><h2>Network clients</h2><p>Request totals seen by the DNS filter.</p></div></div>
      <div class="awd"><table id="ct"><thead><tr><th>Client</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody><tr><td colspan="4" class="pwe">No clients yet</td></tr></tbody></table></div>
    </article>
    <article class="kmu plh">
      <div class="qdn"><div><p class="cjw">RULES</p><h2>Custom blocked domains</h2><p>Block a domain and its subdomains.</p></div></div>
      <form class="vtc" id="domain-form"><input id="dom" placeholder="ads.example.com" autocomplete="off" aria-label="Domain to block"><button class="vfj" type="submit">Add rule</button></form>
      <div id="custom-empty" class="njv">No custom domains yet.</div>
      <div class="awd"><table id="cl"><tbody></tbody></table></div>
    </article>
  </section>

  <section class="nee">
    <p class="uxr">DEVICE MANAGEMENT</p>
    <div class="vhl">
      <article class="kmu plh">
        <div class="qdn"><div><h2>Blocklist updates</h2><p>Upload a blocklist or set its automatic update source.</p></div><span class="gnd" id="ustat">Not configured</span></div>
        <div class="ymv">
          <form id="upf" class="fam"><input type="file" id="blf" accept=".bin" class="cjc" aria-label="Blocklist file"><button type="submit">Upload blocklist</button><span id="upmsg" class="gnd"></span></form>
          <p class="fva">Build blocklist.bin with tools/build_blocklist.py, then upload it here.</p>
          <div class="fam"><input id="uurl" type="url" placeholder="https://host/blocklist.bin" aria-label="Blocklist update URL"><label for="uiv" class="fva">Every</label><input id="uiv" type="number" min="1" value="24" style="width:76px"><span class="fva">hours</span><button id="save-update" type="button">Save URL</button><button id="fetch-now" type="button">Fetch now</button></div>
          <p class="fva">The device downloads a prebuilt blocklist on this schedule.</p>
        </div>
      </article>
      <article class="kmu plh">
        <div class="qdn"><div><h2>Firmware update</h2><p>Install new firmware over the network.</p></div><span class="gnd">OTA</span></div>
        <div class="ymv">
          <form id="fwf" class="fam"><input type="file" id="fwb" accept=".bin" class="cjc" aria-label="Firmware file"><button type="submit">Flash firmware</button><span id="fwmsg" class="gnd"></span></form>
          <p class="fva">Upload .pio/build/c6/firmware.bin. The device verifies the image and reboots.</p>
        </div>
      </article>
      <article class="kmu plh">
        <div class="qdn"><div><h2>WiFi setup</h2><p>Clear saved credentials and reopen network setup.</p></div></div>
        <div class="ymv">
          <button id="forget-wifi" type="button">Forget WiFi and reopen setup</button>
        </div>
      </article>
    </div>
  </section>
  <footer class="dwe">C6 AdBlock runs on your device. Dashboard updates stay on your local network.</footer>
</main>
<script>
const CSRF_HDRS={'X-Requested-With':'c6-adblock'};
const LOG_KEY='c6adblock.logs.v1',CURSOR_KEY='c6adblock.cursor.v1',BOOT_KEY='c6adblock.boot.v1',SAVE_KEY='c6adblock.save.v1';
const MAX_LOGS=200,RENDER_LOGS=40;
const REASON_CLASS={custom:'frz',client:'dvl',list:'ktp'};
let logs=[],seen=new Set(),cursor=0,boot=0,saveEnabled=false,polling=false,missed=0;
const byId=id=>document.getElementById(id);
const fmt=n=>Number(n||0).toLocaleString();
const safeGet=k=>{try{return localStorage.getItem(k)}catch(_){return null}};
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
  for(const item of logs.slice(-RENDER_LOGS).reverse()){
    const row=document.createElement('article');row.className='pgy';
    const time=document.createElement('time');time.className='nos';time.textContent=new Date(item.receivedAt||Date.now()).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const main=document.createElement('div');
    const domain=document.createElement('div');domain.className='gri';domain.textContent=item.domain||'(unknown domain)';
    const detail=document.createElement('div');detail.className='nxp';detail.textContent=(item.ip||'Unknown client')+' · '+(item.reason==='custom'?'Custom rule':item.reason==='client'?'Banned client':'Blocklist');
    main.append(domain,detail);
    const reason=document.createElement('span');reason.className='isd '+(REASON_CLASS[item.reason]||'ktp');reason.textContent=item.reason==='custom'?'CUSTOM':item.reason==='client'?'CLIENT':'BLOCKLIST';
    row.append(time,main,reason);list.append(row);
  }
}
renderLogs();
if(!saveEnabled)byId('log-note').textContent='New events are not being saved to this browser.';

async function loadStats(){
  try{
    const response=await fetch('/stats.json',{cache:'no-store'});if(!response.ok)throw new Error('offline');
    const s=await response.json();
    byId('connection').classList.add('tkw');byId('connection-label').textContent='Device online';
    byId('host').textContent='http://'+s.ip;
    byId('credwarn').style.display=s.defcreds?'block':'none';
    byId('sblocked').textContent=fmt(s.blocked);byId('sallowed').textContent=fmt(s.allowed);
    byId('sdomains').textContent=fmt(s.domains);byId('sclients').textContent=fmt(s.clients.length);
    byId('srssi').textContent=s.rssi+' dBm';byId('stemp').textContent=s.temp+' °C';
    byId('sheap').textContent=fmt(Math.round(s.heap/1024))+' KB';byId('suptime').textContent=s.uptime;
    const on=s.blocking!==false;
    byId('blockstate').textContent=on?'Blocking active':(s.resumeIn>0?'Paused · resumes in '+s.resumeIn+'s':'Blocking paused');
    byId('hero-status').textContent=on?'Filtering is active':'Filtering is paused';
    byId('control-copy').textContent=on?'Blocked requests receive a local sinkhole response.':'Blocklist filtering is paused; client bans still apply.';
    byId('blockbar').style.borderColor='var(--line)';
    byId('pausebtn').textContent=on?'Pause filtering':'Resume filtering';
    byId('pausebtn').classList.toggle('vfj',on);
    byId('pausedur').style.display=on?'':'none';
    if(document.activeElement!==byId('uurl'))byId('uurl').value=s.upurl||'';
    if(document.activeElement!==byId('uiv'))byId('uiv').value=s.upiv||24;
    byId('ustat').textContent=s.upstat||'Not configured';
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
    if(client.banned){const tag=document.createElement('span');tag.className='wis';tag.textContent='BANNED';name.append(tag)}
    blocked.className='oug mou';blocked.textContent=fmt(client.blocked);
    allowed.className='oug lea';allowed.textContent=fmt(client.allowed);
    const btn=document.createElement('button');btn.type='button';btn.className='dzi eln';btn.dataset.ip=client.ip;btn.textContent=client.banned?'Unban':'Ban';action.append(btn);
  }
}
function renderCustom(domains){
  const body=byId('cl').tBodies[0];body.replaceChildren();
  byId('custom-empty').style.display=domains.length?'none':'block';
  for(const domain of domains){
    const row=body.insertRow(),name=row.insertCell(),action=row.insertCell();name.textContent=domain;
    const btn=document.createElement('button');btn.type='button';btn.className='dzi tvm';btn.dataset.domain=domain;btn.textContent='Remove';action.append(btn);
  }
}
async function pollLogs(){
  if(polling||document.hidden)return;polling=true;
  try{
    const response=await fetch('/events.json?after='+encodeURIComponent(cursor)+'&boot='+encodeURIComponent(boot),{cache:'no-store'});
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
  return fetch(url,Object.assign({},options,{headers,cache:'no-store'}));
}
async function refreshAll(){await Promise.all([loadStats(),pollLogs()])}
byId('refresh').addEventListener('click',refreshAll);
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
byId('save-update').addEventListener('click',async()=>{
  const url='/setupdate?u='+encodeURIComponent(byId('uurl').value.trim())+'&h='+encodeURIComponent(parseInt(byId('uiv').value,10)||24);
  try{const r=await api(url);if(r.ok)await loadStats()}catch(_){byId('ustat').textContent='Could not save URL'}
});
byId('fetch-now').addEventListener('click',async()=>{
  byId('ustat').textContent='Fetching…';
  try{const r=await api('/fetchnow');byId('ustat').textContent=await r.text();await loadStats()}catch(_){byId('ustat').textContent='Fetch failed'}
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
byId('forget-wifi').addEventListener('click',async()=>{
  if(!confirm('Forget saved WiFi and reboot into setup?'))return;
  try{const r=await api('/forgetwifi');alert(await r.text())}catch(_){alert('The device is restarting or unavailable.')}
});

refreshAll();
window.setInterval(()=>{if(!document.hidden)loadStats()},5000);
window.setInterval(pollLogs,2000);
</script>
</body>
</html>)HTML";
