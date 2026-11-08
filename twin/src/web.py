"""The Scenario Control page and its small HTTP API (port 8080)."""
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from engine import Engine, setup_logging
from settings import LOG_DIR


def make_handler(engine):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _allowed(self):
            """Optional protection: set TWIN_UI_PASSWORD (and TWIN_UI_USER) to ask a login."""
            pwd = os.environ.get("TWIN_UI_PASSWORD")
            if not pwd:
                return True
            import base64
            want = base64.b64encode(f"{os.environ.get('TWIN_UI_USER', 'twin')}:{pwd}".encode()).decode()
            if self.headers.get("Authorization", "") == "Basic " + want:
                return True
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Chicago Twin"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def do_GET(self):
            if not self._allowed():
                return
            path = urlparse(self.path).path
            if path == "/":
                self._send(200, UI_HTML, "text/html")
            elif path == "/api/status":
                self._send(200, json.dumps(engine.status()))
            elif path == "/api/logfiles":
                files = []
                if os.path.isdir(LOG_DIR):
                    for n in os.listdir(LOG_DIR):
                        p = os.path.join(LOG_DIR, n)
                        if n.endswith(".log") and not n.startswith("session-") and os.path.isfile(p):
                            files.append({"name": n, "size": os.path.getsize(p), "m": os.path.getmtime(p)})
                files.sort(key=lambda f: -f["m"])
                self._send(200, json.dumps(files[:50]))
            elif path.startswith("/logs/"):
                name = os.path.basename(path[6:])
                p = os.path.join(LOG_DIR, name)
                if name.endswith(".log") and os.path.isfile(p):
                    with open(p, "rb") as fh:
                        self._send(200, fh.read(), "text/plain")
                else:
                    self._send(404, json.dumps({"error": "not found"}))
            else:
                self._send(404, json.dumps({"error": "not found"}))

        def do_POST(self):
            if not self._allowed():
                return
            u = urlparse(self.path)
            if u.path == "/api/start":
                name = (parse_qs(u.query).get("scenario") or [""])[0]
                ok, info = engine.start(name)
                self._send(200 if ok else 409, json.dumps({"ok": ok, "error": None if ok else info}))
            elif u.path == "/api/brain":
                on = (parse_qs(u.query).get("on") or ["1"])[0] == "1"
                engine.set_brain(on)
                self._send(200, json.dumps({"ok": True, "mock_brain": on}))
            elif u.path == "/api/stop":
                self._send(200, json.dumps({"ok": engine.stop()}))
            else:
                self._send(404, json.dumps({"error": "not found"}))
    return Handler


def cmd_serve(conf, secrets, port, host):
    os.makedirs(LOG_DIR, exist_ok=True)
    setup_logging(os.path.join(LOG_DIR, f"session-{datetime.now():%Y%m%d-%H%M%S}.log"))
    engine = Engine(conf, secrets)
    engine.begin()
    server = ThreadingHTTPServer((host, port), make_handler(engine))
    print(f"Scenario Control: http://{'localhost' if host == '127.0.0.1' else host}:{port}   (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        engine.stop_flag.set()
        server.server_close()


UI_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chicago Operations Centre - Scenario Control</title>
<style>
:root{--bg:#eef2f7;--panel:#fff;--tx:#14202e;--mut:#5d6b7e;--line:#d9e0ea;--blue:#1f6fd1;--sky:#41b6e6;--red:#d6232f;--ok:#1f9d55;--warn:#e8890c;--crit:#d6232f;--navy:#0e2a47}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.4 system-ui,Segoe UI,Roboto,sans-serif}
.top{background:var(--navy);color:#fff;display:flex;flex-wrap:wrap;align-items:center;gap:14px;padding:10px 18px;border-bottom:4px solid var(--sky)}
.brand{font-weight:800;letter-spacing:1px;font-size:17px}
.brand .st{color:var(--red);letter-spacing:3px;margin-left:8px;text-shadow:0 0 0 #fff}
.brand small{display:block;font-weight:400;color:#9fb6d0;letter-spacing:.4px;font-size:11px}
.nav{display:flex;gap:4px;flex-wrap:wrap}
.nav button,.nav a{background:transparent;border:1px solid transparent;color:#c9d8ea;padding:7px 14px;border-radius:7px;font:inherit;cursor:pointer;text-decoration:none}
.nav button:hover,.nav a:hover{border-color:#3a5a80;color:#fff}
.nav button.on{background:var(--sky);color:#06223a;font-weight:700}
.sp{flex:1}
.chips{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.chip{background:#16395e;border-radius:8px;padding:4px 10px;text-align:center;min-width:64px}
.chip b{display:block;font-size:18px;line-height:1.1}.chip span{font-size:10px;color:#9fb6d0;text-transform:uppercase;letter-spacing:.6px}
.pill{display:inline-block;padding:4px 14px;border-radius:999px;font-weight:800;color:#fff;letter-spacing:.5px}
.NORMAL{background:var(--ok)}.WARNING{background:var(--warn)}.CRITICAL{background:var(--crit)}
.layout{display:grid;grid-template-columns:270px minmax(0,1fr) 340px;gap:14px;padding:14px 18px}
.layout.camsonly{grid-template-columns:minmax(0,1fr)}.layout.camsonly aside{display:none}
.layout.camsonly .cams{grid-template-columns:repeat(auto-fit,minmax(460px,1fr))}
@media(max-width:1100px){.layout{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:14px;box-shadow:0 1px 2px rgba(20,40,70,.05)}
.panel h2{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:1.2px;color:var(--mut)}
.launch{display:flex;flex-direction:column;gap:8px}
.card{border:1px solid var(--line);border-left:5px solid var(--blue);background:#f8fafd;border-radius:9px;padding:9px 11px;text-align:left;color:var(--tx);cursor:pointer;font:inherit}
.card:hover{background:#eef5ff;border-color:var(--blue)}
.card[disabled]{opacity:.45;cursor:not-allowed}
.card .z{font-size:11px;font-weight:800;letter-spacing:1px}
.card .t{font-size:15px;font-weight:700}
.card .d{color:var(--mut);font-size:12px;margin-top:2px}
.card.A{border-left-color:var(--blue)}.card.A .z{color:var(--blue)}
.card.B{border-left-color:var(--red)}.card.B .z{color:var(--red)}
.card.C{border-left-color:var(--ok)}.card.C .z{color:var(--ok)}
.card.G{border-left-color:#7048e8}.card.G .z{color:#7048e8}
.btn{background:var(--red);border:0;color:#fff;border-radius:8px;padding:9px 14px;font:inherit;font-weight:700;cursor:pointer;width:100%}
.bar{height:6px;background:#e3e9f1;border-radius:4px;margin-top:8px;overflow:hidden}.bar i{display:block;height:100%;background:var(--sky);width:0;transition:width .5s}
.small{font-size:12px;color:var(--mut)}
.cams{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.cam{background:#0b1522;border:3px solid #0b1522;border-radius:12px;overflow:hidden;position:relative}
.cam.w1{border-color:var(--warn)}.cam.w2{border-color:var(--crit);animation:pulse 1s infinite}
@keyframes pulse{50%{box-shadow:0 0 0 4px rgba(214,35,47,.35)}}
.cam canvas{display:block;width:100%;height:auto}
.cam .cap{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;background:#fff;color:var(--tx)}
.cam .cap b{font-size:13px}.cam .cap .pill{font-size:12px;padding:2px 10px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:5px 6px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
th{color:var(--mut);font-size:11px;text-transform:uppercase}
.sev{padding:1px 9px;border-radius:999px;font-size:11px;font-weight:800;color:#fff}.sev.warning{background:var(--warn)}.sev.critical{background:var(--crit)}
.empty{color:var(--mut)}
#tl{max-height:300px;overflow:auto;font:12px/1.4 ui-monospace,Consolas,monospace}
#tl div{padding:3px 0;border-bottom:1px dashed var(--line)}
.tg{display:inline-block;min-width:66px;text-align:center;border-radius:4px;padding:0 5px;margin:0 6px;font-size:10px;font-weight:800;color:#fff}
.t-SCENARIO{background:#7048e8}.t-TWIN{background:var(--blue)}.t-ALERT{background:var(--warn)}.t-BRAIN{background:var(--ok)}.t-EFFECT{background:#0ca678}.t-ERROR{background:var(--red)}
.view{display:none;padding:14px 18px}.view.on{display:block}
a.file{color:var(--blue);text-decoration:none}
#map{width:100%;height:auto;border-radius:8px;display:block}
.acts{display:flex;flex-wrap:wrap;gap:6px}
.act{background:#f1f5fa;border:1px solid var(--line);border-radius:8px;padding:4px 8px;font-size:12px}
.act b{display:block;font-size:11px;color:var(--mut)}
@keyframes fl{50%{opacity:.45}}.fl{animation:fl .6s infinite}
#wblocks{display:none}
.wb{background:#fff;color:#14202e;text-align:center;padding:14px 10px;height:100%}
.wb .lab{font-size:15px;letter-spacing:1.5px;color:#5d6b7e;text-transform:uppercase}
.wb .big{font-size:58px;font-weight:800;line-height:1.1;margin:4px 0}
.wb .sub{font-size:17px;color:#14202e}.wb .upd{font-size:13px;color:#5d6b7e;margin-top:4px}
.g{color:#1f9d55}.o{color:#e8890c}.r{color:#d6232f}.n{color:#868e96}
.hrow{display:flex;justify-content:space-around;margin-top:6px}.hrow div{flex:1}
.hrow .num{font-size:58px;font-weight:800;line-height:1.1}.hrow .cap{font-size:14px;letter-spacing:1.4px;color:#5d6b7e}
.conn{width:100%;border-collapse:collapse;font-size:16px}.conn td{padding:4px 8px;border:0}
.conn .pl{padding:1px 12px;border-radius:999px;color:#fff;font-weight:800;font-size:13px}
body.wid{background:#fff}body.wid #wblocks{display:block}
body.wid .top,body.wid .nav{display:none}
body.wid .layout{display:block!important;padding:0!important}
body.wid .panel{border:0;box-shadow:none;margin:0;border-radius:0;padding:8px}
body.wid .cams{grid-template-columns:1fr!important;gap:0}
body.wid .cam{border-radius:0}
body.wid #tl{max-height:none}
</style></head><body>
<div class="top">
  <div class="brand">CHICAGO<span class="st">&#10038; &#10038; &#10038; &#10038;</span><small>Twin Operations Centre - simulated live data</small></div>
  <div class="nav" id="nav">
    <button class="on" data-m="main">Scenario Control</button>
    <button data-m="cams">Cameras</button>
    <button data-m="log">Event log</button>
    <a id="opsdash" href="#" target="_blank" rel="noopener">Operations dashboard &#8599;</a>
  </div>
  <span class="sp"></span>
  <div class="chips">
    <span id="st" class="pill NORMAL">-</span>
    <div class="chip"><b id="kn">-</b><span>Normal</span></div>
    <div class="chip"><b id="kw" style="color:#ffc069">-</b><span>Warning</span></div>
    <div class="chip"><b id="kc" style="color:#ff8787">-</b><span>Critical</span></div>
    <div class="chip"><b id="ko">-</b><span>Offline</span></div>
    <div class="chip"><b id="ka">-</b><span>Alerts</span></div>
    <div class="chip"><b id="kt">-</b><span>Telemetry</span></div>
  </div>
</div>

<div class="layout" id="layout">
  <aside>
    <div class="panel" data-w="control"><h2>Launch a scenario</h2>
      <div class="launch" id="cards"></div>
      <div style="margin-top:12px"><button class="btn" id="stop">Reset all - return sensors to normal</button></div>
      <label class="small" style="display:flex;gap:8px;align-items:flex-start;margin-top:12px"><input type="checkbox" id="brain" checked style="margin-top:2px"><span><b>Mock Brain acts automatically</b><br>Turn off to let your real Brain, or the dashboard buttons, command the alarm, lights and units.</span></label>
      <div id="run" class="small" style="margin-top:10px"></div>
      <div id="msg" class="small" style="margin-top:6px;min-height:16px"></div>
    </div>
  </aside>
  <section>
    <div class="cams">
      <div class="cam" id="m1" data-w="cam1"><canvas id="c1" width="420" height="250"></canvas><div class="cap"><b>Zone A - Intersection (roads 1 and 2)</b><span id="b1" class="pill NORMAL">NORMAL</span></div></div>
      <div class="cam" id="m2" data-w="cam2"><canvas id="c2" width="420" height="250"></canvas><div class="cap"><b>Zone A - Road 3 (second camera)</b><span id="b2" class="pill NORMAL">NORMAL</span></div></div>
      <div class="cam" id="m3" data-w="cam3"><canvas id="c3" width="420" height="250"></canvas><div class="cap"><b>Zone B - Building (fire)</b><span id="b3" class="pill NORMAL">NORMAL</span></div></div>
      <div class="cam" id="m4" data-w="cam4"><canvas id="c4" width="420" height="250"></canvas><div class="cap"><b>Zone C - Collection point (waste)</b><span id="b4" class="pill NORMAL">NORMAL</span></div></div>
    </div>
  </section>
  <aside>
    <div class="panel" data-w="map"><h2>City map - where it happens</h2><svg id="map" viewBox="0 0 400 290"></svg></div>
    <div class="panel" data-w="alerts"><h2>Active alerts</h2><div id="alerts"></div></div>
    <div class="panel" data-w="actuators"><h2>Brain commands (actuators)</h2><div class="acts" id="act"></div></div>
    <div class="panel" data-w="timeline"><h2>Live timeline</h2><div id="tl"></div></div>
  </aside>
</div>

<div id="wblocks">
  <div class="wb" data-w="status"><div class="lab">Chicago &middot; city status</div><div class="big" id="ws-big">-</div><div class="sub" id="ws-sub"></div><div class="upd" id="ws-upd"></div></div>
  <div class="wb" data-w="health"><div class="hrow">
    <div><div class="num g" id="wh-n">-</div><div class="cap">NORMAL</div></div>
    <div><div class="num o" id="wh-w">-</div><div class="cap">WARNING</div></div>
    <div><div class="num r" id="wh-c">-</div><div class="cap">CRITICAL</div></div>
    <div><div class="num n" id="wh-o">-</div><div class="cap">OFFLINE</div></div></div>
    <div class="upd" id="wh-f"></div></div>
  <div class="wb" data-w="emergency"><div class="lab">Emergency status</div><div class="big" style="font-size:34px" id="we-t">-</div></div>
  <div class="wb" data-w="connectivity" style="text-align:left"><table class="conn" id="wc-t"></table></div>
</div>
<div class="view" id="v-log">
  <div class="panel"><h2>Event log - newest first</h2><div id="logtab"></div></div>
  <div class="panel"><h2>Scenario log files (one per run, saved in the logs folder)</h2><div id="files" class="small"></div></div>
</div>

<script>
const $=id=>document.getElementById(id);
let busy=false,last=null,built=false;
function el(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e}
async function api(path,method){const r=await fetch(path,{method:method||'GET'});return r.json()}
async function start(id){const r=await api('api/start?scenario='+id,'POST');$('msg').textContent=r.ok?'Started':(r.error||'refused');refresh()}
$('brain').onchange=async()=>{await api('api/brain?on='+($('brain').checked?1:0),'POST')};
$('stop').onclick=async()=>{const r=await api('api/stop','POST');$('msg').textContent=r.ok?'Everything returned to normal':(r.error||'');refresh()};
function fmt(v){return(v===null||v===undefined||v==='')?'-':String(v)}
const LIST=['us-a-traf-01','us-a-traf-02','us-a-traf-03'];
function raw(id){return(last&&last.raw&&last.raw[id])||{}}
function mode(id){return(last&&last.modes&&last.modes[id])||'normal'}
function sevFor(ids){let w=0;(last&&last.alerts||[]).forEach(a=>{if(ids.some(i=>a.where.includes(i)))w=Math.max(w,a.severity==='critical'?2:1)});return w}
const NAMES=['NORMAL','WARNING','CRITICAL'];
function badge(b,card,w){$(b).textContent=NAMES[w];$(b).className='pill '+NAMES[w];$(card).className='cam'+(w?' w'+w:'')}
function buildCards(list){
  const c=$('cards');c.textContent='';
  list.forEach(s=>{const k=s.zone.includes('A')?'A':s.zone.includes('B')?'B':s.zone.includes('C')?'C':'G';
    const b=el('button','card '+k);b.append(el('div','z',s.zone),el('div','t',s.title),el('div','d',s.description));
    b.onclick=()=>start(s.id);c.append(b)});built=true}

const WMODE=new URLSearchParams(location.search).get('w');
function applyWidgetMode(){
  if(!WMODE)return;document.body.classList.add('wid');
  const t=document.querySelector('[data-w="'+WMODE+'"]');if(!t)return;
  let n=t;while(n&&n!==document.body){[...n.parentNode.children].forEach(c=>{if(c!==n&&c.tagName!=='SCRIPT')c.style.setProperty('display','none','important')});n=n.parentNode}
}
function fillBlocks(s){
  const c=s.city||{},st=c.cityStatus||'n/a',col={NORMAL:'g',WARNING:'o',CRITICAL:'r'}[st]||'n';
  const big=$('ws-big');big.textContent=st;big.className='big '+col;
  const dv=s.devices||[],on=dv.filter(d=>d.online).length;
  const nw=c.devicesWarning||0,nc=c.devicesCritical||0;
  $('ws-sub').textContent=st==='NORMAL'?('All systems normal \u00b7 '+on+'/'+dv.length+' devices online'):((nc?nc+' critical ':'')+(nw?nw+' warning ':'')+'\u00b7 '+on+'/'+dv.length+' devices online');
  $('ws-upd').textContent='updated '+new Date().toLocaleTimeString('en-GB',{timeZone:'America/Chicago'})+' (Chicago)';
  $('wh-n').textContent=fmt(c.devicesNormal);$('wh-w').textContent=fmt(c.devicesWarning);$('wh-c').textContent=fmt(c.devicesCritical);$('wh-o').textContent=fmt(c.devicesOffline);
  const ns=dv.filter(d=>d.kind==='sensor').length,na=dv.filter(d=>d.kind==='actuator').length;
  $('wh-f').textContent=dv.length+' devices: '+ns+' sensors \u00b7 '+na+' actuators \u00b7 3 zones \u00b7 4 cameras';
  const em=c.emergencyStatus||'-',e=$('we-t');e.textContent=em;e.className='big '+(em.indexOf('No active')===0?'g':'r');e.style.fontSize='34px';
  const t=$('wc-t');t.textContent='';
  dv.forEach(d=>{const r=el('tr');const td=el('td');const w=d.level==='offline'?'OFFLINE':d.level.toUpperCase();
    const p=el('span','pl',w==='NORMAL'?'NORMAL':w);p.style.background={NORMAL:'#1f9d55',WARNING:'#e8890c',CRITICAL:'#d6232f',OFFLINE:'#868e96'}[w];td.append(p);
    r.append(td,el('td',null,d.name),el('td',null,d.kind),el('td',null,'NGSI '+(d.online?'\u2713':'\u2717')),el('td',null,'\u26a1 mains'));t.append(r)});
}
function render(s){
  last=s;fillBlocks(s);if(!built)buildCards(s.scenarios);
  const c=s.city||{};
  $('st').textContent=c.cityStatus||'n/a';$('st').className='pill '+(c.cityStatus||'NORMAL');
  $('kn').textContent=fmt(c.devicesNormal);$('kw').textContent=fmt(c.devicesWarning);$('kc').textContent=fmt(c.devicesCritical);
  $('ko').textContent=fmt(c.devicesOffline);$('ka').textContent=fmt(c.activeAlerts);
  $('kt').textContent=s.telemetryAge===null?'-':Math.round(s.telemetryAge)+' s';
  document.querySelectorAll('.card').forEach(b=>b.disabled=!!s.scenario);
  const sc=s.scenario;
  $('run').textContent=sc?('Running: '+sc.title+' - '+Math.round(sc.elapsed)+' s. '+(sc.resolved?'Incident resolved, recovering.':'It continues until the incident is resolved or you press Reset.')):'No scenario running. The city publishes normal data.';
  if(document.activeElement!==$('brain'))$('brain').checked=!!s.mock_brain;
  const al=$('alerts');al.textContent='';
  if(!s.alerts.length)al.append(el('div','empty','No active alert.'));
  else{const t=el('table');const h=el('tr');['Severity','Alert','Where','Since'].forEach(x=>h.append(el('th',null,x)));t.append(h);
    s.alerts.forEach(a=>{const r=el('tr');const td=el('td');td.append(el('span','sev '+a.severity,a.severity.toUpperCase()));r.append(td,el('td',null,a.type),el('td',null,a.where),el('td',null,a.since));t.append(r)});al.append(t)}
  const ac=$('act');ac.textContent='';
  s.actuators.forEach(a=>{const d=el('div','act');d.append(el('b',null,a.id.replace('us-','')),document.createTextNode(a.text.replace(/,/g,' ')));ac.append(d)});
  const tl=$('tl');tl.textContent='';
  s.events.slice(-30).reverse().forEach(e=>{const d=el('div');d.append(el('span',null,e.t),el('span','tg t-'+e.tag,e.tag),el('span',null,e.msg));tl.append(d)});
  const od=$('opsdash');
  if(s.dashboard_url){od.href=s.dashboard_url;od.onclick=null}else{od.href='#';od.onclick=e=>{e.preventDefault();alert('Set ui.dashboard_url in config.json to the address of your Chicago Operations Centre dashboard.')}}
  badge('b1','m1',sevFor(['us-a-traf-01','us-a-traf-02','us-a-light','us-a-sign']));
  badge('b2','m2',sevFor(['us-a-traf-03']));
  badge('b3','m3',sevFor(['us-b-']));
  badge('b4','m4',sevFor(['us-c-']));
  drawMap();renderLog();
}
function renderLog(){
  if(!$('v-log').classList.contains('on')||!last)return;
  const d=$('logtab');d.textContent='';
  const t=el('table');const h=el('tr');['Time','Layer','Event'].forEach(x=>h.append(el('th',null,x)));t.append(h);
  last.events.slice().reverse().forEach(e=>{const r=el('tr');const td=el('td');td.append(el('span','tg t-'+e.tag,e.tag));r.append(el('td',null,e.t),td,el('td',null,e.msg));t.append(r)});
  d.append(t)}
async function loadFiles(){
  const f=await api('api/logfiles');const d=$('files');d.textContent='';
  if(!f.length){d.textContent='No log file yet. Launch a scenario.';return}
  f.forEach(x=>{const a=el('a','file',x.name);a.href='logs/'+encodeURIComponent(x.name);a.target='_blank';const row=el('div');row.append(a,el('span',null,'  '+x.size+' bytes'));d.append(row)})}
document.querySelectorAll('#nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#nav button').forEach(x=>x.classList.toggle('on',x===b));
  const m=b.dataset.m;$('layout').style.display=m==='log'?'none':'grid';
  $('layout').classList.toggle('camsonly',m==='cams');
  $('v-log').classList.toggle('on',m==='log');
  if(m==='log'){loadFiles();renderLog()}});

/* ---------------- city map ---------------- */
const POS={'us-a-traf-01':[55,122,'c'],'us-a-traf-02':[165,122,'c'],'us-a-traf-03':[232,165,'c'],
 'us-a-light-01':[98,111,'s'],'us-a-light-03':[122,133,'s'],'us-a-sign-01':[140,108,'s'],
 'us-b-bldg-01':[300,215,'c'],'us-b-alarm-01':[282,198,'s'],'us-b-disp-01':[348,238,'s'],
 'us-c-cam-01':[95,212,'c'],'us-c-bin-01':[78,228,'c'],'us-c-bin-02':[112,228,'c'],'us-c-task-01':[135,240,'s']};
function dotColor(id){const w=sevFor([id]);return w===2?'#d6232f':w===1?'#e8890c':'#1f9d55'}
function drawMap(){
  let g='<rect width="400" height="290" fill="#e8eef5"/>';
  g+='<path d="M0,58 C110,86 210,40 400,70" stroke="#a9d3f5" stroke-width="16" fill="none"/>';
  [120,190].forEach(y=>g+=`<rect x="0" y="${y-6}" width="400" height="12" fill="#cfd8e4"/><line x1="0" y1="${y}" x2="400" y2="${y}" stroke="#fff" stroke-dasharray="8 7"/>`);
  [110,232,320].forEach(x=>g+=`<rect x="${x-6}" y="0" width="12" height="290" fill="#cfd8e4"/><line x1="${x}" y1="0" x2="${x}" y2="290" stroke="#fff" stroke-dasharray="8 7"/>`);
  [[20,135,70,45],[130,135,80,45],[245,135,60,45],[335,135,50,45],[20,205,60,70],[245,205,60,70],[335,205,50,70],[130,205,90,70],[130,10,80,30],[245,10,60,30],[335,10,50,30]].forEach(b=>g+=`<rect x="${b[0]}" y="${b[1]}" width="${b[2]}" height="${b[3]}" rx="4" fill="#d3dce9"/>`);
  g+='<text x="168" y="16" font-size="9" fill="#5d6b7e">Chicago River</text>';
  // zones
  const Z=[['A',110,120,'#1f6fd1'],['B',300,215,'#d6232f'],['C',95,225,'#1f9d55']];
  Z.forEach(z=>g+=`<circle cx="${z[1]}" cy="${z[2]}" r="34" fill="${z[3]}" fill-opacity=".08" stroke="${z[3]}" stroke-dasharray="4 3"/><circle cx="${z[1]-30}" cy="${z[2]-30}" r="9" fill="${z[3]}"/><text x="${z[1]-30}" y="${z[2]-26}" font-size="10" font-weight="700" fill="#fff" text-anchor="middle">${z[0]}</text>`);
  g+='<rect x="288" y="203" width="24" height="24" rx="3" fill="#6b7a90"/>';
  g+='<rect x="205" y="92" width="30" height="16" rx="3" fill="#0e2a47"/><text x="220" y="103" font-size="7" fill="#fff" text-anchor="middle">OPS</text>';
  // incident overlays
  if(mode('us-a-traf-01')==='jam'||mode('us-a-traf-02')==='jam'){g+='<line x1="30" y1="120" x2="190" y2="120" stroke="#d6232f" stroke-width="7" stroke-opacity=".55"/>'}
  if(mode('us-a-traf-03')==='fake_jam'){g+='<line x1="232" y1="130" x2="232" y2="200" stroke="#7048e8" stroke-width="7" stroke-opacity=".5" stroke-dasharray="5 4"/>'}
  if(mode('us-b-bldg-01')==='fire'){g+='<g class="fl"><polygon points="292,212 300,190 308,212" fill="#ff6b00"/><polygon points="298,212 303,198 309,212" fill="#ffd43b"/></g>'}
  if(mode('us-c-cam-01')==='dump'){g+='<g><circle cx="93" cy="238" r="8" fill="#6b4a2b"/><circle cx="102" cy="241" r="6" fill="#6b4a2b"/></g>'}
  Object.keys(POS).forEach(id=>{const p=POS[id];const col=dotColor(id);
    g+=p[2]==='c'?`<circle cx="${p[0]}" cy="${p[1]}" r="5" fill="${col}" stroke="#fff" stroke-width="1.5"/>`:`<rect x="${p[0]-4}" y="${p[1]-4}" width="8" height="8" fill="${col}" stroke="#fff" stroke-width="1.5"/>`});
  g+='<text x="8" y="284" font-size="8" fill="#5d6b7e">circle = sensor, square = actuator, colour = status</text>';
  $('map').innerHTML=g}

/* ---------------- simulated cameras ---------------- */
const W=420,H=250;let frame=0;
function overlay(g,name){
  g.fillStyle='rgba(0,0,0,.55)';g.fillRect(0,0,W,18);g.fillStyle='#cfe3ff';g.font='10px monospace';g.fillText(name,6,12);
  const ts=new Date().toLocaleString();g.fillText(ts,W-g.measureText(ts).width-6,12);
  g.fillStyle='#e03131';g.beginPath();g.arc(12,H-12,4,0,7);g.fill();g.fillStyle='#fff';g.font='10px monospace';g.fillText('REC',22,H-8);g.fillText('TWIN VMS',W-64,H-8)}
function banner(g,text,col){g.fillStyle=col;g.fillRect(0,24,W,20);g.fillStyle='#fff';g.font='bold 11px monospace';g.fillText(text,8,38)}
const carsA=[[],[]],carsB=[[],[]];
function drawRoad(id,sens,cars,name,showCtl){
  const g=$(id).getContext('2d');
  const d=sens.map(raw);let cong=d.reduce((a,x)=>a+(x.congestionLevel||0),0)/d.length,speed=d.reduce((a,x)=>a+(x.avgSpeed||50),0)/d.length;
  let note='',col='#7048e8';
  sens.forEach(i=>{const m=mode(i);if(m==='fake_jam'){cong=15;speed=50;note='DATA SAYS JAM - CAMERA SEES FREE FLOW (spoofed)'}else if(m==='dead'){note='SENSOR '+i.replace('us-','')+' OFFLINE';col='#c92a2a'}else if(m==='stuck'){note='SENSOR '+i.replace('us-','')+' STUCK';col='#e8590c'}});
  const sk=g.createLinearGradient(0,0,0,110);sk.addColorStop(0,'#223a63');sk.addColorStop(1,'#7e9bc4');g.fillStyle=sk;g.fillRect(0,0,W,110);
  g.fillStyle='#34414f';[[20,50,60,70],[95,30,55,90],[165,55,70,65],[245,25,50,95],[310,45,60,75],[375,35,60,85]].forEach(r=>{g.fillRect(r[0],r[1],r[2],r[3]);g.fillStyle='#ffd866';for(let i=0;i<4;i++)g.fillRect(r[0]+6+(i%2)*22,r[1]+8+Math.floor(i/2)*18,8,8);g.fillStyle='#34414f'});
  g.fillStyle='#3d424b';g.fillRect(0,110,W,140);g.fillStyle='#585f6a';g.fillRect(0,110,W,6);
  g.strokeStyle='#d7dbe0';g.setLineDash([16,14]);g.lineWidth=2;g.beginPath();g.moveTo(0,180);g.lineTo(W,180);g.stroke();g.setLineDash([]);
  const target=4+Math.round(cong/100*8),v0=Math.max(0.2,speed/50*3);
  cars.forEach((lane,li)=>{
    while(lane.length<target/2)lane.push({x:Math.random()*W,c:['#d9480f','#1c7ed6','#2f9e44','#ae3ec9','#f1f3f5'][Math.floor(Math.random()*5)]});
    while(lane.length>Math.ceil(target/2))lane.pop();
    lane.sort((p,q)=>p.x-q.x);
    lane.forEach((c,i)=>{const nx=lane[(i+1)%lane.length];const gap=nx===c?999:((nx.x-c.x+W)%W)-34;const v=Math.min(v0,Math.max(0,gap*0.15));c.x=(c.x+v)%W;
      const y=li?200:140;g.fillStyle=c.c;g.fillRect(c.x,y,32,16);g.fillStyle='#10151c';g.fillRect(c.x+6,y-6,18,7);g.fillStyle=cong>60?'#ff3b3b':'#ffe08a';g.fillRect(c.x+30,y+3,3,4)})});
  if(showCtl){const lt=raw('us-a-light-01');const lc=lt.phase==='green'?'#2fb344':lt.phase==='yellow'?'#f59f00':'#e03131';
    g.fillStyle='#111';g.fillRect(W-30,124,14,34);g.fillStyle=lc;g.beginPath();g.arc(W-23,141,5,0,7);g.fill();
    const sg=raw('us-a-sign-01');if(sg.message){g.fillStyle='#111';g.fillRect(50,88,320,22);g.fillStyle='#ffb000';g.font='bold 12px monospace';g.fillText(String(sg.message).slice(0,42),56,103)}}
  g.fillStyle='#fff';g.font='bold 14px sans-serif';g.fillText(Math.round(speed)+' km/h - congestion '+Math.round(cong)+'%',10,H-26);
  if(note)banner(g,note,col);overlay(g,name)}
const smoke=[];
function drawBuilding(){
  const g=$('c3').getContext('2d');const b=raw('us-b-bldg-01'),al=raw('us-b-alarm-01'),dp=raw('us-b-disp-01'),m=mode('us-b-bldg-01');
  const sm=b.smokeLevel||0,tp=b.temperature||22,fire=(m==='fire');
  g.fillStyle=fire?'#2a1a22':'#1a2b4c';g.fillRect(0,0,W,H);g.fillStyle='#2c3340';g.fillRect(0,200,W,50);
  g.fillStyle='#6a7691';g.fillRect(130,40,160,160);
  for(let r=0;r<4;r++)for(let c=0;c<4;c++){const lit=!(fire&&(r+c)%2===0);g.fillStyle=lit?'#ffd866':'#3a2a1a';g.fillRect(146+c*36,54+r*36,22,22)}
  g.fillStyle='#2b2f38';g.fillRect(195,170,30,30);
  if(fire){const n=Math.min(6,1+Math.floor(sm/60));for(let i=0;i<n;i++){const x=150+i*(120/n)+(frame%7),y=60+((i*37)%90);g.fillStyle=frame%6<3?'#ff6b00':'#ffb000';g.beginPath();g.moveTo(x,y+30);g.lineTo(x+10,y);g.lineTo(x+20,y+30);g.fill()}}
  const want=fire?Math.min(40,sm/6):0;
  while(smoke.length<want)smoke.push({x:150+Math.random()*120,y:60,r:6+Math.random()*10});while(smoke.length>want)smoke.pop();
  smoke.forEach(s=>{s.y-=0.8;s.x+=Math.sin(frame/12+s.y)*0.4;if(s.y<-10)s.y=70;g.fillStyle='rgba(190,190,200,.4)';g.beginPath();g.arc(s.x,s.y,s.r,0,7);g.fill()});
  if(al.alarmState==='on'&&frame%10<5){g.fillStyle='rgba(224,49,49,.22)';g.fillRect(0,0,W,H);g.fillStyle='#e03131';g.beginPath();g.arc(300,45,8,0,7);g.fill()}
  if(dp.status&&dp.status!=='idle'){g.fillStyle='#d9480f';g.fillRect(30+(frame%3),174,70,26);g.fillStyle='#fff';g.fillRect(36,178,14,10);g.fillStyle=frame%8<4?'#4dabf7':'#e03131';g.fillRect(70,169,16,5);
    for(let i=0;i<8;i++){g.strokeStyle='rgba(120,190,255,.85)';g.lineWidth=2;g.beginPath();g.moveTo(100,176);g.quadraticCurveTo(120+(frame*3+i*7)%25,115-(i%3)*8,150+(i*9)%45,95+(i*13)%55);g.stroke()}}
  if(m==='spoof_smoke')banner(g,'SENSOR SAYS smoke '+sm+' ppm - CAMERA SEES NO SMOKE (spoofed)','#7048e8');
  g.fillStyle='#fff';g.font='bold 14px sans-serif';g.fillText('smoke '+sm+' ppm - '+tp+' C - '+(b.occupancyCount||0)+' people',10,H-26);
  overlay(g,'CAM-B-BLDG  LASALLE ST')}
function drawWaste(){
  const g=$('c4').getContext('2d');const cam=raw('us-c-cam-01'),b1=raw('us-c-bin-01'),b2=raw('us-c-bin-02'),tk=raw('us-c-task-01');
  const sk=g.createLinearGradient(0,0,0,120);sk.addColorStop(0,'#223a63');sk.addColorStop(1,'#7e9bc4');g.fillStyle=sk;g.fillRect(0,0,W,120);
  g.fillStyle='#3d424b';g.fillRect(0,120,W,130);g.fillStyle='#585f6a';g.fillRect(0,120,W,8);g.fillStyle='#4f586a';g.fillRect(0,40,420,80);
  [[60,b1.fillLevel||0],[300,b2.fillLevel||0]].forEach(p=>{g.fillStyle='#2b6f4a';g.fillRect(p[0],150,50,60);g.fillStyle='#1e4d35';g.fillRect(p[0]-3,145,56,8);
    const f=p[1]/100;g.fillStyle=f>.9?'#e03131':f>.75?'#f59f00':'#74c0fc';g.fillRect(p[0]+58,150+60*(1-f),6,60*f);g.strokeStyle='#888';g.strokeRect(p[0]+58,150,6,60)});
  if(cam.dumpingDetected){g.fillStyle='#6b4a2b';[[170,200,28],[200,210,22],[225,198,30],[185,190,18]].forEach(q=>{g.beginPath();g.arc(q[0],q[1],q[2],0,7);g.fill()});
    g.strokeStyle=frame%12<6?'#ff3b3b':'#ffb000';g.lineWidth=2;g.strokeRect(140,160,120,70);g.fillStyle='#ff3b3b';g.font='bold 12px monospace';g.fillText('DUMPING DETECTED',146,154)}
  if(tk.taskStatus&&tk.taskStatus!=='none'&&tk.taskStatus!=='done'){const x=(frame*2)%470-60;g.fillStyle='#1c7ed6';g.fillRect(x,170,80,28);g.fillStyle='#fff';g.fillRect(x+6,174,18,12);g.fillStyle='#ffb000';g.fillRect(x+40,165,14,5)}
  g.fillStyle='#fff';g.font='bold 14px sans-serif';g.fillText('bins '+(b1.fillLevel||0)+'% / '+(b2.fillLevel||0)+'% - task: '+(tk.taskStatus||'none'),10,H-26);
  overlay(g,'CAM-C-WASTE  COLLECTION POINT 1')}
setInterval(()=>{frame++;if(!last)return;
  drawRoad('c1',['us-a-traf-01','us-a-traf-02'],carsA,'CAM-A1  MICHIGAN AVE / JACKSON',true);
  drawRoad('c2',['us-a-traf-03'],carsB,'CAM-A2  WABASH AVE / ROAD 3',false);
  drawBuilding();drawWaste()},80);
applyWidgetMode();refresh();
async function refresh(){if(busy)return;busy=true;try{render(await api('api/status'))}catch(e){$('msg').textContent='Twin not reachable'}busy=false}
setInterval(refresh,2000);
</script></body></html>
"""
