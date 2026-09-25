import base64, http.client, json, os, secrets, sqlite3, subprocess, tarfile, threading, time, urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT=os.environ.get('CONFIG_DIR','/config'); DB=os.path.join(ROOT,'backup.db'); CFG=os.path.join(ROOT,'config.json'); STORE=os.environ.get('BACKUP_DIR','/backups')
os.makedirs(ROOT,exist_ok=True); os.makedirs(STORE,exist_ok=True)
DEFAULT={'source':'/data','remote_url':'','remote_path':'/115-backups','username':'','password':'','encryption_password':'','schedule':'02:00','enabled':False,'keep_local':False}
lock=threading.Lock()
PART_BYTES=1024*1024*1024

def load():
    try:
        with open(CFG) as f: return {**DEFAULT,**json.load(f)}
    except Exception: return DEFAULT.copy()
def save(c):
    tmp=CFG+'.tmp'
    with open(tmp,'w') as f: json.dump(c,f,ensure_ascii=False,indent=2)
    os.chmod(tmp,0o600); os.replace(tmp,CFG)
def db():
    c=sqlite3.connect(DB); c.execute('create table if not exists runs(id integer primary key, started text, finished text, status text, message text, archive text, kind text)'); c.commit(); return c
def log_run(status,msg='',archive='',kind='incremental',rid=None):
    c=db(); now=datetime.now().isoformat(timespec='seconds')
    if rid: c.execute('update runs set finished=?,status=?,message=?,archive=? where id=?',(now,status,msg,archive,rid))
    else: rid=c.execute('insert into runs(started,status,message,archive,kind) values(?,?,?,?,?)',(now,'running','',archive,kind)).lastrowid
    c.commit(); c.close(); return rid
def update_progress(rid,msg):
    c=db(); c.execute('update runs set message=? where id=?',(msg,rid)); c.commit(); c.close()
    print(msg,flush=True)
def runs():
    c=db(); rows=c.execute('select id,started,finished,status,message,archive,kind from runs order by id desc limit 30').fetchall(); c.close(); return rows

def dav_put(url, local, user, password):
    u=urllib.parse.urlsplit(url); conn=(http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection)(u.hostname,u.port,timeout=120)
    path=urllib.parse.quote(u.path or '/',safe='/%'); auth=base64.b64encode((user+':'+password).encode()).decode(); size=os.path.getsize(local)
    conn.request('PUT',path,open(local,'rb'),{'Content-Length':str(size),'Authorization':'Basic '+auth,'Content-Type':'application/octet-stream'})
    r=conn.getresponse(); data=r.read(200); conn.close()
    if r.status not in (200,201,204): raise RuntimeError('WebDAV 上传失败: HTTP %s %s'%(r.status,data.decode(errors='ignore')))
def remote_url(c,name): return c['remote_url'].rstrip('/')+'/'+c['remote_path'].strip('/')+'/'+urllib.parse.quote(name)

def human_size(size):
    return f'{size/(1024**3):.2f} GiB'

class ChunkWriter:
    def __init__(self,prefix): self.prefix=prefix; self.parts=[]; self.file=None; self.size=0
    def write(self,data):
        data=memoryview(data); total=len(data)
        while data:
            if self.file is None or self.size==PART_BYTES:
                if self.file: self.file.close()
                path=f'{self.prefix}.part{len(self.parts):04d}'
                self.file=open(path,'wb'); self.parts.append(path); self.size=0
            count=min(len(data),PART_BYTES-self.size)
            self.file.write(data[:count]); self.size+=count; data=data[count:]
        return total
    def flush(self):
        if self.file: self.file.flush()
    def close(self):
        if self.file: self.file.close(); self.file=None

class ProgressReader:
    def __init__(self,source,callback): self.source=source; self.callback=callback; self.bytes=0
    def read(self,size=-1):
        data=self.source.read(size)
        if data: self.bytes+=len(data); self.callback(self.bytes)
        return data

def make_parts(changed,prefix,password,rid,total_bytes,overall_done=0,overall_total=None,batch_number=1,full_run=False):
    writer=ChunkWriter(prefix); errors=[]
    done=0; total_files=len(changed)
    last_report=[0,time.monotonic()]
    def report(msg,force=False):
        now=time.monotonic()
        if force or now-last_report[1]>=2:
            update_progress(rid,msg); last_report[:]=[0,now]
    def add_files(archive):
        nonlocal done
        for index,(path,rel) in enumerate(changed,1):
            info=archive.gettarinfo(path,arcname=rel); size=os.path.getsize(path)
            def progress(read_bytes):
                now=time.monotonic()
                if read_bytes-last_report[0]>=16*1024*1024 or now-last_report[1]>=3:
                    total=min(total_bytes,done+read_bytes); overall=overall_done+total; pct=int(overall*100/max(overall_total or total_bytes,1))
                    prefix=f'全量第 {batch_number} 包；' if full_run else ''
                    report(f'{prefix}正在压缩加密：{index}/{total_files} 个文件，本包 {human_size(total)} / {human_size(total_bytes)}；总进度 {human_size(overall)} / {human_size(overall_total or total_bytes)}（{pct}%）',True)
            if info.isfile():
                with open(path,'rb') as source: archive.addfile(info,ProgressReader(source,progress))
            else: archive.addfile(info)
            done+=size
            overall=overall_done+min(done,total_bytes); pct=int(overall*100/max(overall_total or total_bytes,1)); prefix=f'全量第 {batch_number} 包；' if full_run else ''
            report(f'{prefix}已处理 {index}/{total_files} 个文件，本包 {human_size(min(done,total_bytes))} / {human_size(total_bytes)}；总进度 {human_size(overall)} / {human_size(overall_total or total_bytes)}（{pct}%）',index==total_files)
    if password:
        env={**os.environ,'BACKUP_PASSPHRASE':password}
        proc=subprocess.Popen(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-salt','-pass','env:BACKUP_PASSPHRASE'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        def collect():
            try:
                while block:=proc.stdout.read(1024*1024): writer.write(block)
            except Exception as e: errors.append(e)
            finally: writer.close()
        reader=threading.Thread(target=collect); reader.start()
        try:
            with tarfile.open(fileobj=proc.stdin,mode='w|gz') as archive:
                add_files(archive)
        finally: proc.stdin.close()
        reader.join(); code=proc.wait(); detail=proc.stderr.read().decode(errors='replace')
        if errors: raise errors[0]
        if code: raise RuntimeError('加密失败: '+detail)
    else:
        try:
            with tarfile.open(fileobj=writer,mode='w|gz') as archive:
                add_files(archive)
        finally: writer.close()
    return writer.parts

def backup():
    if not lock.acquire(blocking=False): return
    c=load(); source=c['source']; manifest_path=os.path.join(STORE,'manifest.json'); kind='full' if not os.path.exists(manifest_path) else 'incremental'; rid=log_run('running',kind=kind)
    try:
        if not os.path.isdir(source): raise RuntimeError('源目录不存在: '+source)
        old={}
        if os.path.exists(manifest_path):
            with open(manifest_path) as f: old=json.load(f)
        current={}; sizes={}
        changed=[]; scanned=0; last_report=time.monotonic(); pending_estimate=0
        update_progress(rid,'正在扫描源目录并统计待备份数据…')
        for base,dirs,files in os.walk(source):
            dirs.sort(); files.sort()
            for fn in files:
                p=os.path.join(base,fn); rel=os.path.relpath(p,source); st=os.stat(p); sig=f'{st.st_size}:{st.st_mtime_ns}'
                current[rel]=sig; sizes[rel]=st.st_size
                if not old or old.get(rel)!=sig:
                    changed.append((p,rel)); pending_estimate+=st.st_size
                scanned+=1
                if scanned%1000==0 or time.monotonic()-last_report>=3:
                    update_progress(rid,f'正在扫描：已检查 {scanned} 个文件，待备份约 {human_size(pending_estimate)}')
                    last_report=time.monotonic()
        if not changed: log_run('success','没有检测到变更','',rid=rid); return
        pending_bytes=sum(sizes[rel] for _,rel in changed)
        full_run=not bool(old)
        if not full_run and pending_bytes<PART_BYTES:
            log_run('waiting',f'待备份新增/变更数据 {human_size(pending_bytes)}，达到 1.00 GiB 后打包；定时扫描会继续累计','',rid=rid); return
        remaining=changed[:]; overall_done=0; batch_number=0; completed_parts=0; final_name=''
        while remaining:
            batch=[]; batch_bytes=0
            for item in remaining:
                if batch and batch_bytes>=PART_BYTES: break
                batch.append(item); batch_bytes+=sizes[item[1]]
            batch_number+=1; kind='full' if full_run else 'incremental'; stamp=datetime.now().strftime('%Y%m%d-%H%M%S'); token=secrets.token_hex(3)
            name=f'{kind}-{stamp}-{token}.tar.gz'+('.enc' if c['encryption_password'] else ''); final_name=name
            prefix=f'全量第 {batch_number} 包；' if full_run else ''
            update_progress(rid,f'{prefix}发现待备份 {human_size(pending_bytes-overall_done)}；本包处理 {len(batch)} 个文件，源数据 {human_size(batch_bytes)}')
            parts=make_parts(batch,os.path.join(STORE,name),c['encryption_password'],rid,batch_bytes,overall_done,pending_bytes,batch_number,full_run)
            if c['remote_url']:
                for index,part in enumerate(parts,1):
                    update_progress(rid,f'{prefix}总进度 {human_size(overall_done)} / {human_size(pending_bytes)}；正在上传分卷 {index}/{len(parts)}：{os.path.getsize(part)/(1024**2):.0f} MiB')
                    dav_put(remote_url(c,os.path.basename(part)),part,c['username'],c['password'])
            updated=old.copy()
            for rel in list(updated):
                if rel not in current: updated.pop(rel)
            for _,rel in batch: updated[rel]=current[rel]
            tmp=manifest_path+'.tmp'
            with open(tmp,'w') as f: json.dump(updated,f)
            os.replace(tmp,manifest_path); old=updated
            if c['remote_url'] and not c['keep_local']:
                for part in parts: os.remove(part)
            overall_done+=batch_bytes; completed_parts+=len(parts)
            remaining=remaining[len(batch):]
            if full_run and remaining:
                update_progress(rid,f'全量已完成 {human_size(overall_done)} / {human_size(pending_bytes)}；开始第 {batch_number+1} 个 1 GiB 包')
            elif not full_run:
                break
        log_run('success',f'{"首轮全量" if full_run else "增量备份"}完成：{batch_number} 个归档批次，{completed_parts} 个分卷，已处理 {human_size(overall_done)}',final_name,rid=rid)
    except Exception as e: log_run('failed',str(e),rid=rid)
    finally: lock.release()

def scheduler():
    last=''
    while True:
        c=load(); now=datetime.now(); key=now.strftime('%Y-%m-%d %H:%M')
        if c['enabled'] and now.strftime('%H:%M')==c['schedule'] and key!=last:
            last=key; threading.Thread(target=backup,daemon=True).start()
        time.sleep(20)

HTML='''<!doctype html><meta charset="utf-8"><title>飞牛 115 备份</title><style>body{font:15px system-ui;max-width:900px;margin:30px auto;background:#f5f7fb;color:#1f2937}main{background:white;padding:26px;border-radius:14px;box-shadow:0 2px 12px #ccd}label{display:block;margin:12px 0}input{padding:9px;width:100%;box-sizing:border-box;border:1px solid #ccd;border-radius:7px}button{padding:10px 18px;border:0;border-radius:7px;background:#2563eb;color:white;cursor:pointer}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:8px;border-bottom:1px solid #eee;text-align:left}.ok{color:green}.bad{color:#b91c1c}.wait{color:#9a6700}#live{padding:12px;background:#eef4ff;border-radius:8px;margin:12px 0}#live progress{display:block;width:100%;height:16px;margin-top:8px}</style><main><h1>飞牛 NAS · 115 备份</h1><p>定时扫描新增和变更内容，累计达到 1 GiB 后打包加密并上传；首次全量也按约 1 GiB 源数据逐包处理，单个大文件单独成包。压缩加密分卷不超过 1 GiB。</p><form method="post" action="/save"><label>源目录（容器内路径）<input name="source" value="{source}"></label><div class="grid"><label>115 WebDAV URL<input name="remote_url" placeholder="https://..." value="{remote_url}"></label><label>远端目录<input name="remote_path" value="{remote_path}"></label><label>WebDAV 用户名<input name="username" value="{username}"></label><label>WebDAV 密码<input type="password" name="password" value="{password}"></label><label>归档加密密码<input type="password" name="encryption_password" value="{encryption_password}"></label><label>每日执行时间<input name="schedule" pattern="[0-2][0-9]:[0-5][0-9]" value="{schedule}"></label></div><label><input style="width:auto" type="checkbox" name="enabled" {enabled}> 启用定时备份</label><label><input style="width:auto" type="checkbox" name="keep_local" {keep_local}> 上传后保留本地归档</label><button>保存配置</button> <button formaction="/run" formmethod="post">立即备份</button></form><h2>实时进度</h2><div id="live"><span id="liveText">正在加载任务状态…</span><progress id="liveBar"></progress></div><h2>最近任务</h2><table><tr><th>开始</th><th>类型</th><th>状态</th><th>信息</th><th>归档</th></tr>{rows}</table></main>'''
def esc(x): return str(x).replace('&','&amp;').replace('<','&lt;').replace('"','&quot;')
class Handler(BaseHTTPRequestHandler):
    def send(self,code,body): self.send_response(code); self.send_header('Content-Type','text/html;charset=utf-8'); self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        if self.path=='/progress':
            data=[{'id':r[0],'status':r[3],'message':r[4],'archive':r[5],'kind':r[6]} for r in runs()]
            body=json.dumps(data,ensure_ascii=False).encode(); self.send_response(200); self.send_header('Content-Type','application/json;charset=utf-8'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(body); return
        c=load(); rr=''.join(f'<tr><td>{esc(r[1])}</td><td>{esc(r[6])}</td><td class="{"ok" if r[3]=="success" else "wait" if r[3]=="waiting" else "bad"}">{esc(r[3])}</td><td>{esc(r[4])}</td><td>{esc(r[5])}</td></tr>' for r in runs())
        vals={k:esc(v) for k,v in c.items()}; vals['enabled']='checked' if c['enabled'] else ''; vals['keep_local']='checked' if c['keep_local'] else ''; vals['rows']=rr
        page=HTML
        for k,v in vals.items(): page=page.replace('{'+k+'}',str(v))
        page+='''<script>async function poll(){try{const items=await fetch('/progress',{cache:'no-store'}).then(r=>r.json());if(!items.length)return;const x=items[0],text=document.getElementById('liveText'),bar=document.getElementById('liveBar');text.textContent=(x.status==='running'?'运行中：':x.status+'：')+(x.message||'');const m=(x.message||'').match(/（([0-9]+)%）/);if(m){bar.value=Number(m[1]);bar.max=100}else{bar.removeAttribute('value')} }catch(e){}}poll();setInterval(poll,2000)</script>'''
        self.send(200,page)
    def do_POST(self):
        n=int(self.headers.get('Content-Length',0)); q=urllib.parse.parse_qs(self.rfile.read(n).decode()); c=load()
        for k in DEFAULT:
            if k in q: c[k]=q[k][0]
        c['enabled']='enabled' in q; c['keep_local']='keep_local' in q; save(c)
        if self.path=='/run': threading.Thread(target=backup,daemon=True).start()
        self.send_response(303); self.send_header('Location','/'); self.end_headers()
if __name__=='__main__': db(); threading.Thread(target=scheduler,daemon=True).start(); ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
