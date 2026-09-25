import base64, hashlib, http.client, json, os, posixpath, secrets, shutil, sqlite3, subprocess, tarfile, threading, time, urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT=os.environ.get('CONFIG_DIR','/config'); DB=os.path.join(ROOT,'backup.db'); CFG=os.path.join(ROOT,'config.json'); STORE=os.environ.get('BACKUP_DIR','/backups')
os.makedirs(ROOT,exist_ok=True); os.makedirs(STORE,exist_ok=True)
DEFAULT={'source':'/data','remote_url':'','remote_path':'/115-backups','username':'','password':'','encryption_password':'','schedule':'02:00','enabled':False,'keep_local':False}
lock=threading.Lock()

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
def runs():
    c=db(); rows=c.execute('select id,started,finished,status,message,archive,kind from runs order by id desc limit 30').fetchall(); c.close(); return rows

def dav_put(url, local, user, password):
    u=urllib.parse.urlsplit(url); conn=(http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection)(u.hostname,u.port,timeout=120)
    path=u.path or '/'; auth=base64.b64encode((user+':'+password).encode()).decode(); size=os.path.getsize(local)
    conn.request('PUT',path,open(local,'rb'),{'Content-Length':str(size),'Authorization':'Basic '+auth,'Content-Type':'application/octet-stream'})
    r=conn.getresponse(); data=r.read(200); conn.close()
    if r.status not in (200,201,204): raise RuntimeError('WebDAV 上传失败: HTTP %s %s'%(r.status,data.decode(errors='ignore')))
def remote_url(c,name): return c['remote_url'].rstrip('/')+'/'+c['remote_path'].strip('/')+'/'+urllib.parse.quote(name)

def backup():
    c=load(); source=c['source']; rid=log_run('running',kind='full' if not os.path.exists(os.path.join(STORE,'manifest.json')) else 'incremental')
    try:
        if not os.path.isdir(source): raise RuntimeError('源目录不存在: '+source)
        manifest_path=os.path.join(STORE,'manifest.json'); old={}
        if os.path.exists(manifest_path):
            with open(manifest_path) as f: old=json.load(f)
        current={}
        changed=[]
        for base,dirs,files in os.walk(source):
            dirs.sort(); files.sort()
            for fn in files:
                p=os.path.join(base,fn); rel=os.path.relpath(p,source); st=os.stat(p); sig=f'{st.st_size}:{st.st_mtime_ns}'
                current[rel]=sig
                if old.get(rel)!=sig: changed.append((p,rel))
        if not old: changed=[(os.path.join(source,r),r) for r in current]
        if not changed: log_run('success','没有检测到变更','',rid=rid); return
        kind='full' if not old else 'incremental'; stamp=datetime.now().strftime('%Y%m%d-%H%M%S'); name=f'{kind}-{stamp}.tar.gz'; archive=os.path.join(STORE,name)
        with tarfile.open(archive,'w:gz') as t:
            for p,rel in changed: t.add(p,arcname=rel,recursive=False)
        final=archive
        if c['encryption_password']:
            enc=archive+'.enc'; subprocess.run(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-salt','-in',archive,'-out',enc,'-pass','pass:'+c['encryption_password']],check=True); os.remove(archive); final=enc; name=os.path.basename(enc)
        if c['remote_url']:
            dav_put(remote_url(c,name),final,c['username'],c['password'])
        with open(manifest_path,'w') as f: json.dump(current,f)
        if not c['keep_local']: os.remove(final)
        log_run('success',f'完成：{len(changed)} 个文件',name,rid=rid)
    except Exception as e: log_run('failed',str(e),rid=rid)

def scheduler():
    last=''
    while True:
        c=load(); now=datetime.now(); key=now.strftime('%Y-%m-%d %H:%M')
        if c['enabled'] and now.strftime('%H:%M')==c['schedule'] and key!=last:
            last=key; threading.Thread(target=backup,daemon=True).start()
        time.sleep(20)

HTML='''<!doctype html><meta charset="utf-8"><title>飞牛 115 备份</title><style>body{font:15px system-ui;max-width:900px;margin:30px auto;background:#f5f7fb;color:#1f2937}main{background:white;padding:26px;border-radius:14px;box-shadow:0 2px 12px #ccd}label{display:block;margin:12px 0}input{padding:9px;width:100%;box-sizing:border-box;border:1px solid #ccd;border-radius:7px}button{padding:10px 18px;border:0;border-radius:7px;background:#2563eb;color:white;cursor:pointer}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:8px;border-bottom:1px solid #eee;text-align:left}.ok{color:green}.bad{color:#b91c1c}</style><main><h1>飞牛 NAS · 115 备份</h1><form method="post" action="/save"><label>源目录（容器内路径）<input name="source" value="{source}"></label><div class="grid"><label>115 WebDAV URL<input name="remote_url" placeholder="https://..." value="{remote_url}"></label><label>远端目录<input name="remote_path" value="{remote_path}"></label><label>WebDAV 用户名<input name="username" value="{username}"></label><label>WebDAV 密码<input type="password" name="password" value="{password}"></label><label>归档加密密码<input type="password" name="encryption_password" value="{encryption_password}"></label><label>每日执行时间<input name="schedule" pattern="[0-2][0-9]:[0-5][0-9]" value="{schedule}"></label></div><label><input style="width:auto" type="checkbox" name="enabled" {enabled}> 启用定时备份</label><label><input style="width:auto" type="checkbox" name="keep_local" {keep_local}> 上传后保留本地归档</label><button>保存配置</button> <button formaction="/run" formmethod="post">立即备份</button></form><h2>最近任务</h2><table><tr><th>开始</th><th>类型</th><th>状态</th><th>信息</th><th>归档</th></tr>{rows}</table></main>'''
def esc(x): return str(x).replace('&','&amp;').replace('<','&lt;').replace('"','&quot;')
class Handler(BaseHTTPRequestHandler):
    def send(self,code,body): self.send_response(code); self.send_header('Content-Type','text/html;charset=utf-8'); self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        c=load(); rr=''.join(f'<tr><td>{esc(r[1])}</td><td>{esc(r[6])}</td><td class="{"ok" if r[3]=="success" else "bad"}">{esc(r[3])}</td><td>{esc(r[4])}</td><td>{esc(r[5])}</td></tr>' for r in runs())
        vals={k:esc(v) for k,v in c.items()}; vals['enabled']='checked' if c['enabled'] else ''; vals['keep_local']='checked' if c['keep_local'] else ''; vals['rows']=rr
        page=HTML
        for k,v in vals.items(): page=page.replace('{'+k+'}',str(v))
        self.send(200,page)
    def do_POST(self):
        n=int(self.headers.get('Content-Length',0)); q=urllib.parse.parse_qs(self.rfile.read(n).decode()); c=load()
        for k in DEFAULT:
            if k in q: c[k]=q[k][0]
        c['enabled']='enabled' in q; c['keep_local']='keep_local' in q; save(c)
        if self.path=='/run': threading.Thread(target=backup,daemon=True).start()
        self.send_response(303); self.send_header('Location','/'); self.end_headers()
if __name__=='__main__': db(); threading.Thread(target=scheduler,daemon=True).start(); ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
