"""Independent, authenticated AES ZIP backups with verified incremental commits."""
import base64, hashlib, http.client, io, json, os, secrets, shutil, socket
import sqlite3, stat, subprocess, threading, time, urllib.parse
from datetime import datetime
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pyzipper
from PIL import Image

# The scanner only reads image headers and EXIF; it never decodes pixel data.
# Some NAS photos exceed Pillow's default pixel limit, so that limit would abort
# metadata-only scans despite no large image buffer being allocated.
Image.MAX_IMAGE_PIXELS = None

ROOT = os.environ.get('CONFIG_DIR', '/config')
STORE = os.environ.get('BACKUP_DIR', '/backups')
CFG = os.path.join(ROOT, 'config.json')
DB = os.path.join(ROOT, 'backup.db')
ROOTS = [os.path.realpath(p) for p in os.environ.get('SOURCE_ROOTS', '/sources/vol1:/sources/vol2:/sources/vol3:/data').split(':') if p]
EXCLUDES = [os.path.realpath(p) for p in os.environ.get('EXCLUDE_PATHS', '').split(':') if p] + [os.path.realpath(ROOT), os.path.realpath(STORE)]
GIB, BLOCK = 1024 ** 3, 1024 ** 2
DEFAULT = dict(source='/data/照片', remote_url='', remote_path='/115/备份', username='', password='', encryption_password='', enabled=False, keep_local=True, interval_minutes=60, threshold_gib=1, format='zip')
gate, network_lock = threading.Lock(), threading.Lock()
cancel = threading.Event()
active_connection = None
csrf = secrets.token_urlsafe(32)
os.makedirs(ROOT, exist_ok=True)
os.makedirs(STORE, exist_ok=True)

def atomic_json(path, value):
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def load():
    try:
        with open(CFG) as f: return {**DEFAULT, **json.load(f)}
    except FileNotFoundError: return DEFAULT.copy()

def db():
    c = sqlite3.connect(DB, timeout=30); c.row_factory = sqlite3.Row
    return c

def now(): return datetime.now().isoformat(timespec='seconds')

def init():
    with db() as c:
        c.execute('create table if not exists runs(id integer primary key, started text, finished text, status text, message text, archive text, kind text)')
        c.execute('create table if not exists events(id integer primary key, run_id integer, at text, message text)')
        c.execute("update runs set status='interrupted',finished=?,message='旧任务已停止；已完成的归档保留' where status='running'", (now(),))
    c = load()
    if c.get('zip_version') != 2:
        c.update(zip_version=2, enabled=False, password_verified=False, format='zip')
        atomic_json(CFG, c)

def event(rid, message):
    with db() as c:
        c.execute('update runs set message=? where id=?', (message, rid))
        c.execute('insert into events(run_id,at,message) values(?,?,?)', (rid, now(), message))
    print(message, flush=True)

def finish(rid, status, message):
    event(rid, message)
    with db() as c: c.execute('update runs set status=?,finished=? where id=?', (status, now(), rid))

def check_cancel():
    if cancel.is_set(): raise InterruptedError('任务已停止，完成的 ZIP 保留')

def inside(path, root): return path == root or path.startswith(root + os.sep)

def source_path(value):
    p = os.path.realpath(value)
    if not any(inside(p, r) for r in ROOTS) or any(inside(p, r) for r in EXCLUDES):
        raise ValueError('请选择已挂载的源目录，不能选择程序配置或归档目录')
    if not os.path.isdir(p): raise ValueError('目录不存在或未挂载')
    return p

def signature(st): return f'{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}'

def photo_time(path, st):
    if Path(path).suffix.lower() in {'.jpg','.jpeg','.tif','.tiff','.png','.webp','.heic','.heif'}:
        try:
            with Image.open(path) as im:
                exif = im.getexif(); values = exif.get_ifd(34665) if 34665 in exif else {}
                for tag in (36867, 36868):
                    raw = values.get(tag) or exif.get(tag)
                    if raw: return datetime.strptime(str(raw).strip('\x00'), '%Y:%m:%d %H:%M:%S').timestamp(), 'EXIF'
        except (OSError, ValueError, KeyError, TypeError, SyntaxError): pass
    birth = getattr(st, 'st_birthtime', 0)
    if not birth:
        # Linux st_ctime means inode change time, not birth time.
        try: birth = int(subprocess.check_output(['stat','-c','%W','--',path], stderr=subprocess.DEVNULL, timeout=3).strip())
        except (OSError, ValueError, subprocess.SubprocessError): birth = 0
    return (birth, '创建时间') if birth > 0 else (st.st_mtime, '修改时间回退')

def scan(source, old, rid, cache=None, save_cache=None):
    cache = cache if cache is not None else {}
    save_cache = save_cache or (lambda value: None)
    found, count, skipped, kinds = [], 0, 0, {}
    cache_dirty, last_report = 0, time.monotonic()
    def walk_error(e): raise e
    for base, dirs, files in os.walk(source, onerror=walk_error):
        check_cancel()
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(base,d)) and not any(inside(os.path.realpath(os.path.join(base,d)),x) for x in EXCLUDES))
        for name in sorted(files):
            check_cancel(); path = os.path.join(base, name); st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode): skipped += 1; continue
            rel = os.path.relpath(path, source); count += 1
            sig = signature(st)
            cached = cache.get(rel)
            if cached and cached[0] == sig:
                ts, origin = cached[1], cached[2]
            else:
                ts, origin = photo_time(path, st)
                cache[rel] = [sig, ts, origin]
                cache_dirty += 1
            kinds[origin] = kinds.get(origin,0)+1
            if old.get(rel) != sig:
                found.append(dict(path=path, rel=rel, size=st.st_size, sig=signature(st), time=ts, time_source=origin))
            if cache_dirty >= 1000:
                save_cache(cache)
                cache_dirty = 0
            if count % 5000 == 0 or time.monotonic() - last_report >= 10:
                event(rid, f'扫描目录 {count} 个文件；待备份 {len(found)} 个；照片日期索引已缓存')
                last_report = time.monotonic()
    save_cache(cache)
    found.sort(key=lambda x:(x['time'],x['rel']))
    event(rid, f'扫描完成：{count} 个文件，新增或修改 {len(found)} 个；日期来源 {kinds}；跳过链接/特殊文件 {skipped}')
    return found

def batches(items, limit=GIB):
    batch, size = [], 0
    for item in items:
        if batch and size + item['size'] > limit:
            yield batch; batch, size = [], 0
        batch.append(item); size += item['size']
    if batch: yield batch

def password_probe(password):
    if len(password) < 8: raise ValueError('加密密码至少 8 个字符')
    data, buf = secrets.token_bytes(64), io.BytesIO()
    with pyzipper.AESZipFile(buf,'w',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password.encode()); z.setencryption(pyzipper.WZ_AES,nbits=256)
        z.writestr('password-check.txt',data)
    with pyzipper.AESZipFile(io.BytesIO(buf.getvalue())) as z:
        if z.read('password-check.txt',pwd=password.encode()) != data: raise ValueError('密码加密/解密验证失败')
    try:
        with pyzipper.AESZipFile(io.BytesIO(buf.getvalue())) as z: z.read('password-check.txt',pwd=(password+'-wrong').encode())
    except (RuntimeError,ValueError,pyzipper.BadZipFile): return
    raise ValueError('错误密码仍可解密，校验失败')

def verify_zip(path, password, hashes, rid):
    done, last = 0, time.monotonic(); total = sum(h['size'] for h in hashes.values())
    with pyzipper.AESZipFile(path) as z:
        z.setpassword(password.encode())
        if set(z.namelist()) != set(hashes): raise ValueError('ZIP 文件清单不一致')
        for info in z.infolist():
            if not info.flag_bits & 1: raise ValueError('发现未加密的 ZIP 条目')
            digest = hashlib.sha256()
            with z.open(info) as f:
                while block := f.read(BLOCK):
                    check_cancel(); digest.update(block); done += len(block)
                    if time.monotonic()-last >= 3:
                        event(rid,f'解密校验 {done/BLOCK:.0f}/{total/BLOCK:.0f} MiB'); last=time.monotonic()
            if digest.hexdigest() != hashes[info.filename]['sha256']: raise ValueError('解密内容哈希不匹配：'+info.filename)
    event(rid,'本包密码、完整解压及 SHA-256 校验通过')

def make_zip(batch, path, password, rid, number):
    partial, hashes = path+'.building', {}
    total = sum(x['size'] for x in batch); done, last = 0, time.monotonic()
    with pyzipper.AESZipFile(partial,'w',compression=pyzipper.ZIP_DEFLATED,compresslevel=3,encryption=pyzipper.WZ_AES,allowZip64=True) as z:
        z.setpassword(password.encode()); z.setencryption(pyzipper.WZ_AES,nbits=256)
        for index,item in enumerate(batch,1):
            check_cancel()
            with os.fdopen(os.open(item['path'],os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)),'rb') as source:
                if signature(os.fstat(source.fileno())) != item['sig']: raise ValueError('扫描后源文件变化：'+item['rel'])
                info = z.zipinfo_cls.from_file(item['path'],arcname=item['rel'],strict_timestamps=False)
                info.compress_type = pyzipper.ZIP_DEFLATED; digest = hashlib.sha256()
                with z.open(info,'w',force_zip64=item['size']>=2**31) as target:
                    while block := source.read(BLOCK):
                        check_cancel(); target.write(block); digest.update(block); done += len(block)
                        if time.monotonic()-last >= 2:
                            event(rid,f'第 {number} 包：压缩加密 {index}/{len(batch)} 文件，{done/BLOCK:.0f}/{total/BLOCK:.0f} MiB'); last=time.monotonic()
                if signature(os.fstat(source.fileno())) != item['sig']: raise ValueError('压缩过程中源文件变化：'+item['rel'])
                hashes[item['rel']] = dict(sha256=digest.hexdigest(),size=item['size'])
    event(rid,f'第 {number} 包压缩完成，开始完整解密验证')
    verify_zip(partial,password,hashes,rid); os.replace(partial,path)
    return hashes

def upload(c, path, rid):
    global active_connection
    u = urllib.parse.urlsplit(c['remote_url'].rstrip('/'))
    dav_root = u.path.rstrip('/')
    if not dav_root.endswith('/dav'): dav_root += '/dav'
    target = dav_root+'/'+c['remote_path'].strip('/')+'/'+os.path.basename(path)
    target = urllib.parse.quote(urllib.parse.unquote(target),safe='/')
    conn = (http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection)(u.hostname,u.port,timeout=3600)
    done, waiting, start_wait = threading.Event(), threading.Event(), [0]
    def heartbeat():
        while not done.wait(10):
            if waiting.is_set(): event(rid,f'本包全部数据已发送，等待 OpenList/115 确认（{int(time.monotonic()-start_wait[0])} 秒）；尚未计为成功')
    watcher=threading.Thread(target=heartbeat,daemon=True); watcher.start()
    with network_lock: active_connection=conn
    try:
        check_cancel(); size=os.path.getsize(path)
        conn.putrequest('PUT',target)
        conn.putheader('Content-Length',str(size)); conn.putheader('Authorization','Basic '+base64.b64encode((c['username']+':'+c['password']).encode()).decode())
        conn.putheader('Content-Type','application/zip'); conn.endheaders()
        sent,last=0,time.monotonic()
        try:
            with open(path,'rb') as f:
                while block:=f.read(BLOCK):
                    check_cancel(); conn.send(block); sent+=len(block)
                    if time.monotonic()-last>=2 or sent==size:
                        event(rid,f'发送 ZIP 至 OpenList：{sent/BLOCK:.0f}/{size/BLOCK:.0f} MiB（{int(sent*100/max(size,1))}%）'); last=time.monotonic()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError) as exc:
            # A WebDAV server can reject a PUT immediately after its headers and
            # close the socket while the request body is still being sent.
            # Read that response when possible so logs show the actual cause.
            try:
                response=conn.getresponse()
                detail=response.read(1024).decode('utf-8','replace').strip()
                suffix=f'; {detail[:300]}' if detail else ''
                raise RuntimeError(f'WebDAV 在接收数据时提前关闭连接：HTTP {response.status} {response.reason}{suffix}；已发送 {sent/BLOCK:.0f}/{size/BLOCK:.0f} MiB，本地 ZIP 保留') from exc
            except (http.client.HTTPException, OSError):
                raise RuntimeError(f'WebDAV 在接收数据时断开连接（{type(exc).__name__}: {exc}）；已发送 {sent/BLOCK:.0f}/{size/BLOCK:.0f} MiB，本地 ZIP 保留') from exc
        start_wait[0]=time.monotonic(); waiting.set()
        event(rid,'本包数据发送完毕，正在等待 OpenList/115 确认上传成功…')
        response=conn.getresponse(); check_cancel()
        if response.status not in (200,201,204): raise RuntimeError(f'WebDAV 上传失败 HTTP {response.status}；保留本地 ZIP，下次重试')
        event(rid,f'WebDAV 已确认上传成功（HTTP {response.status}）')
    finally:
        done.set(); watcher.join(timeout=2); conn.close()
        with network_lock: active_connection=None

def state_path(c):
    key=json.dumps([os.path.realpath(c['source']),c['remote_url'],c['remote_path'],'aes-zip-v2'],ensure_ascii=False)
    return os.path.join(ROOT,'zip-state-'+hashlib.sha256(key.encode()).hexdigest()[:20]+'.json')

def commit_package(state, sp, pending, c):
    state['files'].update(pending['files'])
    state['packages'].append(dict(name=pending['name'],completed=now(),count=len(pending['files'])))
    state.pop('pending',None); atomic_json(sp,state)
    if not c['keep_local']: os.remove(os.path.join(STORE,pending['name']))

def perform(c, manual):
    rid=None
    try:
        source=source_path(c['source']); sp=state_path(c)
        try:
            with open(sp) as f: state=json.load(f)
        except FileNotFoundError: state=dict(files={},baseline_complete=False,packages=[])
        full=not state['baseline_complete']
        with db() as con: rid=con.execute('insert into runs(started,status,message,archive,kind) values(?,?,?,?,?)',(now(),'running','正在扫描','','full' if full else 'incremental')).lastrowid
        pending=state.get('pending')
        if pending:
            path=os.path.join(STORE,pending['name']); event(rid,'重试上次已生成的独立 ZIP：'+pending['name'])
            verify_zip(path,c['encryption_password'],pending['hashes'],rid); upload(c,path,rid); commit_package(state,sp,pending,c)
        cache = state.get('date_cache', {})
        items=scan(source,state['files'],rid,cache,lambda value: (state.update(date_cache=value), atomic_json(sp,state)))
        total=sum(x['size'] for x in items)
        if not items:
            state['baseline_complete']=True; atomic_json(sp,state); finish(rid,'success','扫描完成，没有待备份内容'); return
        if not full and not manual and total<float(c['threshold_gib'])*GIB:
            finish(rid,'waiting',f'新增/修改 {total/GIB:.3f} GiB，未达到 {c["threshold_gib"]} GiB；手动备份可立即打包'); return
        groups=list(batches(items)); event(rid,f'按日期从旧到新：{len(items)} 个文件，{total/GIB:.2f} GiB，预计 {len(groups)} 个独立 ZIP')
        for index,batch in enumerate(groups,1):
            check_cancel(); size=sum(x['size'] for x in batch)
            if shutil.disk_usage(STORE).free<size*1.02+64*BLOCK: raise ValueError('归档目录剩余空间不足，已完成的包保留')
            name=f'{"full" if full else "incremental"}-{datetime.now():%Y%m%d-%H%M%S}-{index:04d}-{secrets.token_hex(3)}.zip'
            path=os.path.join(STORE,name)
            event(rid,f'第 {index}/{len(groups)} 包：{datetime.fromtimestamp(batch[0]["time"]):%Y-%m-%d} 至 {datetime.fromtimestamp(batch[-1]["time"]):%Y-%m-%d}；{size/GIB:.3f} GiB')
            hashes=make_zip(batch,path,c['encryption_password'],rid,index)
            pending=dict(name=name,hashes=hashes,files={x['rel']:x['sig'] for x in batch}); state['pending']=pending; atomic_json(sp,state)
            with db() as con: con.execute('update runs set archive=? where id=?',(name,rid))
            upload(c,path,rid); commit_package(state,sp,pending,c)
            event(rid,f'第 {index}/{len(groups)} 个独立 ZIP 已校验并上传：{name}')
        state['baseline_complete']=True; atomic_json(sp,state)
        finish(rid,'success',f'完成：{len(groups)} 个独立加密 ZIP；{len(items)} 个文件；{total/GIB:.2f} GiB；每包均解密校验通过')
    except Exception as e:
        if rid: finish(rid,'cancelled' if cancel.is_set() else 'failed','任务已停止；完成的 ZIP 保留' if cancel.is_set() else str(e))
        else: print(type(e).__name__+': '+str(e),flush=True)
    finally: gate.release()

def start(manual=True):
    if not gate.acquire(blocking=False): raise ValueError('已有任务运行中')
    try:
        c=load(); source_path(c['source'])
        if not c.get('password_verified'): raise ValueError('请先输入两遍 ZIP 密码并保存验证')
        if not c['remote_url']: raise ValueError('请配置 WebDAV 目标')
        cancel.clear(); threading.Thread(target=perform,args=(c,manual),daemon=True).start()
    except Exception: gate.release(); raise

def scheduler():
    next_check=time.monotonic()+60
    while True:
        time.sleep(5); c=load()
        if time.monotonic()>=next_check:
            next_check=time.monotonic()+int(c['interval_minutes'])*60
            if c['enabled'] and c.get('password_verified'):
                try: start(False)
                except ValueError: pass

def settings(q):
    c=load()
    for key in ('source','remote_url','remote_path','username'):
        if key in q: c[key]=str(q[key]).strip()
    c['source']=source_path(c['source']); u=urllib.parse.urlsplit(c['remote_url'])
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.query or u.fragment: raise ValueError('请输入有效的 HTTP(S) WebDAV URL，不包含密码或查询参数')
    if '..' in c['remote_path'].split('/') or any(x in c['remote_path'] for x in ('?','#','\r','\n')): raise ValueError('远端目录格式不正确')
    if q.get('password'): c['password']=str(q['password'])
    pw,confirmation=str(q.get('encryption_password','')),str(q.get('encryption_password_confirm',''))
    if pw or confirmation:
        if pw!=confirmation: raise ValueError('两次 ZIP 加密密码不一致，未保存')
        sp=state_path(c)
        if pw!=c['encryption_password'] and os.path.exists(sp):
            with open(sp) as f:
                if json.load(f).get('pending'): raise ValueError('存在待上传 ZIP，请先用原密码完成上传再更换密码')
        password_probe(pw); c.update(encryption_password=pw,password_verified=True)
    elif not c.get('password_verified'): raise ValueError('请输入两遍加密密码进行验证')
    c['enabled']=bool(q.get('enabled')); c['keep_local']=bool(q.get('keep_local'))
    c['interval_minutes']=int(q.get('interval_minutes',c['interval_minutes'])); c['threshold_gib']=float(q.get('threshold_gib',c['threshold_gib']))
    if not 1<=c['interval_minutes']<=10080 or not 0<=c['threshold_gib']<=1024: raise ValueError('检查间隔须为 1～10080 分钟，增量阈值为 0～1024 GiB')
    c.update(zip_version=2,format='zip'); atomic_json(CFG,c)

class Handler(BaseHTTPRequestHandler):
    def reply(self,code,data,content_type='application/json;charset=utf-8'):
        raw=(json.dumps(data,ensure_ascii=False) if not isinstance(data,str) else data).encode()
        self.send_response(code); self.send_header('Content-Type',content_type); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        u=urllib.parse.urlsplit(self.path)
        try:
            if u.path=='/': self.reply(200,Path(__file__).with_name('web.html').read_text().replace('__CSRF__',csrf),'text/html;charset=utf-8')
            elif u.path=='/config':
                c=load(); c.pop('password',None); c.pop('encryption_password',None); self.reply(200,c)
            elif u.path=='/progress':
                with db() as c:
                    rows=[dict(r) for r in c.execute('select * from runs order by id desc limit 30')]
                    logs=[dict(r) for r in c.execute('select * from events order by id desc limit 100')][::-1]
                self.reply(200,dict(running=gate.locked(),runs=rows,logs=logs))
            elif u.path=='/browse':
                value=urllib.parse.parse_qs(u.query).get('path',[''])[0]
                if not value: self.reply(200,dict(path='',parent='',directories=[p for p in ROOTS if os.path.isdir(p)]))
                else:
                    p=source_path(value); parent=os.path.dirname(p)
                    directories=sorted(e.path for e in os.scandir(p) if e.is_dir(follow_symlinks=False) and not any(inside(os.path.realpath(e.path),x) for x in EXCLUDES))
                    self.reply(200,dict(path=p,parent=parent if any(inside(parent,r) for r in ROOTS) else '',directories=directories))
            else: self.reply(404,dict(error='Not found'))
        except (ValueError,OSError) as e: self.reply(400,dict(error=str(e)))
    def do_POST(self):
        if self.headers.get('X-CSRF-Token')!=csrf: self.reply(403,dict(error='页面已过期，请刷新')); return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=32768: raise ValueError('请求过大')
            q=json.loads(self.rfile.read(length) or b'{}')
            if self.path in ('/save','/verify-password'):
                if not gate.acquire(blocking=False): raise ValueError('任务运行中，请停止后再修改设置')
                try:
                    if self.path=='/save': settings(q)
                    else:
                        pw=str(q.get('password',''))
                        if not secrets.compare_digest(pw.encode(),load()['encryption_password'].encode()): raise ValueError('密码与已保存的密码不一致')
                        password_probe(pw)
                finally: gate.release()
            elif self.path=='/run': start(True)
            elif self.path=='/stop':
                cancel.set()
                with network_lock:
                    if active_connection:
                        if active_connection.sock:
                            try: active_connection.sock.shutdown(socket.SHUT_RDWR)
                            except OSError: pass
                        active_connection.close()
            elif self.path=='/clear-history':
                if not gate.acquire(blocking=False): raise ValueError('请先停止任务')
                try:
                    with db() as c: c.execute('delete from events'); c.execute('delete from runs')
                finally: gate.release()
            else: self.reply(404,dict(error='Not found')); return
            self.reply(200,dict(ok=True))
        except (ValueError,OSError,RuntimeError) as e: self.reply(400,dict(error=str(e)))

if __name__=='__main__':
    init(); threading.Thread(target=scheduler,daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('PORT','8080'))),Handler).serve_forever()
