import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

tmp = tempfile.TemporaryDirectory()
root = Path(tmp.name)
os.environ.update(CONFIG_DIR=str(root/'config'),BACKUP_DIR=str(root/'archives'),SOURCE_ROOTS=str(root/'source'))
(root/'source').mkdir()
import zip_app as app
import pyzipper
from PIL import Image
app.init()

class BackupTests(unittest.TestCase):
    def setUp(self):
        app.cancel.clear()
        with app.db() as c:
            self.rid=c.execute("insert into runs(status) values('running')").lastrowid

    def test_independent_unicode_aes_zip(self):
        folder=root/'source'/'相片';folder.mkdir(exist_ok=True)
        p=folder/'照片.txt';p.write_bytes(b'photo-data'*1000)
        item=dict(path=str(p),rel='相片/照片.txt',size=p.stat().st_size,sig=app.signature(p.stat()))
        dest=str(root/'archives'/'independent.zip')
        hashes=app.make_zip([item],dest,'test-password-123',self.rid,1)
        with pyzipper.AESZipFile(dest) as z:
            self.assertEqual(z.read(item['rel'],pwd=b'test-password-123'),p.read_bytes())
            with self.assertRaises((RuntimeError,ValueError,pyzipper.BadZipFile)):z.read(item['rel'],pwd=b'wrong')
        self.assertFalse(Path(dest+'.building').exists())
        app.verify_zip(dest,'test-password-123',hashes,self.rid)

    def test_password_confirmation_and_no_secret_config(self):
        c=dict(source=str(root/'source'),remote_url='http://localhost:1999',remote_path='/115/备份',encryption_password='abcdefghi',encryption_password_confirm='different')
        with self.assertRaisesRegex(ValueError,'不一致'):app.settings(c)
        c['encryption_password_confirm']='abcdefghi';app.settings(c)
        self.assertTrue(app.load()['password_verified'])
        app.password_probe('abcdefghi')

    def test_batch_boundaries_no_file_splitting(self):
        groups=list(app.batches([dict(size=s) for s in [6,4,11,2,3]],10))
        self.assertEqual([[x['size'] for x in g] for g in groups],[[6,4],[11],[2,3]])

    def test_five_gib_batches_accumulate_to_minimum_and_leave_tail(self):
        groups=list(app.batches([dict(size=s) for s in [3,3,4,2]],5))
        self.assertEqual([[x['size'] for x in g] for g in groups],[[3,3],[4,2]])

    def test_daily_observation_deduplicates_repeated_scan(self):
        item=dict(rel='one.jpg',sig='1:2:3',size=123)
        app.record_observed([item]); app.record_observed([item])
        with app.db() as con:
            count=con.execute('select count(*) from observed').fetchone()[0]
            amount=con.execute('select sum(size) from observed').fetchone()[0]
        self.assertEqual((count,amount),(1,123))

    def test_completed_package_keeps_final_gap_progress_and_daily_upload_total(self):
        name='full-test-final.zip'; archive=root/'archives'/name; archive.write_bytes(b'zip-data')
        state_path=root/'config'/'state-test.json'; state={'files':{},'packages':[]}
        app.atomic_json(str(state_path),state)
        c={**app.DEFAULT,'source':str(root/'source'),'remote_url':'http://localhost','remote_path':'/115/backup','keep_local':True}
        app.set_progress(self.rid,total_bytes=100,completed_bytes=0,package_index=1,package_count=1,threshold_bytes=5*app.GIB)
        pending={'name':name,'files':{'one.jpg':'1:2:3'},'items':[{'size':100}],
                 'items_by_rel':{'one.jpg':100},'archive_size':len(b'zip-data'),
                 'hashes':{'one.jpg':{'size':100}}}
        app.commit_package(state,str(state_path),pending,c,self.rid)
        with app.db() as con:
            progress=con.execute('select * from run_progress where run_id=?',(self.rid,)).fetchone()
            uploaded=con.execute('select count(*) from upload_events where name=?',(name,)).fetchone()[0]
            con.execute('delete from uploaded_packages where name=?',(name,))
        self.assertEqual(progress['archive_bytes'],len(b'zip-data'))
        self.assertEqual(progress['sent_bytes'],len(b'zip-data'))
        self.assertEqual(uploaded,1)
        self.assertTrue(any(row['uploaded']==len(b'zip-data') for row in app.package_metrics()[0]))

    def test_forgetting_one_package_preserves_other_file_signatures(self):
        state_path=root/'config'/'state-delete.json'
        state={'files':{'a.jpg':'sig-a','b.jpg':'sig-b'},'baseline_complete':True,
               'packages':[{'name':'a.zip','files':{'a.jpg':'sig-a'}},{'name':'b.zip','files':{'b.jpg':'sig-b'}}]}
        app.atomic_json(str(state_path),state)
        app.forget_state_package(str(state_path),'a.zip',app.DEFAULT)
        saved=json.loads(state_path.read_text())
        self.assertEqual(saved['files'],{'b.jpg':'sig-b'})
        self.assertEqual([p['name'] for p in saved['packages']],['b.zip'])

    def test_exif_precedence_oldest_first(self):
        folder=root/'source'/'dates';folder.mkdir(exist_ok=True)
        for name,date in [('a-new.jpg','2025:01:01 00:00:00'),('z-old.jpg','2001:01:01 00:00:00')]:
            im=Image.new('RGB',(10,10));exif=Image.Exif();exif[36867]=date;im.save(folder/name,exif=exif)
        items=app.scan(str(folder),{},self.rid)
        self.assertEqual([x['rel'] for x in items],['z-old.jpg','a-new.jpg'])
        self.assertEqual(items[0]['time_source'],'EXIF')

    def test_source_change_rejected(self):
        p=root/'source'/'changed.txt';p.write_text('before')
        item=dict(path=str(p),rel=p.name,size=p.stat().st_size,sig=app.signature(p.stat()))
        p.write_text('after with different size')
        with self.assertRaisesRegex(ValueError,'变化'):app.make_zip([item],str(root/'archives'/'changed.zip'),'abcdefgh',self.rid,1)

    def test_failed_upload_does_not_commit_and_resumes(self):
        folder=root/'source'/'resume';folder.mkdir(exist_ok=True);(folder/'one.txt').write_text('one')
        c={**app.DEFAULT,'source':str(folder),'remote_url':'http://localhost','encryption_password':'abcdefgh','keep_local':True}
        app.gate.acquire()
        with patch.object(app,'upload',side_effect=RuntimeError('network failed')):app.perform(c,True)
        sp=app.state_path(c);state=json.loads(Path(sp).read_text())
        self.assertFalse(state['baseline_complete']);self.assertFalse(state['files']);self.assertIn('pending',state)
        oldname=state['pending']['name'];app.gate.acquire()
        with patch.object(app,'upload') as upload:app.perform(c,True)
        self.assertEqual(upload.call_count,1)
        state=json.loads(Path(sp).read_text());self.assertTrue(state['baseline_complete']);self.assertNotIn('pending',state)
        self.assertEqual(state['packages'][0]['name'],oldname)
        self.assertEqual(len(state['files']),1)

    def test_upload_reports_early_webdav_rejection_instead_of_broken_pipe(self):
        archive=root/'archives'/'early-reject.zip';archive.write_bytes(b'zip-data')
        conn=unittest.mock.Mock()
        conn.send.side_effect=BrokenPipeError('peer closed')
        response=unittest.mock.Mock(status=413,reason='Content Too Large')
        response.read.return_value=b'upload exceeds server limit'
        conn.getresponse.return_value=response
        c={**app.DEFAULT,'remote_url':'http://localhost:1999','remote_path':'/115/backup','username':'backup','password':'secret'}
        with patch.object(app.http.client,'HTTPConnection',return_value=conn):
            with self.assertRaisesRegex(RuntimeError,'HTTP 413 Content Too Large.*server limit'):
                app.upload(c,str(archive),self.rid)
        self.assertEqual(conn.putrequest.call_args.args[1],'/dav/115/backup/early-reject.zip')

    def test_source_isolation_and_traversal(self):
        with self.assertRaises(ValueError):app.source_path('/etc')
        a={**app.DEFAULT,'source':str(root/'source')};b={**a,'source':str(root/'source'/'resume')}
        self.assertNotEqual(app.state_path(a),app.state_path(b))

if __name__=='__main__':unittest.main()
