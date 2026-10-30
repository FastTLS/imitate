import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import update
import releases
import audit


class PipelineTests(unittest.TestCase):
    def test_semantic_diff_preserves_order_presence_and_zero(self):
        self.assertEqual(update.semantic_diff({'a':1,'b':[1,2]},{'b':[1,2],'a':1}),[])
        for before,after in (({'a':[1,2]},{'a':[2,1]}),({'a':None},{}),({'a':0},{'a':False}),({'a/b':0},{'a/b':1})):
            self.assertTrue(update.semantic_diff(before,after))
        self.assertEqual(update.semantic_diff({'a/b':0},{'a/b':1}),['/a~1b'])

    def test_known_build_requires_matching_full_version_and_verified_fields(self):
        fields=['tls.static_client_hello.cold','http.headers.navigation.zh-CN']
        candidate={'firefox/159/windows':{'match':{'verified_fields':fields},'spec':{'evidence':[{'product_version':'159.0','verified_fields':fields}]}}}
        self.assertTrue(update.known_build(candidate,'159.0'))
        self.assertFalse(update.known_build(candidate,'159.0.1'))
        candidate['firefox/159/windows']['spec']['evidence'][0]['verified_fields']=[]
        self.assertFalse(update.known_build(candidate,'159.0'))

    def test_offline_bundle_exact_bytes_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            spec={'id':'firefox/159/windows','tls':{'cipher_suites':['0x1301','0x1302']}}
            catalog={spec['id']:{'spec':spec}}
            receipt=update.write_bundles(Path(directory)/'bundles',catalog,'159.0','official HTTPS SHA512SUMS')
            bundle=audit.read(Path(directory)/receipt['path'])
            self.assertEqual(bundle['schema_version'],1)
            self.assertEqual(update.hashlib.sha256(bundle['spec_json'].encode()).hexdigest(),receipt['sha256'])
            self.assertEqual(json.loads(bundle['spec_json']),spec)

    def test_no_change_does_not_download_or_modify_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); repo=root/'repo';repo.mkdir()
            audit.dump(repo/'browser-specs.json',{})
            before=(repo/'browser-specs.json').read_bytes()
            args=SimpleNamespace(output=root/'run',repo=repo,core=repo,transport=repo,lab=repo,version=None,force_capture=False,sevenzip='unused')
            with patch.object(update.sys,'platform','win32'),patch.object(update,'source_identity',return_value={}),patch.object(releases,'discover',return_value={'latest':'159.0'}),patch.object(update,'known_build',return_value=True),patch.object(releases,'download') as download:
                self.assertEqual(update.run(args)['status'],'no_change');download.assert_not_called()
            self.assertEqual((repo/'browser-specs.json').read_bytes(),before)
            self.assertEqual(audit.read(args.output/'update-report.json')['status'],'no_change')
            with self.assertRaises(ValueError):update.run(args)

    def test_failure_preserves_report_and_does_not_activate_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);repo=root/'repo';repo.mkdir();audit.dump(repo/'browser-specs.json',{})
            before=(repo/'browser-specs.json').read_bytes()
            args=SimpleNamespace(output=root/'run',repo=repo,core=repo,transport=repo,lab=repo,version='159.0',force_capture=True,sevenzip='unused')
            with patch.object(update.sys,'platform','win32'),patch.object(update,'source_identity',return_value={}),patch.object(releases,'discover',return_value={'latest':'159.0'}),patch.object(releases,'download',side_effect=ValueError('SHA512 mismatch')):
                with self.assertRaises(ValueError):update.run(args)
            self.assertEqual(audit.read(args.output/'update-report.json')['phase'],'download')
            self.assertFalse((args.output/'bundles').exists())
            self.assertEqual((repo/'browser-specs.json').read_bytes(),before)


if __name__=='__main__':unittest.main()
