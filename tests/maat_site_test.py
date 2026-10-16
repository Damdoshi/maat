#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'tools' / 'maat-site'
loader = importlib.machinery.SourceFileLoader('maat_site', str(SCRIPT))
spec = importlib.util.spec_from_loader('maat_site', loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

class SiteTest(unittest.TestCase):
    def test_creates_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            path = mod.create('demo-1', root)
            self.assertTrue((path / 'public' / 'index.php').is_file())
            self.assertTrue((path / 'private' / 'README.txt').is_file())
            self.assertEqual((path / 'private').stat().st_mode & 0o777, 0o700)
            fragment = (path / 'apache-private.conf.example').read_text()
            self.assertIn('MaatIngress On', fragment)
            self.assertNotIn('Listen ', fragment)
            with self.assertRaises(FileExistsError):
                mod.create('demo-1', root)
    def test_bad_names(self):
        with tempfile.TemporaryDirectory() as root:
            for n in ('../foo', 'a/b', 'UPPER', 'x y', 'a-', '.hidden'):
                with self.assertRaises(ValueError):
                    mod.create(n, root)
    def test_symlink_parent(self):
        with tempfile.TemporaryDirectory() as root:
            p = pathlib.Path(root)
            (p/'real').mkdir()
            (p/'link').symlink_to(p/'real', target_is_directory=True)
            with self.assertRaises(ValueError):
                mod.create('demo', p/'link')
    def test_php_lint(self):
        if subprocess.run(['sh', '-c', 'command -v php >/dev/null'], capture_output=True).returncode:
            self.skipTest('php unavailable')
        for php in (ROOT / 'examples' / 'maat-site' / 'public').glob('*.php'):
            subprocess.run(['php', '-l', str(php)], check=True, capture_output=True)

class DeployTest(unittest.TestCase):
    def test_check_deploy_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root)
            site = mod.create('demo', path)
            self.assertEqual(mod.validated_site('demo', path), site)
            runtime = path / 'run'
            runtime.mkdir()
            a, b = path / 'maat.so', path / 'php.so'
            a.write_bytes(b'test')
            b.write_bytes(b'test')
            output = path / 'private-apache.conf'
            mod.deploy('demo', path, output, 18082, a, b, 'www-data', 'www-data', runtime)
            config = output.read_text()
            self.assertIn('Listen 127.0.0.1:18082', config)
            self.assertIn('MaatIngress On', config)
            self.assertNotIn('/var/www/html', config)
            with self.assertRaises(FileExistsError):
                mod.deploy('demo', path, output, 18082, a, b, 'www-data', 'www-data', runtime)
            self.assertIn('MaatIngress On', output.read_text())
    def test_bad_permissions_and_bad_paths(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root)
            site = mod.create('demo', path)
            (site / 'private').chmod(0o755)
            with self.assertRaises(ValueError):
                mod.validated_site('demo', root)
            (site / 'private').chmod(0o700)
            (site / 'public' / 'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                mod.validated_site('demo', root)

if __name__ == '__main__':
    unittest.main()

# Additional alpha15 checks run by unittest discovery (defined before __main__ via external suite).
