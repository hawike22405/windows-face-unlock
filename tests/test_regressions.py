"""Portable regressions: no camera, Windows credentials, or ML downloads."""
import importlib.util
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


class StartupTests(unittest.TestCase):
    def test_frozen_entrypoints_have_no_package_context(self):
        for package, target in [('face_service', 'service'), ('presence_monitor', 'monitor')]:
            with self.subTest(package=package):
                module = types.ModuleType(f'{package}.{target}')
                module.main = Mock()
                with patch.dict(sys.modules, {module.__name__: module}), patch('multiprocessing.freeze_support') as freeze:
                    # PyInstaller executes the entry script with no __package__.
                    runpy.run_path(str(ROOT / package / '__main__.py'), run_name='__main__')
                    freeze.assert_called_once()
                    module.main.assert_called_once()


class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stubs = {name: types.ModuleType(name) for name in
                 ['win32api', 'win32con', 'win32pipe', 'win32security']}
        with patch.dict(sys.modules, stubs):
            spec = importlib.util.spec_from_file_location('pipe_security', ROOT / 'face_service/pipe_security.py')
            cls.security = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.security)

    def test_command_matrix(self):
        for role in [None, 'user', 'credential_provider', 'SYSTEM', 'unknown']:
            self.assertEqual(self.security.command_allowed('unlock', role), role == 'credential_provider')
            for cmd in ['ping', 'status', 'verify', 'presence', 'shutdown', 'build_enrollment']:
                self.assertEqual(self.security.command_allowed(cmd, role), role == 'user')

    def test_identity_failure_denies(self):
        with patch.object(self.security, 'current_user_sid', side_effect=OSError):
            self.assertIsNone(self.security.client_role(123))

    def test_system_must_be_logonui_in_same_session(self):
        sec = self.security
        token = Mock()
        token.__enter__ = Mock(return_value=token)
        token.__exit__ = Mock(return_value=False)
        with patch.object(sec, 'current_user_sid', return_value='owner'), \
             patch.object(sec.win32security, 'ImpersonateNamedPipeClient', create=True), \
             patch.object(sec.win32security, 'RevertToSelf', create=True) as revert, \
             patch.object(sec.win32security, 'OpenThreadToken', return_value=token, create=True), \
             patch.object(sec.win32security, 'OpenProcessToken', return_value=token, create=True), \
             patch.object(sec.win32security, 'TokenUser', 1, create=True), \
             patch.object(sec.win32security, 'TokenSessionId', 12, create=True), \
             patch.object(sec.win32security, 'ConvertSidToStringSid', return_value=sec.SYSTEM_SID, create=True), \
             patch.object(sec.win32api, 'GetCurrentThread', create=True), \
             patch.object(sec.win32api, 'GetCurrentProcess', create=True), \
             patch.object(sec.win32con, 'TOKEN_QUERY', 8, create=True), \
             patch.object(sec.win32api, 'GetSystemDirectory', return_value=r'C:\Windows\System32', create=True), \
             patch.object(sec, '_client_process_id', return_value=42), \
             patch.object(sec, '_process_image') as image, \
             patch.object(sec.win32security, 'GetTokenInformation', create=True) as info:
            for path, session, allowed in [
                (r'C:\Windows\System32\LogonUI.exe', 2, True),
                (r'C:\Temp\LogonUI.exe', 2, False),
                (r'C:\Windows\System32\LogonUI.exe', 3, False),
            ]:
                info.side_effect = [('system', 0), session, 2]
                image.return_value = path
                self.assertEqual(sec.client_role(123), 'credential_provider' if allowed else None)
            self.assertEqual(revert.call_count, 3)


if __name__ == '__main__':
    unittest.main()
