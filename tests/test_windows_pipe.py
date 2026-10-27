"""Real Windows pipe tests. Never read stored passwords or use a camera."""
import os
import json
import threading
import sys
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.name == 'nt', 'Windows named-pipe APIs required')
class WindowsPipeTests(unittest.TestCase):
    def test_current_user_identity_and_remote_rejection_flag(self):
        import win32file
        import win32pipe
        from face_service.pipe_security import (build_pipe_security, client_role,
            PIPE_REJECT_REMOTE_CLIENTS, _client_process_id, _process_image)
        name = rf'\\.\pipe\FaceUnlock-Test-{os.getpid()}'
        pipe = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
            1, 4096, 4096, 0, build_pipe_security())
        from face_service.service import FaceService
        from unittest.mock import Mock
        svc = FaceService.__new__(FaceService)
        svc._capture_and_verify = Mock()
        result = []
        def serve():
            try:
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except Exception as exc:
                    if exc.winerror != 535:
                        raise
                request = json.loads(win32file.ReadFile(pipe, 4096)[1])
                self.assertEqual(_client_process_id(pipe), os.getpid())
                expected_execs = [os.path.normcase(sys.executable), os.path.normcase(getattr(sys, '_base_executable', sys.executable))]
                self.assertIn(os.path.normcase(_process_image(os.getpid())), expected_execs)
                role = client_role(pipe)
                result.append(role)
                with patch('face_service.service.load_password') as password:
                    response = svc._handle(request, role)
                    password.assert_not_called()
                    svc._capture_and_verify.assert_not_called()
                win32file.WriteFile(pipe, json.dumps(response).encode())
            except Exception as exc:
                result.append(exc)
                win32pipe.DisconnectNamedPipe(pipe)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            client = win32file.CreateFile(name, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None)
            try:
                win32file.WriteFile(client, b'{"cmd":"unlock"}')
                self.assertEqual(json.loads(win32file.ReadFile(client, 4096)[1]),
                                 {'ok': False, 'reason': 'unauthorized'})
            finally:
                client.Close()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, ['user'])
        finally:
            pipe.Close()

    def test_unauthorized_unlock_never_checks_face_or_loads_password(self):
        from face_service.service import FaceService
        from unittest.mock import Mock
        svc = FaceService.__new__(FaceService)
        svc._capture_and_verify = Mock(return_value=(True, 0.1, True))
        with patch('face_service.service.load_password') as password:
            for role in [None, 'user', 'SYSTEM', 'unknown']:
                self.assertEqual(svc._handle({'cmd': 'unlock'}, role),
                                 {'ok': False, 'reason': 'unauthorized'})
            svc._capture_and_verify.assert_not_called()
            password.assert_not_called()

    def test_failed_face_does_not_load_credentials(self):
        from face_service.service import FaceService
        from unittest.mock import Mock
        svc = FaceService.__new__(FaceService)
        svc._capture_and_verify = Mock(return_value=(False, 0.9, False))
        with patch('face_service.service.load_password') as password:
            self.assertFalse(svc._handle({'cmd': 'unlock'}, 'credential_provider')['ok'])
            password.assert_not_called()
