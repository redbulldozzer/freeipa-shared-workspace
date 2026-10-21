import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from entry import dispatch
from transition.core import Job, STATE, TransitionError
import test_engine as engine_tests


class DispatchTests(unittest.TestCase):
    def setUp(self):
        engine_tests.EngineTests.setUp(self)

    def tearDown(self):
        engine_tests.EngineTests.tearDown(self)

    def install_receiver(self):
        self.received = None
        self.receiver_error = None
        self.thread = None
        original = self.system.run
        def run(args, **kwargs):
            if args[0] == 'systemctl' and args[1] == 'is-active':
                return subprocess.CompletedProcess(args, 3, 'inactive\n', '')
            if args[0] != 'systemd-run':
                return original(args, **kwargs)
            job_id = args[-1]
            def receiver():
                try:
                    client = socket.socket(socket.AF_UNIX)
                    client.settimeout(3)
                    client.connect(str(self.system.path(STATE+'/jobs/'+job_id+'/credentials.sock')))
                    data = b''
                    while True:
                        block = client.recv(4096)
                        if not block:
                            break
                        data += block
                    client.close()
                    if data:
                        self.received = json.loads(data)
                        # The sender must release the execution lock before sending EOF.
                        fd = Job(self.system, job_id).lock()
                        os.close(fd)
                except Exception as error:
                    self.receiver_error = error
            self.thread = threading.Thread(target=receiver)
            self.thread.start()
            return subprocess.CompletedProcess(args, 0, '', '')
        self.system.run = run

    def test_credentials_pass_only_through_socket_and_lock_handoff(self):
        self.install_receiver()
        opts = self.job.planned()['options']
        with patch('entry.struct.unpack', return_value=(123, 0, 0)):
            result = dispatch(self.system, opts, self.secrets)
        self.thread.join(4)
        self.assertFalse(self.thread.is_alive())
        self.assertIsNone(self.receiver_error)
        self.assertEqual(self.received, self.secrets)
        job = Job(self.system, result['id'])
        self.assertFalse((job.directory/'credentials.sock').exists())
        for file in job.directory.glob('*.json'):
            self.assertNotIn(self.secrets['password'], file.read_text())
            self.assertNotIn(self.secrets['admin_password'], file.read_text())

    def test_non_root_receiver_rejected_and_lock_released(self):
        self.install_receiver()
        with patch('entry.struct.unpack', return_value=(123, 1000, 1000)):
            with self.assertRaises(TransitionError):
                dispatch(self.system, self.job.planned()['options'], self.secrets)
        self.thread.join(4)
        self.assertIsNone(self.received)
        fd = self.job.lock()
        os.close(fd)
