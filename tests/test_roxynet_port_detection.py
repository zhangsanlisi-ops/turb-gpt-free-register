"""Regression tests for long-running RoxyBrowser dynamic port discovery."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from core import roxybrowser_client as client


class RoxyNetPortDetectionTests(unittest.TestCase):
    def test_old_startup_log_still_supplies_live_ports(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            startup = root / "run_20261012.log"
            startup.write_bytes(
                b"[mixed] listen on 0.0.0.0:0: 62322\n"
                b"api server:Listening on 62324 port:[::]:62324\n"
                + b"x" * 300_000
            )
            for day in range(13, 17):
                (root / f"run_202610{day}.log").write_text("still running\n")
            with (
                patch.object(client, "_roxynet_log_dirs", return_value=[root]),
                patch.object(client, "_tcp_port_listening", return_value=True),
            ):
                self.assertEqual(client._detect_roxynet_ports_from_logs(), (62324, 62322))

    @unittest.skipUnless(os.name == "nt", "Windows netstat parser")
    def test_netstat_fallback_does_not_need_tasklist_or_post(self):
        netstat = (
            "TCP    0.0.0.0:62322    0.0.0.0:0    LISTENING    46956\n"
            "TCP    0.0.0.0:62324    0.0.0.0:0    LISTENING    46956\n"
        )
        proxy_response = Mock(status_code=407, text="")
        control_response = Mock(status_code=200, text="Invlaid proxy format")
        with (
            patch.object(client.subprocess, "check_output", return_value=netstat) as command,
            patch.object(client, "_windows_process_image", return_value="roxynet.exe"),
            patch.object(client.requests, "get", side_effect=[proxy_response, control_response]) as get,
            patch.object(client.requests, "post") as post,
            patch.object(client, "_tcp_port_listening", return_value=True),
        ):
            self.assertEqual(client._detect_roxynet_ports_from_netstat(), (62324, 62322))
        command.assert_called_once()
        self.assertEqual(get.call_count, 2)
        post.assert_not_called()
