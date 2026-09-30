"""Real nftables checks inside disposable network namespaces, never the host ruleset.

Debian: sudo python3 -m unittest discover -s tests -p test_linux_network.py -v
Requires nftables, iproute2, root and network-namespace capability.
"""
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import unittest
import uuid

import vps_firewall as app


SERVER = r'''
import socket, sys, threading
family = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s = socket.socket(family)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen()
print('ready', flush=True)
def serve(c):
    try:
        while True:
            data = c.recv(1024)
            if not data: break
            c.sendall(data)
    except OSError: pass
    finally: c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
'''

CLIENT = r'''
import socket, sys
family = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s = socket.socket(family)
s.settimeout(1.5)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.sendall(b'hello')
    assert s.recv(5) == b'hello'
except (OSError, AssertionError):
    sys.exit(2)
finally:
    s.close()
'''

PERSISTENT_CLIENT = r'''
import socket, sys
family = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s = socket.socket(family)
s.settimeout(1.5)
s.connect((sys.argv[1], int(sys.argv[2])))
s.sendall(b'before')
assert s.recv(6) == b'before'
print('connected', flush=True)
input()
try:
    s.sendall(b'after')
    data = s.recv(5)
    print('passed' if data == b'after' else 'blocked', flush=True)
except OSError:
    print('blocked', flush=True)
s.close()
'''


@unittest.skipUnless(sys.platform == "linux", "requires Linux network namespaces")
class NetworkIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or not all(shutil.which(tool) for tool in ("nft", "ip")):
            raise unittest.SkipTest("requires root, nft and iproute2")

    def command(self, *args, namespace=None, input_text=None, check=True):
        prefix = ["ip", "netns", "exec", namespace] if namespace else []
        result = subprocess.run(prefix + list(args), input=input_text, capture_output=True,
                                text=True, timeout=10)
        if check and result.returncode:
            self.fail("%s\n%s" % (args, result.stderr))
        return result

    def setUp(self):
        suffix = uuid.uuid4().hex[:8]
        self.namespaces = []
        self.children = []
        self.addCleanup(self.cleanup)
        self.server = "wl-s-" + suffix
        self.client = "wl-c-" + suffix
        self.container = "wl-d-" + suffix
        for namespace in (self.server, self.client, self.container):
            result = self.command("ip", "netns", "add", namespace, check=False)
            if result.returncode:
                self.skipTest("network namespace unavailable: " + result.stderr.strip())
            self.namespaces.append(namespace)
            self.command("ip", "link", "set", "lo", "up", namespace=namespace)
        # Links are created inside the test namespace, not in the host network.
        self.command("ip", "link", "add", "external", "type", "veth", "peer", "name", "client",
                     namespace=self.server)
        self.command("ip", "link", "set", "client", "netns", self.client, namespace=self.server)
        for namespace, interface, ipv4, ipv6 in (
                (self.server, "external", "10.203.0.1/24", "fd42:203::1/64"),
                (self.client, "client", "10.203.0.2/24", "fd42:203::2/64")):
            self.command("ip", "addr", "add", ipv4, "dev", interface, namespace=namespace)
            self.command("ip", "-6", "addr", "add", ipv6, "dev", interface, "nodad", namespace=namespace)
            self.command("ip", "link", "set", interface, "up", namespace=namespace)
        self.command("ip", "link", "add", "inside", "type", "veth", "peer", "name", "container",
                     namespace=self.server)
        self.command("ip", "link", "set", "container", "netns", self.container, namespace=self.server)
        for namespace, interface, address in ((self.server, "inside", "10.204.0.1/24"),
                                               (self.container, "container", "10.204.0.2/24")):
            self.command("ip", "addr", "add", address, "dev", interface, namespace=namespace)
            self.command("ip", "link", "set", interface, "up", namespace=namespace)
        self.command("ip", "route", "add", "default", "via", "10.204.0.1", namespace=self.container)
        self.command("sysctl", "-qw", "net.ipv4.ip_forward=1", namespace=self.server)
        # Unrelated firewall table must survive policy changes and disable/rollback.
        self.command("nft", "-f", "-", namespace=self.server, input_text="table inet unrelated {}\n")

    def cleanup(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
        for namespace in reversed(self.namespaces):
            self.command("ip", "netns", "delete", namespace, check=False)

    def start(self, namespace, script, address, port):
        process = subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable, "-u", "-c",
                                    script, address, str(port)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(process)
        return process

    def read_line(self, process):
        ready, _, _ = select.select([process.stdout], [], [], 5)
        self.assertTrue(ready, "test peer did not respond")
        line = process.stdout.readline().strip()
        self.assertTrue(line, "test peer exited")
        return line

    def echo_server(self, namespace, address, port=8080):
        process = self.start(namespace, SERVER, address, port)
        self.assertEqual(self.read_line(process), "ready")

    def rules(self, allowed, **kwargs):
        rules = app.render_rules(allowed, ping_mode="whitelist", **kwargs)
        self.command("nft", "-c", "-f", "-", namespace=self.server, input_text=rules)
        self.command("nft", "-f", "-", namespace=self.server, input_text=rules)

    def connects(self, namespace, address, port=8080):
        return self.command(sys.executable, "-c", CLIENT, address, str(port),
                            namespace=namespace, check=False).returncode == 0

    def test_ipv4_delete_blocks_existing_and_new_connections_but_keeps_outbound(self):
        self.echo_server(self.server, "10.203.0.1")
        self.echo_server(self.client, "10.203.0.2")
        self.rules(["10.203.0.2", "10.203.0.3"])
        client = self.start(self.client, PERSISTENT_CLIENT, "10.203.0.1", 8080)
        self.assertEqual(self.read_line(client), "connected")
        self.rules(["10.203.0.3"])
        client.stdin.write("continue\n")
        client.stdin.flush()
        self.assertEqual(self.read_line(client), "blocked")
        self.assertFalse(self.connects(self.client, "10.203.0.1"))
        self.assertTrue(self.connects(self.server, "10.203.0.2"), "outbound replies must survive")
        self.rules([], enabled=False)
        self.assertTrue(self.connects(self.client, "10.203.0.1"))
        self.command("nft", "list", "table", "inet", "unrelated", namespace=self.server)

    def test_pause_resume_ip_and_network_configuration(self):
        self.echo_server(self.server, "10.203.0.1")
        for key, entry in (("ips", "10.203.0.2"), ("cidrs", "10.203.0.0/24")):
            with self.subTest(key=key):
                cfg = app.validate_config({"rescue_ips": ["10.203.0.3"], key: [entry]})
                self.rules(app.build_allowlist(cfg))
                client = self.start(self.client, PERSISTENT_CLIENT, "10.203.0.1", 8080)
                self.assertEqual(self.read_line(client), "connected")
                cfg["paused"] = {key: [entry]}
                self.rules(app.build_allowlist(cfg))
                client.stdin.write("continue\n")
                client.stdin.flush()
                self.assertEqual(self.read_line(client), "blocked")
                self.assertFalse(self.connects(self.client, "10.203.0.1"))
                cfg["paused"] = {}
                self.rules(app.build_allowlist(cfg))
                self.assertTrue(self.connects(self.client, "10.203.0.1"))
                self.assertEqual(cfg[key], [entry])
        self.command("nft", "list", "table", "inet", "unrelated", namespace=self.server)

    def test_ipv6_is_never_filtered(self):
        self.echo_server(self.server, "fd42:203::1")
        self.echo_server(self.server, "10.203.0.1")
        # 客户端的 IPv4 不在白名单：IPv4 被拦截，IPv6 不经过本程序、始终可达。
        self.rules(["10.203.0.3"])
        client = self.start(self.client, PERSISTENT_CLIENT, "fd42:203::1", 8080)
        self.assertEqual(self.read_line(client), "connected")
        self.assertFalse(self.connects(self.client, "10.203.0.1"))
        for mode in app.PING_MODES:
            rules = app.render_rules(["10.203.0.3"], ping_mode=mode, blocked_ips=["10.203.0.2"])
            self.command("nft", "-f", "-", namespace=self.server, input_text=rules)
            self.assertTrue(self.connects(self.client, "fd42:203::1"), mode)
            self.command("ping", "-6", "-c", "1", "-W", "2", "fd42:203::1", namespace=self.client)
        client.stdin.write("continue\n")
        client.stdin.flush()
        self.assertEqual(self.read_line(client), "passed")

    def test_upgrade_removes_legacy_inet_table(self):
        self.echo_server(self.server, "fd42:203::1")
        legacy = """add table inet vps_wl
delete table inet vps_wl
table inet vps_wl {
 chain input {
  type filter hook input priority 10; policy drop;
  iifname "lo" accept
  meta l4proto ipv6-icmp accept
 }
}
"""
        self.command("nft", "-f", "-", namespace=self.server, input_text=legacy)
        self.assertFalse(self.connects(self.client, "fd42:203::1"))
        self.rules(["10.203.0.3"])
        self.assertTrue(self.connects(self.client, "fd42:203::1"))
        tables = self.command("nft", "list", "tables", namespace=self.server).stdout
        self.assertIn("table ip vps_wl", tables)
        self.assertNotIn("table inet vps_wl", tables)
        self.rules([], enabled=False)
        self.assertNotIn("vps_wl", self.command("nft", "list", "tables", namespace=self.server).stdout)
        self.command("nft", "list", "table", "inet", "unrelated", namespace=self.server)

    def test_ping_modes(self):
        def pings():
            return self.command("ping", "-c", "1", "-W", "1", "10.203.0.1", namespace=self.client,
                                check=False).returncode == 0
        for mode, allowed, expected in (("whitelist", ["10.203.0.2"], True), ("whitelist", ["10.203.0.3"], False),
                                        ("off", ["10.203.0.2"], False), ("all", ["10.203.0.3"], True)):
            with self.subTest(mode=mode, allowed=allowed):
                rules = app.render_rules(allowed, ping_mode=mode)
                self.command("nft", "-f", "-", namespace=self.server, input_text=rules)
                self.assertEqual(pings(), expected)

    def test_dnat_published_port_rechecks_existing_connections(self):
        self.echo_server(self.container, "10.204.0.2")
        nat = """table ip test_nat {
 chain prerouting {
  type nat hook prerouting priority dstnat;
  ip daddr 10.203.0.1 tcp dport 8080 dnat to 10.204.0.2:8080
 }
}
"""
        self.command("nft", "-f", "-", namespace=self.server, input_text=nat)
        self.rules(["10.203.0.2", "10.203.0.3"])
        client = self.start(self.client, PERSISTENT_CLIENT, "10.203.0.1", 8080)
        self.assertEqual(self.read_line(client), "connected")
        self.rules(["10.203.0.3"])
        client.stdin.write("continue\n")
        client.stdin.flush()
        self.assertEqual(self.read_line(client), "blocked")
        self.assertFalse(self.connects(self.client, "10.203.0.1"))
        self.command("nft", "list", "table", "ip", "test_nat", namespace=self.server)
        self.rules(["10.203.0.3"], protect_dnat=False)
        self.assertTrue(self.connects(self.client, "10.203.0.1"))


if __name__ == "__main__":
    unittest.main()
