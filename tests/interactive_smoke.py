#!/usr/bin/env python3
"""Interactive-mode smoke test for `near-drive`, driven through a pty (pexpect).

Dev gateway (configured keys, no chain), near-cli config pointing at an
unreachable RPC, so the request key comes from near-cli's legacy keychain dir
("not checked onchain"). Walks: keygen menu, the top-level menu -> put,
get with listing pick, rm with confirmation.

    cargo build && python3 tests/interactive_smoke.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import pexpect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "debug")
DOWN, ENTER = "\x1b[B", "\r"
ACCOUNT = "alice.local"
passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  ok   {msg}")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


t = tempfile.mkdtemp(prefix="drive-interactive.")
creds = os.path.join(t, "creds")
cfgdir = os.path.join(t, "config", "near-cli")
os.makedirs(os.path.join(creds, "localnet", ACCOUNT))
os.makedirs(cfgdir)
dead_rpc = f"http://127.0.0.1:{free_port()}/"
with open(os.path.join(cfgdir, "config.toml"), "w") as f:
    f.write(
        f'version = "4"\ncredentials_home_dir = "{creds}"\n\n[network_connection.local]\nnetwork_name = "localnet"\n'
        f'rpc_url = "{dead_rpc}"\nwallet_url = "http://127.0.0.1/"\nexplorer_transaction_url = "http://127.0.0.1/"\n'
    )
key_file = os.path.join(t, "alice.json")
pk = subprocess.check_output([f"{BIN}/near-drive", "--no-interactive", "--account", ACCOUNT, "dev-key", "--out", key_file], text=True).strip()
os.rename(key_file, os.path.join(creds, "localnet", ACCOUNT, pk.replace(":", "_") + ".json"))
with open(os.path.join(creds, "accounts.json"), "w") as f:
    json.dump([{"account_id": ACCOUNT, "used_as_signer": True}], f)

gw_port = free_port()
with open(os.path.join(t, "gw.json"), "w") as f:
    json.dump({"listen": f"127.0.0.1:{gw_port}", "data_dir": os.path.join(t, "gw"), "dev_keys": {ACCOUNT: [pk]}}, f)
gw = subprocess.Popen([f"{BIN}/near-drive-gateway", "--config", os.path.join(t, "gw.json")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(40):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{gw_port}/healthz")
        break
    except OSError:
        time.sleep(0.25)

env = dict(os.environ, XDG_CONFIG_HOME=os.path.join(t, "config"), NEAR_DRIVE_GATEWAY=f"http://127.0.0.1:{gw_port}",
           NEAR_DRIVE_HOME=os.path.join(t, "home"), TERM="xterm", NO_COLOR="1")
for k in ("NEAR_DRIVE_ACCOUNT", "NEAR_DRIVE_NETWORK", "NEAR_DRIVE_CREDENTIALS"):
    env.pop(k, None)


def spawn(*args):
    return pexpect.spawn(f"{BIN}/near-drive", list(args), env=env, cwd=t, encoding="utf-8", timeout=20, dimensions=(40, 160))


try:
    # keygen: account picked from near-cli's accounts, key type from a menu.
    p = spawn("--network", "local", "keygen")
    p.expect("Which account")
    p.send(ENTER)  # alice.local (first)
    p.expect("How should your encryption key be created")
    p.send(DOWN + ENTER)  # random
    p.expect("near drive|near-drive")
    p.expect(r"keygen --random")
    p.expect("root key written")
    p.expect(pexpect.EOF)
    assert os.path.exists(os.path.join(t, "home", "keys", f"{ACCOUNT}.root"))
    ok("keygen: account and key type chosen from menus; equivalent command printed")

    # Top-level menu -> put, network + account + file prompts.
    src = os.path.join(t, "notes.txt")
    with open(src, "w") as f:
        f.write("hello from interactive mode\n")
    p = spawn()
    p.expect("What do you want to do")
    p.send(DOWN + DOWN + ENTER)  # ls, get, put
    p.expect("Which network")
    p.send(DOWN + DOWN + ENTER)  # mainnet, testnet, local
    p.expect("Which account")
    p.send(ENTER)
    p.expect("File to upload")
    p.send(src + ENTER)
    p.expect("Save as")
    p.send(ENTER)  # default near://alice.local/notes.txt
    p.expect("unencrypted")
    p.send(ENTER)  # default No
    p.expect(r"put \S*notes.txt near://alice.local/notes.txt")
    p.expect(r"near://alice.local/notes.txt seq=")
    p.expect(pexpect.EOF)
    ok("menu -> put: network, account, file, destination prompted; uploaded")

    # get: listing pick + save-to prompt.
    p = spawn("--network", "local", "--account", ACCOUNT, "get")
    p.expect("File to download")
    p.send(ENTER)  # near://alice.local/ -> listing
    p.expect("Pick a file")
    p.expect("notes.txt")
    p.send(ENTER)
    p.expect("Save to")
    p.send(ENTER)  # notes.txt in cwd
    p.expect("saved notes.txt")
    p.expect(pexpect.EOF)
    with open(os.path.join(t, "notes.txt")) as f:
        assert f.read() == "hello from interactive mode\n"
    ok("get: picked from listing, saved to the suggested file")

    # rm: pick + confirm.
    p = spawn("--network", "local", "--account", ACCOUNT, "rm")
    p.expect("File to delete")
    p.send(ENTER)
    p.expect("Pick a file")
    p.send(ENTER)
    p.expect("Delete near://alice.local/notes.txt")
    p.send("y" + ENTER)
    p.expect(pexpect.EOF)
    out = subprocess.check_output([f"{BIN}/near-drive", "--no-interactive", "--network", "local", "--account", ACCOUNT, "ls"], env=env, text=True)
    assert "notes.txt" not in out, out
    ok("rm: picked, confirmed, deleted")

    # Non-interactive: a missing argument is an error, not a prompt.
    r = subprocess.run([f"{BIN}/near-drive", "--network", "local", "--account", ACCOUNT, "get"], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert r.returncode != 0 and "missing" in r.stderr, r.stderr
    ok("without a terminal, missing arguments fail instead of prompting")
finally:
    gw.kill()
    subprocess.run(["rm", "-rf", t])

print(f"\n{passed} passed")
