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

    # Bare paths are in your own namespace; a folder destination keeps the file name.
    def nd(*args, **kw):
        return subprocess.run([f"{BIN}/near-drive", "--no-interactive", "--network", "local", "--account", ACCOUNT, *args],
                              env=env, cwd=t, stdin=subprocess.DEVNULL, capture_output=True, text=True, **kw)
    r = nd("put", src, "docs/")
    assert r.returncode == 0 and "near://alice.local/docs/notes.txt" in r.stderr, r.stderr
    r = nd("get", "docs/notes.txt")
    assert r.stdout == "hello from interactive mode\n", r
    r = nd("put", src)
    assert r.returncode == 0 and "near://alice.local/notes.txt " in r.stderr, r.stderr
    ok("bare paths: put notes.txt docs/ -> near://alice.local/docs/notes.txt; get docs/notes.txt")

    # up / down: background S3 endpoint.
    s3_port = free_port()
    r = nd("up", "--listen", f"127.0.0.1:{s3_port}", timeout=30)
    assert r.returncode == 0, r.stderr
    exports = dict(l[len("export "):].split("=", 1) for l in r.stdout.splitlines() if l.startswith("export "))
    assert exports["AWS_ENDPOINT_URL"] == f"http://127.0.0.1:{s3_port}", r.stdout
    r2 = nd("up", "--listen", f"127.0.0.1:{s3_port}")
    assert r2.returncode == 0 and "already running" in r2.stderr, r2.stderr
    import boto3
    s3 = boto3.client("s3", endpoint_url=exports["AWS_ENDPOINT_URL"], aws_access_key_id=exports["AWS_ACCESS_KEY_ID"],
                      aws_secret_access_key=exports["AWS_SECRET_ACCESS_KEY"], region_name="us-east-1")
    body = s3.get_object(Bucket=ACCOUNT, Key="docs/notes.txt")["Body"].read()
    assert body == b"hello from interactive mode\n", body
    r = nd("down")
    assert r.returncode == 0 and "stopped" in r.stderr, r.stderr
    try:
        socket.create_connection(("127.0.0.1", s3_port), timeout=1).close()
        raise AssertionError("s3 endpoint still listening after down")
    except OSError:
        pass
    assert "not running" in nd("down").stderr
    ok("up: background S3 endpoint (boto3 reads docs/notes.txt); down stops it")

    # Sync: register a folder, the background service keeps it in sync; a second folder pulls it.
    laptop, desktop = os.path.join(t, "Laptop"), os.path.join(t, "Desktop")
    r = nd("sync", "add", laptop, "Shared")
    assert r.returncode == 0 and "near://alice.local/Shared/" in r.stdout, r
    r = nd("up", "--no-s3", timeout=30)
    assert r.returncode == 0 and laptop in r.stdout, r
    os.makedirs(os.path.join(laptop, "plans"))
    with open(os.path.join(laptop, "plans", "q1.md"), "w") as f:
        f.write("# Q1\n")
    for _ in range(60):
        time.sleep(0.5)
        if "Shared/plans/q1.md" in nd("ls", "Shared/").stdout:
            break
    else:
        raise AssertionError("background sync did not upload; log:\n" + open(os.path.join(t, "home", "daemon.log")).read())
    r = nd("sync", "run", desktop, "Shared")
    assert r.returncode == 0 and "down   plans/q1.md" in r.stderr, r
    with open(os.path.join(desktop, "plans", "q1.md")) as f:
        assert f.read() == "# Q1\n"
    r = nd("sync", "status")
    assert "running" in r.stdout and "last sync" in r.stdout, r.stdout
    assert "stopped" in nd("down").stderr
    assert "stopped syncing" in nd("sync", "remove", laptop).stdout

    # Files on demand: mount the same folder; reading a file downloads it.
    if os.path.exists("/dev/fuse"):
        mp = os.path.join(t, "mnt")
        p = subprocess.Popen([f"{BIN}/near-drive", "--no-interactive", "--network", "local", "--account", ACCOUNT, "mount", mp, "Shared"],
                             env=env, cwd=t, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        for _ in range(40):
            time.sleep(0.25)
            if os.path.isdir(os.path.join(mp, "plans")):
                break
        with open(os.path.join(mp, "plans", "q1.md")) as f:
            assert f.read() == "# Q1\n"
        p.send_signal(2)  # Ctrl-C
        assert "unmounted" in p.communicate(timeout=20)[1]
        assert os.listdir(mp) == []
        ok("mount: files listed, downloaded on open; Ctrl-C unmounts")
    ok("sync: `sync add` + `up --no-s3` syncs in the background; `sync run` pulls into a second folder")

    # Non-interactive: a missing argument is an error, not a prompt.
    r = subprocess.run([f"{BIN}/near-drive", "--network", "local", "--account", ACCOUNT, "get"], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert r.returncode != 0 and "missing" in r.stderr, r.stderr
    ok("without a terminal, missing arguments fail instead of prompting")
finally:
    gw.kill()
    subprocess.run(["rm", "-rf", t])

print(f"\n{passed} passed")
