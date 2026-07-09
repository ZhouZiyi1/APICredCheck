import argparse
import configparser
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class FridaServerConfig:
    local_path: Optional[Path] = Path("frida-server-16.4.10-android-arm64")
    remote_path: str = "/data/local/tmp/frida-server-16.4.10-android-arm64"
    use_su: bool = True
    auto_push: bool = True
    wait_seconds: float = 3.0


def read_frida_server_config(config_path: str = "config.ini") -> FridaServerConfig:
    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")
    section = "APP_HOOKER"

    local_path_text = parser.get(section, "AppHook_FRIDA_SERVER_LOCAL_PATH", fallback="").strip()
    local_path = Path(local_path_text) if local_path_text else None

    return FridaServerConfig(
        local_path=local_path,
        remote_path=parser.get(
            section,
            "AppHook_FRIDA_SERVER_REMOTE_PATH",
            fallback="/data/local/tmp/frida-server-16.4.10-android-arm64",
        ),
        use_su=parser.getboolean(section, "AppHook_FRIDA_SERVER_USE_SU", fallback=True),
        auto_push=parser.getboolean(section, "AppHook_FRIDA_SERVER_AUTO_PUSH", fallback=True),
        wait_seconds=parser.getfloat(section, "AppHook_FRIDA_SERVER_WAIT_SECONDS", fallback=3.0),
    )


def adb_available() -> bool:
    return shutil.which("adb") is not None


def run_adb(args, check: bool = False) -> subprocess.CompletedProcess:
    if not adb_available():
        raise FileNotFoundError("adb")
    return subprocess.run(
        ["adb", *args],
        check=check,
        capture_output=True,
        text=True,
        errors="replace",
    )


def ensure_device_connected() -> bool:
    proc = run_adb(["devices"])
    devices = [
        line.split()[0]
        for line in proc.stdout.splitlines()
        if line.strip().endswith("\tdevice")
    ]
    if not devices:
        print("[-] No adb device is connected or authorized.")
        return False
    print(f"[+] adb device connected: {devices[0]}")
    return True


def adb_shell(command: str, use_su: bool = False) -> subprocess.CompletedProcess:
    if use_su:
        command = "su -c " + shell_quote(command)
    return run_adb(["shell", command])


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def remote_file_exists(remote_path: str) -> bool:
    proc = adb_shell(f"[ -f {shell_quote(remote_path)} ] && echo exists || echo missing")
    return "exists" in proc.stdout


def is_frida_server_running(remote_path: str = "/data/local/tmp/frida-server-16.4.10-android-arm64") -> bool:
    remote_name = Path(remote_path).name
    command = (
        f"pidof {shell_quote(remote_name)} 2>/dev/null || "
        "pidof frida-server 2>/dev/null || "
        "ps -A | grep '[f]rida-server' || true"
    )
    proc = adb_shell(command)
    output = proc.stdout.strip()
    return bool(output)


def push_frida_server(config: FridaServerConfig) -> bool:
    if not config.local_path:
        return False
    local_path = config.local_path
    if not local_path.is_absolute():
        local_path = Path.cwd() / local_path
    if not local_path.is_file():
        print(f"[-] Local frida-server not found: {local_path}")
        return False

    print(f"[*] Pushing frida-server: {local_path} -> {config.remote_path}")
    proc = run_adb(["push", str(local_path), config.remote_path])
    if proc.returncode != 0:
        print(f"[-] adb push failed: {proc.stderr.strip() or proc.stdout.strip()}")
        return False

    chmod = adb_shell(f"chmod 755 {shell_quote(config.remote_path)}")
    if chmod.returncode != 0:
        print(f"[-] chmod failed: {chmod.stderr.strip() or chmod.stdout.strip()}")
        return False
    return True


def start_frida_server(config: Optional[FridaServerConfig] = None) -> bool:
    config = config or FridaServerConfig()
    if not ensure_device_connected():
        return False

    if is_frida_server_running(config.remote_path):
        print("[+] frida-server is already running.")
        return True

    if remote_file_exists(config.remote_path):
        print(f"[+] Remote frida-server exists: {config.remote_path}")
        chmod = adb_shell(f"chmod 755 {shell_quote(config.remote_path)}")
        if chmod.returncode != 0:
            print(f"[-] chmod failed: {chmod.stderr.strip() or chmod.stdout.strip()}")
            return False
    else:
        print(f"[*] Remote frida-server not found: {config.remote_path}")
        if not config.auto_push:
            print("[!] Auto push is disabled; set AppHook_FRIDA_SERVER_AUTO_PUSH=true or push it manually.")
            return False
        if not push_frida_server(config):
            return False

    log_path = "/data/local/tmp/frida-server.log"
    command = f"nohup {shell_quote(config.remote_path)} > {shell_quote(log_path)} 2>&1 &"
    print(f"[*] Starting frida-server at {config.remote_path}...")
    proc = adb_shell(command, use_su=config.use_su)
    if proc.returncode != 0:
        print(f"[-] Failed to start frida-server: {proc.stderr.strip() or proc.stdout.strip()}")
        return False

    time.sleep(config.wait_seconds)
    if is_frida_server_running(config.remote_path):
        print("[+] frida-server started.")
        return True

    print(f"[-] frida-server did not appear to start. Check device log: {log_path}")
    return False


def run_frida_server_cli() -> None:
    parser = argparse.ArgumentParser(description="Push and start frida-server on the connected Android device.")
    parser.add_argument("--config", default="config.ini", help="Path to config.ini.")
    args = parser.parse_args()
    if not start_frida_server(read_frida_server_config(args.config)):
        raise SystemExit(1)


if __name__ == "__main__":
    run_frida_server_cli()
