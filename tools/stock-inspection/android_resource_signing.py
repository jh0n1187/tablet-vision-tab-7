"""Local APK signing key: private backup, user-only ACL, DPAPI password.

No password or private key is emitted, passed literally on a command line, or
stored in source. Used only for the resource-only Central system overlays.
"""
from pathlib import Path
import csv
import ctypes
from ctypes import wintypes
import os
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[2]
JDK = Path('C:/Program Files/Android/Android Studio/jbr/bin')
TOOLS = Path.home() / 'AppData/Local/Android/Sdk/build-tools/36.0.0'


class Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def dpapi(data, encrypt):
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    buffer = ctypes.create_string_buffer(data)
    src = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    dst = Blob()
    fun = crypt.CryptProtectData if encrypt else crypt.CryptUnprotectData
    fun.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fun.restype = wintypes.BOOL
    if not fun(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(dst.data, dst.size)
    finally:
        kernel.LocalFree(ctypes.cast(dst.data, wintypes.HLOCAL))


def signing_environment():
    folder = ROOT / 'backup/private-signing'
    folder.mkdir(exist_ok=True)
    identity = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], text=True)
    sid = next(csv.reader([identity.strip()]))[1]
    assert sid.startswith('S-1-5-')
    subprocess.run(['icacls', str(folder), '/inheritance:r', '/grant:r',
                    '*' + sid + ':(OI)(CI)F'], check=True, capture_output=True)
    protected, key = folder / 'resource-key-password.dpapi', folder / 'central-resources.p12'
    if not protected.exists():
        assert not key.exists()
        password = secrets.token_urlsafe(36).encode()
        protected.write_bytes(dpapi(password, True))
    password = dpapi(protected.read_bytes(), False).decode()
    env = dict(os.environ, CENTRAL_RESOURCE_STOREPASS=password)
    if not key.exists():
        subprocess.run([str(JDK / 'keytool.exe'), '-genkeypair', '-keystore', str(key),
                        '-storetype', 'PKCS12', '-alias', 'central-resources',
                        '-storepass:env', 'CENTRAL_RESOURCE_STOREPASS',
                        '-keypass:env', 'CENTRAL_RESOURCE_STOREPASS',
                        '-keyalg', 'RSA', '-keysize', '2048', '-validity', '3650',
                        '-dname', 'CN=Central Inteligente Resources,O=Homelab,C=BR'],
                       env=env, check=True, capture_output=True)
    return key, env


def sign_apk(source, destination):
    key, env = signing_environment()
    aligned = destination.with_suffix('.aligned.apk')
    subprocess.run([str(TOOLS / 'zipalign.exe'), '-f', '4', str(source), str(aligned)],
                   check=True, capture_output=True)
    args = [str(JDK / 'java.exe'), '--enable-native-access=ALL-UNNAMED', '-jar',
            str(TOOLS / 'lib/apksigner.jar')]
    subprocess.run(args + ['sign', '--ks', str(key), '--ks-key-alias', 'central-resources',
                          '--ks-pass', 'env:CENTRAL_RESOURCE_STOREPASS',
                          '--key-pass', 'env:CENTRAL_RESOURCE_STOREPASS',
                          '--out', str(destination), str(aligned)],
                   env=env, check=True, capture_output=True)
    result = subprocess.run(args + ['verify', '--print-certs', str(destination)],
                            capture_output=True, check=True)
    destination.with_suffix('.signature.txt').write_bytes(result.stdout)
    aligned.unlink()
