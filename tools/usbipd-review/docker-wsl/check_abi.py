"""Container diagnostic only: C ABI, libc on /dev/null, fake USB tests.

Requires the reviewed kit mounted at /input/kit.zip. Never opens USBFS/usbmon.
"""
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

probe = subprocess.run(['/usr/local/bin/usbfs-abi-probe'],capture_output=True,text=True)
if probe.returncode != 0:
    raise RuntimeError(probe.stdout + probe.stderr)
abi = json.loads(probe.stdout)
assert abi['matches_reviewed_abi']
with zipfile.ZipFile('/input/kit.zip') as archive:
    assert all(not Path(p).is_absolute() and '..' not in Path(p).parts for p in archive.namelist())
    archive.extractall('/tmp/kit')
sys.path.insert(0,'/tmp/kit/tools/fel-readonly')
import linux_version_only as linux
import native_linux_validation as validation

assert all(value is False for value in validation.gates().values())
api = linux._UsbfsAPI()  # Bind libc, no USB device discovery or opening.
fd = os.open('/dev/null',os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    info = os.fstat(fd)
    assert stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev),os.minor(info.st_rdev)) == (1,3)
    try:
        api.bulk(fd,0x81,13,100)
    except OSError as error:
        assert error.errno == errno.ENOTTY
        null_errno = error.errno
    else:
        raise AssertionError('Unexpected USB ioctl success on /dev/null')
finally:
    os.close(fd)
tests = subprocess.run([sys.executable,'-B','-m','unittest','discover',
                        '-s','/tmp/kit/tools/fel-readonly/tests','-p','test_linux_version_only.py','-v'],
                       capture_output=True,text=True)
assert tests.returncode == 0,tests.stdout + tests.stderr
try:
    validation.native_host()
except validation.Rejected:
    policy = 'WSL still rejected by native hardware policy'
else:
    raise AssertionError('WSL accepted as native hardware')
versions = subprocess.run(['dpkg-query','-W','-f','${Package} ${Version}\n',
                           'gcc','libc6-dev','linux-libc-dev'],capture_output=True,text=True)
print(json.dumps({'C_abi':abi,'libc_null_ioctl_errno':null_errno,
                  'USB_device_opened':False,'libc_kernel_call_target':'/dev/null 1:3',
                  'physical_gates':validation.gates(),'native_hardware_policy':policy,
                  'Linux_VERSION_tests_exit':tests.returncode,
                  'Linux_VERSION_tests_output':tests.stdout + tests.stderr,
                  'diagnostic_package_versions':versions.stdout},indent=2))
