"""Read MSI database/embedded cabinets only. Never starts an install session.

Uses MsiOpenDatabaseW mode 0 and SELECT queries; no msiexec or custom actions.
"""
import ctypes as c
import json
from pathlib import Path
import re
import sys


class Reader:
    def __init__(self, path):
        self.api = c.WinDLL('msi.dll')
        self.handles = []
        signatures = {
            'MsiOpenDatabaseW': ([c.c_wchar_p, c.c_void_p, c.POINTER(c.c_uint)], c.c_uint),
            'MsiDatabaseOpenViewW': ([c.c_uint, c.c_wchar_p, c.POINTER(c.c_uint)], c.c_uint),
            'MsiViewExecute': ([c.c_uint, c.c_uint], c.c_uint),
            'MsiViewFetch': ([c.c_uint, c.POINTER(c.c_uint)], c.c_uint),
            'MsiViewGetColumnInfo': ([c.c_uint, c.c_int, c.POINTER(c.c_uint)], c.c_uint),
            'MsiRecordGetFieldCount': ([c.c_uint], c.c_uint),
            'MsiRecordGetStringW': ([c.c_uint, c.c_uint, c.c_wchar_p, c.POINTER(c.c_uint)], c.c_uint),
            'MsiRecordReadStream': ([c.c_uint, c.c_uint, c.c_void_p, c.POINTER(c.c_uint)], c.c_uint),
            'MsiCloseHandle': ([c.c_uint], c.c_uint),
        }
        for name, (args, ret) in signatures.items():
            fn = getattr(self.api, name); fn.argtypes = args; fn.restype = ret
        handle = c.c_uint()
        self.check(self.api.MsiOpenDatabaseW(str(Path(path).resolve()), None, c.byref(handle)))
        self.db = handle.value
        self.handles.append(self.db)

    @staticmethod
    def check(result):
        if result != 0:
            raise OSError('Read-only MSI API status: ' + str(result))

    def string(self, record, field):
        count = c.c_uint()
        rc = self.api.MsiRecordGetStringW(record, field, None, c.byref(count))
        if rc not in (0, 234): self.check(rc)
        buffer = c.create_unicode_buffer(count.value + 1)
        count.value += 1
        self.check(self.api.MsiRecordGetStringW(record, field, buffer, c.byref(count)))
        return buffer.value

    def rows(self, query):
        if not query.startswith('SELECT '):
            raise ValueError('SELECT only')
        view = c.c_uint()
        self.check(self.api.MsiDatabaseOpenViewW(self.db, query, c.byref(view)))
        self.handles.append(view.value)
        self.check(self.api.MsiViewExecute(view, 0))
        columns = c.c_uint()
        self.check(self.api.MsiViewGetColumnInfo(view, 0, c.byref(columns)))
        try:
            names = [self.string(columns, n) for n in range(1, self.api.MsiRecordGetFieldCount(columns) + 1)]
        finally:
            self.api.MsiCloseHandle(columns)
        while True:
            row = c.c_uint()
            rc = self.api.MsiViewFetch(view, c.byref(row))
            if rc == 259: return
            self.check(rc)
            try:
                yield row.value, names
            finally:
                self.api.MsiCloseHandle(row)

    def table(self, name):
        if not re.fullmatch(r'[A-Za-z0-9_]+', name): raise ValueError('Invalid table')
        return [{key: self.string(row, i) for i, key in enumerate(names, 1)}
                for row, names in self.rows('SELECT * FROM `' + name + '`')]

    def cabinet(self, name, output):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.cab', name): raise ValueError('Invalid embedded cabinet')
        matches = 0
        for row, names in self.rows("SELECT `Data` FROM `_Streams` WHERE `Name`='" + name + "'"):
            matches += 1
            with Path(output).open('xb') as stream:
                total = 0
                while True:
                    data = c.create_string_buffer(65536); count = c.c_uint(65536)
                    self.check(self.api.MsiRecordReadStream(row, 1, data, c.byref(count)))
                    if count.value == 0: break
                    total += count.value
                    if total > 32 * 1024 * 1024: raise ValueError('Cabinet size limit')
                    stream.write(data.raw[:count.value])
        if matches != 1: raise ValueError('Expected one embedded cabinet')

    def close(self):
        for handle in reversed(self.handles): self.api.MsiCloseHandle(handle)
        self.handles.clear()


def main():
    path, output = map(Path, sys.argv[1:])
    output.mkdir(exist_ok=False)
    reader = Reader(path)
    try:
        names = [r['Name'] for r in reader.table('_Tables')]
        wanted = {'Property','Media','File','Directory','Component','CustomAction','InstallExecuteSequence',
                  'ServiceInstall','ServiceControl','Registry','RemoveRegistry','Environment',
                  'LaunchCondition','Upgrade','Wix4FirewallException','WixFirewallException','MsiDigitalSignature'}
        data = {'read_only_database': True, 'tables': names,
                'data': {name: reader.table(name) for name in names if name in wanted}}
        (output/'tables.json').write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
        cabinets = []
        for row in data['data'].get('Media', []):
            cabinet = row['Cabinet']
            if not cabinet.startswith('#'): raise ValueError('External cabinet not expected')
            name = cabinet[1:]
            reader.cabinet(name, output/name)
            cabinets.append(name)
        print(json.dumps({'tables':len(names),'cabinets':cabinets,'installation_executed':False}))
    finally:
        reader.close()


if __name__ == '__main__': main()
