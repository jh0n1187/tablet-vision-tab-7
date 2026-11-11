"""Offline AVB preparation for the acquired 2025 T307F firmware (run in WSL).

Produces a stock-content key-acceptance test and the final custom image set.
Does not access USB, execute adb/fastboot, or retain any private signing key.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import argparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/stock-inspection/vendor'))
import avbtool

DSU = ROOT / 'analise-firmware/desbloqueio-T307F/dsu'
OUT = ROOT / 'analise-firmware/central-inteligente/candidato-2025-v2'
BACKUP = ROOT / 'backup' / (DSU / 'firmware-backup-path.txt').read_text().replace('\\', '/').rsplit('/', 1)[-1]
STOCK = DSU / 'stock-2025-verified-parts'
AVBTOOL = ROOT / 'tools/stock-inspection/vendor/avbtool.py'
AVB = avbtool.Avb()


def read(path):
    return json.loads(path.read_text())


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def parse(path):
    return AVB._parse_image(avbtool.ImageHandler(str(path), read_only=True))


def cli(*args):
    r = subprocess.run(['python3', str(AVBTOOL), *map(str, args)],
                       capture_output=True, timeout=300)
    if r.returncode:
        raise RuntimeError((r.stdout + r.stderr).decode(errors='replace'))
    return r.stdout


def stock_path(name):
    logical = STOCK / (name + '_a.img')
    return logical if logical.exists() else BACKUP / (name + '_a.img')


def meta(path, original, descriptors, key):
    _, header, _, size = parse(original)
    assert header.flags == 0 and header.public_key_metadata_size == 0
    blob = AVB._generate_vbmeta_blob(
        algorithm_name='SHA256_RSA2048', key_path=str(key),
        public_key_metadata_path=None, descriptors=descriptors,
        chain_partitions=[], rollback_index=header.rollback_index, flags=0,
        rollback_index_location=header.rollback_index_location,
        props=[], props_from_file=[], kernel_cmdlines=[],
        setup_rootfs_from_kernel=None, ht_desc_to_setup=None,
        include_descriptors_from_image=[], signing_helper=None,
        signing_helper_with_files=None, release_string=None,
        append_to_release_string=None,
        required_libavb_version_minor=header.required_libavb_version_minor)
    assert len(blob) <= size
    with path.open('xb') as f:
        f.write(blob)
        f.write(bytes(size - len(blob)))


def descriptors(original, public, replacements):
    _, _, source, _ = parse(original)
    result = []
    for item in source:
        desc = copy.deepcopy(item)
        if isinstance(desc, avbtool.AvbChainPartitionDescriptor):
            assert desc.partition_name in {'vbmeta_system', 'vbmeta_vendor'}
            desc.public_key = public
        elif isinstance(desc, avbtool.AvbHashtreeDescriptor) and desc.partition_name in replacements:
            desc = copy.deepcopy(replacements[desc.partition_name])
        else:
            assert desc.encode() == item.encode()
        result.append(desc)
    return result


def validate_set(folder, key, pubfile):
    # Check the child keys too: follow_chain alone doesn't compare those keys.
    expected = pubfile.read_bytes()
    for name in ['vbmeta', 'vbmeta_system', 'vbmeta_vendor']:
        path = folder / (name + '.img')
        data = path.read_bytes()
        _, h, _, _ = parse(path)
        start = 256 + h.authentication_data_block_size + h.public_key_offset
        assert data[start:start + h.public_key_size] == expected
        assert h.flags == 0
    log = cli('verify_image', '--image', folder / 'vbmeta.img', '--key', key,
              '--follow_chain_partitions',
              '--expected_chain_partition', 'vbmeta_system:1:' + str(pubfile),
              '--expected_chain_partition', 'vbmeta_vendor:2:' + str(pubfile))
    (folder / 'verification.txt').write_bytes(log)
    print(folder.name + ': complete AVB signature/hash/tree verification PASS', flush=True)


def main():
    global OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', choices=['v2','v3'], default='v2')
    args = parser.parse_args()
    acceptance_source = None
    if args.revision == 'v3':
        previous = OUT
        assert read(previous / 'post-flash-verification.json')['all_match']
        acceptance_source = previous / 'signed'
        OUT = ROOT / 'analise-firmware/central-inteligente/candidato-2025-v3'
    assert read(OUT / 'plano-limpeza-2025.json')['removed_packages'] == 49
    assert read(DSU / 'restore-identical-test.json')['post_write_hash_verified']
    assert read(DSU / 'bootloader-restore-identical-test.json')['readback_verified']
    assert read(BACKUP / 'manifest.json')['acquisition_complete']
    signed, acceptance = OUT / 'signed', OUT / 'avb-acceptance-test'
    signed.mkdir()
    acceptance.mkdir()
    public_file = OUT / 'central-2025.avbpubkey'
    report = {'base': 'T307TSF.BR.OPEN.2025092701', 'removed_packages': 49,
              'avb_flags': 0, 'verification_disabled': False,
              'hashtree_disabled': False, 'private_key_retained': False,
              'fec': 'New system/product/vendor trees have no FEC; dm-verity remains enabled. Original module trees retain FEC.',
              'parts': {}}
    with tempfile.TemporaryDirectory(prefix='t307-custom-avb-') as temp:
        key = Path(temp) / 'private.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(key), '2048'],
                       check=True, capture_output=True)
        key.chmod(0o600)
        cli('extract_public_key', '--key', key, '--output', public_file)
        replacements = {}
        for name in ['system', 'product', 'vendor']:
            source = OUT / (name + '_a.img')
            validation = read(OUT / (name + '-validation.json'))
            assert validation['passed'] and not validation['errors']
            assert sha(source) == validation['sha256']
            original = stock_path(name)
            _, old_header, old_descs, capacity = parse(original)
            tree = next(d for d in old_descs if isinstance(d, avbtool.AvbHashtreeDescriptor))
            assert tree.partition_name == name and tree.flags == 0
            assert old_header.flags == 0 and tree.data_block_size == 4096
            dest = signed / (name + '.img')
            shutil.copyfile(source, dest)
            props = []
            for d in old_descs:
                if isinstance(d, avbtool.AvbPropertyDescriptor):
                    props += ['--prop', d.key + ':' + d.value.decode()]
            cli('add_hashtree_footer', '--image', dest, '--partition_name', name,
                '--partition_size', capacity, '--algorithm', 'SHA256_RSA2048',
                '--key', key, '--hash_algorithm', tree.hash_algorithm,
                '--salt', tree.salt.hex(), '--do_not_generate_fec',
                '--rollback_index', old_header.rollback_index,
                '--rollback_index_location', old_header.rollback_index_location,
                *props)
            _, new_header, new_descs, new_size = parse(dest)
            new_tree = next(d for d in new_descs if isinstance(d, avbtool.AvbHashtreeDescriptor))
            assert new_size == capacity and new_header.flags == 0
            assert new_tree.image_size == source.stat().st_size and new_tree.fec_num_roots == 0
            replacements[name] = new_tree
            (signed / (name + '-verification.txt')).write_bytes(
                cli('verify_image', '--image', dest, '--key', key))
            report['parts'][name] = {'target': name + '_a', 'size': new_size,
                                     'data_size': new_tree.image_size,
                                     'sha256': sha(dest), 'data_sha256': validation['sha256'],
                                     'root_digest': new_tree.root_digest.hex()}
            print(name + ': footer, signature, hashtree, original capacity PASS', flush=True)
        for folder, trees in [(acceptance, {}), (signed, replacements)]:
            for name in ['vbmeta', 'vbmeta_system', 'vbmeta_vendor']:
                original = acceptance_source / (name + '.img') if folder == acceptance and acceptance_source else stock_path(name)
                desc = descriptors(original, public_file.read_bytes(), trees)
                meta(folder / (name + '.img'), original, desc, key)
            for name in ['boot', 'init_boot', 'vendor_boot', 'dtbo', 'system_dlkm', 'vendor_dlkm']:
                os.link(stock_path(name), folder / (name + '.img'))
            if folder == acceptance:
                for name in ['system', 'product', 'vendor']:
                    original = acceptance_source / (name + '.img') if acceptance_source else stock_path(name)
                    os.link(original, folder / (name + '.img'))
            validate_set(folder, key, public_file)
    for name in ['vbmeta', 'vbmeta_system', 'vbmeta_vendor']:
        report['parts'][name] = {'target': name + '_a',
                                 'size': (signed / (name + '.img')).stat().st_size,
                                 'sha256': sha(signed / (name + '.img'))}
    report['public_key_sha256'] = sha(public_file)
    report['acceptance_test'] = ('Known-good installed v2 contents' if acceptance_source else 'Stock contents') + '; rollback indices preserved; only root/chain keys and signatures changed'
    report['physical_key_acceptance'] = 'NOT_YET_TESTED'
    report['custom_images_flashed'] = False
    (OUT / 'signed-manifest.json').write_text(json.dumps(report, indent=2))
    print('Private signing key removed; offline preparation complete', flush=True)


if __name__ == '__main__':
    main()
