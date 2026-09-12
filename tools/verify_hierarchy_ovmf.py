#!/usr/bin/env python3
"""Execute authored hierarchy transactions inside x86 EFI; no original inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def markers(path):
    rows = path.read_bytes().split(b'\n')[:-1] if path.exists() else []
    return [text for row in rows if (text := re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', row).removesuffix(b'\r').decode(errors='replace')).startswith('NXPERM:')]


def configurations():
    result = [(4096, 1, 1, 2, 0, 1, False, 1)]
    for granule in (4096, 16384):
        for profile in (1, 3):
            for ap in range(4):
                for parent in range(4):
                    for el in (0, 1):
                        for warm in (False, True):
                            for op in (1, 2, 3):
                                result.append((granule, profile, ap, parent, 0, el, warm, op))
            for xn in (1, 2):
                for parent in (0, 2):
                    for el in (0, 1):
                        for warm in (False, True):
                            for op in (1, 2, 3):
                                result.append((granule, profile, 1, parent, xn, el, warm, op))
    assert len(result) == 961
    return result


def expected_case(index, config, old=False):
    granule, profile, ap, parent, xn, el, warm, op = config
    # Independent source-contract rows: EL1 data, EL0 data, EL1 fetch.
    matrix = [
        [('rw', '', True), ('rw', '', True), ('r', '', True), ('r', '', True)],
        [('rw', 'rw', False), ('rw', '', True), ('r', 'r', True), ('r', '', True)],
        [('r', '', True), ('r', '', True), ('r', '', True), ('r', '', True)],
        [('r', 'r', True), ('r', '', True), ('r', 'r', True), ('r', '', True)],
    ]
    privileged, user, execute = matrix[ap][parent]
    allowed = ((execute and not xn & 1) if el else not xn & 2) if op == 1 else ('r' if op == 2 else 'w') in (privileged if el else user)
    retired = (1 if op == 1 else 2) if allowed else 0
    esr = 0 if allowed else ((0x20 + el if op == 1 else 0x24 + el) << 26) | (1 << 25) | 15 | (64 if op == 3 else 0)
    row = dict(id=index, granule=granule, profile=profile, ap=ap, parent=parent, xn=xn, el=el,
               warm=str(warm).lower(), op=op, upper=str(bool((ap ^ parent ^ el) & 1)).lower(),
               allowed=str(allowed).lower(), status=1 if allowed else 16 if op == 1 else 17,
               retired=retired, fetch=retired + int(not allowed), data=int(op != 1),
               completed=int(allowed and op != 1), provider=0, reply=0 if allowed else 1,
               level=0xffffffff if allowed else 3, context=0 if allowed else 4 if warm else 3,
               esr=esr, **{'pass': 'true'})
    if old:
        assert index == 0
        row.update(status=4, retired=0, fetch=1, data=0, completed=0, provider=1,
                   reply=2, level=0, context=2, esr=0, **{'pass': 'false'})
    return row


def parse_case(row):
    pairs = [token.split('=', 1) for token in row.split()[2:]]
    if any(len(p) != 2 for p in pairs) or len({p[0] for p in pairs}) != len(pairs):
        return None
    try:
        return {k: v if k in ('warm', 'upper', 'allowed', 'pass') else int(v, 0) for k, v in pairs}
    except ValueError:
        return None


def group_alive(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi-probe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expect-old-rejection', action='store_true')
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    if not 10 <= args.timeout <= 120:
        parser.error('timeout must be between 10 and 120 seconds including cleanup')
    module = Path(__file__).resolve().parents[1]
    inputs = dict(efi=args.efi_probe.resolve(strict=True), runner=Path(__file__).resolve(),
                  source=module/'src/hierarchy_probe.rs', assembly=module/'docs/fixtures/hierarchy_scalar.S',
                  ovmf_code=Path('/usr/share/OVMF/OVMF_CODE_4M.fd'), ovmf_vars=Path('/usr/share/OVMF/OVMF_VARS_4M.fd'))
    before = {name: sha(path) for name, path in inputs.items()}
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    if any(',' in str(p) for p in [out, *inputs.values()]):
        parser.error('QEMU file paths cannot contain commas')
    commands = []
    for argv in [
        ['clang-18', '--target=aarch64-none-elf', '-c', str(inputs['assembly']), '-o', str(out/'probe.o')],
        ['llvm-objcopy-18', '-O', 'binary', '--only-section=.text', str(out/'probe.o'), str(out/'probe.bin')],
    ]:
        compiled = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        commands.append(dict(argv=argv, return_code=compiled.returncode, stdout=compiled.stdout, stderr=compiled.stderr))
        assert compiled.returncode == 0, commands[-1]
    words = re.search(r'const WORDS\s*:\s*\[u32;\s*5\]\s*=\s*\[(.*?)\];', inputs['source'].read_text(), re.S)
    assert words
    values = [int(n.strip().replace('_', ''), 0) for n in words[1].split(',') if n.strip()]
    assert struct.pack('<5I', *values) == (out/'probe.bin').read_bytes()
    shutil.copyfile(inputs['assembly'], out/'probe.S')
    boot = out/'esp/EFI/BOOT'
    boot.mkdir(parents=True)
    shutil.copyfile(inputs['efi'], boot/'BOOTX64.EFI')
    shutil.copyfile(inputs['ovmf_vars'], out/'vars.fd')
    serial = out/'serial.log'
    argv = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg,smm=off', '-cpu', 'Nehalem',
            '-m', '256', '-smp', '1', '-display', 'none', '-vga', 'std', '-monitor', 'none',
            '-serial', f'file:{serial}', '-net', 'none', '-no-reboot',
            '-drive', f'if=pflash,format=raw,readonly=on,file={inputs["ovmf_code"]}',
            '-drive', f'if=pflash,format=raw,file={out/"vars.fd"}',
            '-drive', f'format=raw,file=fat:rw:{out/"esp"}']
    (out/'command.json').write_text(json.dumps(argv, indent=2)+'\n')
    start = time.monotonic()
    deadline = start + args.timeout
    failure = None
    stopped = False
    with (out/'stdout.log').open('wb') as stdout, (out/'stderr.log').open('wb') as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            while process.poll() is None and time.monotonic() < deadline - 6:
                if any(row.startswith(('NXPERM: PASS ', 'NXPERM: FAIL ')) for row in markers(serial)):
                    break
                time.sleep(.1)
        except Exception as error:
            failure = repr(error)
        finally:
            if group_alive(process.pid):
                stopped = True
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=min(3, max(.01, deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=max(.01, deadline-time.monotonic()))
            if group_alive(process.pid):
                os.killpg(process.pid, signal.SIGKILL)
                while group_alive(process.pid) and time.monotonic() < deadline:
                    time.sleep(.02)
    actual = markers(serial)
    rows = []
    for row in actual:
        if not rows or row != rows[-1]:
            rows.append(row)
    cases = [parse_case(row) for row in rows if row.startswith('NXPERM: CASE ')]
    entry = 'NXPERM: ENTRY host=x86_64 authored=true profile=immutable-hierarchy'
    configs = configurations()
    if args.expect_old_rejection:
        semantic = (len(rows) == 3 and rows[0] == entry and rows[-1] == 'NXPERM: FAIL completed=0 status=COMPROMISED_DATA'
                    and cases == [expected_case(0, configs[0], old=True)])
    else:
        semantic = (len(rows) == 963 and rows[0] == entry
                    and rows[-1] == 'NXPERM: PASS cases=961 physical_boot_verified=false macos_boot_verified=false'
                    and cases == [expected_case(i, config) for i, config in enumerate(configs)])
    after = {name: sha(path) for name, path in inputs.items()}
    reaped = process.poll() is not None and not group_alive(process.pid)
    passed = semantic and before == after and sha(boot/'BOOTX64.EFI') == before['efi'] and failure is None and process.returncode == 0 and reaped
    result = dict(schema='nextcore.authored-hierarchy-efi.v1', passed=passed, cases=cases, markers=actual,
                  expect_old_rejection=args.expect_old_rejection, input_paths={n:str(p) for n,p in inputs.items()},
                  input_sha256_before=before, input_sha256_after=after, assembly_matches=True, commands=commands,
                  elapsed_seconds=round(time.monotonic()-start,3), qemu_exit_code=process.returncode,
                  process_reaped=reaped, process_group_exited=not group_alive(process.pid), stopped_by_harness=stopped,
                  host_failure=failure, original_inputs_used=False, physical_boot_verified=False, macos_boot_verified=False,
                  scope='Actual native load/store/fetch under hierarchy, both ELs/granules/immutable profiles and cold/warm service. VA halves and table levels are distributed, not a complete Cartesian product. Leaf/block and fault-priority breadth is separately qualified by native and Arm tests.')
    (out/'receipt.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(passed=passed, cases=len(cases), old=args.expect_old_rejection, output=str(out))))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
