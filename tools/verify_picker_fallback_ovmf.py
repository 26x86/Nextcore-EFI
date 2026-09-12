#!/usr/bin/env python3
"""Run the authored protocol-failure probe; this is not physical boot proof."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi-probe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    probe = args.efi_probe.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    boot = output / 'esp/EFI/BOOT'
    boot.mkdir(parents=True)
    shutil.copyfile(probe, boot / 'BOOTX64.EFI')
    code = Path('/usr/share/OVMF/OVMF_CODE_4M.fd')
    variables = output / 'vars.fd'
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
    serial = output / 'serial.log'
    command = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg,smm=off', '-cpu', 'Nehalem',
               '-m', '256', '-smp', '1', '-display', 'none', '-vga', 'std', '-monitor', 'none',
               '-serial', f'file:{serial}', '-net', 'none', '-no-reboot',
               '-drive', f'if=pflash,format=raw,readonly=on,file={code}',
               '-drive', f'if=pflash,format=raw,file={variables}',
               '-drive', f'format=raw,file=fat:rw:{output / "esp"}']
    (output / 'command.json').write_text(json.dumps(command, indent=2))
    before = hashlib.sha256(probe.read_bytes()).hexdigest()
    start = time.monotonic()
    with (output / 'stdout.log').open('wb') as stdout, (output / 'stderr.log').open('wb') as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            while process.poll() is None and time.monotonic() - start < 50:
                if serial.exists() and re.search(r'NXPICKER: (PASS|FAIL)', serial.read_text(errors='replace')):
                    break
                time.sleep(.1)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', serial.read_text(errors='replace')) if serial.exists() else ''
    cases = re.findall(r'NXPICKER: CASE id=(\d+) injected=(\d+) gop=(\d+) keys=(\d+) writes=(\d+) child=(true|false) passed=(true|false) full_draws=(\d+)', text)
    passed = len(cases) == 5 and [c[0] for c in cases] == ['1', '2', '3', '4', '5']
    passed = passed and all(int(c[1]) > 0 and c[2] == '1' and c[6] == 'true' and
                           c[3] == ('0' if c[0] == '4' else '1') and
                           c[5] == ('false' if c[0] == '4' else 'true') and
                           c[7] == ('1' if c[0] == '5' else '0') for c in cases)
    passed = passed and text.count('NXTEST: EFI_ENTRY') >= 4 and all(
        f'PICKER_DISPLAY_WARNING operation={operation}' in text for operation in ['color', 'clear', 'confirmation'])
    graphical = re.search(r'NXPICKER: CASE_BEGIN id=5\n(.*?)NXPICKER: CASE id=5 ', text, re.S)
    graphical_order = [
        'NEXTCORE: PICKER_READY renderer=GOP selected=0',
        'NEXTCORE: PICKER_DISPLAY_WARNING operation=confirmation status=DEVICE_ERROR',
        'NEXTCORE: PICKER_BOOT index=0', 'NXTEST: EFI_ENTRY', 'NXTEST: OPTIONS_EMPTY']
    graphical_ok = graphical is not None and 'renderer=TEXT' not in graphical.group(1)
    if graphical_ok:
        positions = [graphical.group(1).find(marker) for marker in graphical_order]
        graphical_ok = all(at >= 0 for at in positions) and positions == sorted(positions)
    passed = passed and graphical_ok and 'NXPICKER: PASS cases=5 physical_boot_verified=false' in text and 'NXPICKER: FAIL' not in text
    after = hashlib.sha256(probe.read_bytes()).hexdigest()
    passed = passed and before == after
    report = dict(passed=passed, cases=cases, probe_sha256=before, probe_unchanged=before == after,
                  graphical_confirmation_verified=graphical_ok,
                  physical_boot_verified=False, macos_boot_verified=False,
                  elapsed_seconds=round(time.monotonic() - start, 3))
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
