#!/usr/bin/env python3
"""Actual x86 EFI ASID admission, MMFR0/control readback and alias transfers.

The host checks 64 exact cases. Internal selected-tag/TLB discrimination belongs
to the independent native ASID tests, not these EFI readbacks. No original input.
"""
import argparse
import hashlib
import itertools
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
    if not path.exists():
        return []
    # An unfinished UART suffix cannot satisfy completion or a case.
    rows = path.read_bytes().split(b'\n')[:-1]
    result = []
    for row in rows:
        text = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', row).removesuffix(b'\r').decode(errors='replace')
        if text.startswith('NXASID:'):
            result.append(text)
    return result


def validate_case(fields):
    required = {'granule','profile','upper','a1','tag0','tag1','status','retired','fetch',
                'data','completed','provider','mmfr0','tcr','ttbr0','ttbr1','pass'}
    if set(fields) != required or fields['upper'] not in ('false','true') or fields['a1'] not in ('false','true'):
        return False
    try:
        actual = {k:int(v,0) for k,v in fields.items() if k not in ('upper','a1','pass')}
    except ValueError:
        return False
    granule, profile, tag = actual['granule'], actual['profile'], actual['tag0']
    if granule not in (4096,16384) or profile not in (1,3) or tag not in (0,1,127,255):
        return False
    tsz = 17 if granule == 16384 else 16
    tcr = tsz | tsz<<16 | 5<<32 | int(fields['a1']=='true')<<22
    tcr |= (2<<14 | 1<<30) if granule == 16384 else 2<<30
    expected = dict(granule=granule,profile=profile,tag0=tag,tag1=tag^255,status=1,
                    retired=9,fetch=9,data=2,completed=2,provider=0,mmfr0=0x0f100005,
                    tcr=tcr,ttbr0=0x30000000 | tag<<48,
                    ttbr1=(0x30000000+granule) | (tag^255)<<48)
    return fields['pass']=='true' and actual == expected


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi-probe',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expect-old-rejection',action='store_true')
    parser.add_argument('--timeout',type=float,default=60)
    args=parser.parse_args()
    if not 0 < args.timeout <= 60:
        parser.error('timeout must be in (0,60]')
    module=Path(__file__).resolve().parents[1]
    inputs={'efi':args.efi_probe.resolve(strict=True),'runner':Path(__file__).resolve(),
            'source':module/'src/asid_probe.rs','assembly':module/'docs/fixtures/asid_scalar.S',
            'ovmf_code':Path('/usr/share/OVMF/OVMF_CODE_4M.fd'),
            'ovmf_vars':Path('/usr/share/OVMF/OVMF_VARS_4M.fd')}
    before={n:sha(p) for n,p in inputs.items()}
    out=args.output.resolve(); out.mkdir(parents=True,exist_ok=False)
    if any(',' in str(p) for p in [out,*inputs.values()]):
        parser.error('QEMU file paths cannot contain a comma')
    commands=[]
    for argv in [
        ['clang-18','--target=aarch64-none-elf','-c',str(inputs['assembly']),'-o',str(out/'probe.o')],
        ['llvm-objcopy-18','-O','binary','--only-section=.text',str(out/'probe.o'),str(out/'probe.bin')]]:
        process=subprocess.run(argv,capture_output=True,text=True,timeout=20)
        commands.append(dict(argv=argv,return_code=process.returncode,stdout=process.stdout,stderr=process.stderr))
        assert process.returncode==0, commands[-1]
    source=inputs['source'].read_text()
    word_text=re.search(r'const WORDS: \[u32; 10\] = \[(.*?)\];',source,re.S)
    assert word_text
    words=[int(n.strip().replace('_',''),0) for n in word_text[1].split(',') if n.strip()]
    assert struct.pack('<10I',*words)==(out/'probe.bin').read_bytes()
    shutil.copyfile(inputs['assembly'],out/'probe.S')
    boot=out/'esp/EFI/BOOT'; boot.mkdir(parents=True)
    shutil.copyfile(inputs['efi'],boot/'BOOTX64.EFI')
    variables=out/'vars.fd'; shutil.copyfile(inputs['ovmf_vars'],variables)
    serial=out/'serial.log'
    argv=['qemu-system-x86_64','-machine','q35,accel=tcg,smm=off','-cpu','Nehalem','-m','256',
          '-smp','1','-display','none','-vga','std','-monitor','none','-serial',f'file:{serial}',
          '-net','none','-no-reboot','-drive',f'if=pflash,format=raw,readonly=on,file={inputs["ovmf_code"]}',
          '-drive',f'if=pflash,format=raw,file={variables}','-drive',f'format=raw,file=fat:rw:{out/"esp"}']
    (out/'command.json').write_text(json.dumps(argv,indent=2)+'\n')
    start=time.monotonic(); failure=None; stopped=False
    with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
        process=subprocess.Popen(argv,stdout=stdout,stderr=stderr,start_new_session=True)
        try:
            while process.poll() is None and time.monotonic()-start < args.timeout:
                if any(row.startswith(('NXASID: PASS ','NXASID: FAIL ')) for row in markers(serial)):
                    break
                time.sleep(.1)
        except Exception as error:
            failure=repr(error)
        finally:
            if process.poll() is None:
                stopped=True; os.killpg(process.pid,signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL); process.wait(timeout=3)
    actual=markers(serial)
    rows=[]
    for row in actual:
        if not rows or row != rows[-1]:
            rows.append(row)
    cases=[]; malformed=[]
    for row in rows:
        if row.startswith('NXASID: CASE '):
            pairs=[s.split('=',1) for s in row.split()[2:]]
            if any(len(p)!=2 for p in pairs) or len({p[0] for p in pairs})!=len(pairs):
                malformed.append(row); continue
            cases.append(dict(pairs))
    identities=[tuple(c.get(k) for k in ('granule','profile','upper','a1','tag0')) for c in cases]
    expected=set(itertools.product(['4096','16384'],['1','3'],['false','true'],['false','true'],['0','1','127','255']))
    entry='NXASID: ENTRY host=x86_64 authored=true profile=immutable-asid8-el1'
    if args.expect_old_rejection:
        semantic=(rows==[entry,'NXASID: FAIL completed=0 status=INVALID_PARAMETER'] and not cases)
    else:
        semantic=(len(cases)==64 and set(identities)==expected and all(map(validate_case,cases))
                  and rows[0:1]==[entry] and rows[-1:]==['NXASID: PASS cases=64 physical_boot_verified=false macos_boot_verified=false']
                  and len(rows)==66 and not malformed)
    after={n:sha(p) for n,p in inputs.items()}
    passed=semantic and before==after and sha(boot/'BOOTX64.EFI')==before['efi'] and failure is None and process.returncode==0
    receipt=dict(schema='nextcore.authored-asid8-efi.v1',passed=passed,expect_old_rejection=args.expect_old_rejection,
                 cases=cases,markers=actual,malformed=malformed,input_paths={n:str(p) for n,p in inputs.items()},
                 input_sha256_before=before,input_sha256_after=after,assembly_matches=True,commands=commands,
                 elapsed_seconds=round(time.monotonic()-start,3),qemu_exit_code=process.returncode,
                 process_reaped=process.poll() is not None,stopped_by_harness=stopped,host_failure=failure,
                 original_inputs_used=False,physical_boot_verified=False,macos_boot_verified=False,
                 scope='Actual immutable ASID admission/control readback and alias transfers. Internal tag selection is separately qualified by native tests.')
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(passed=passed,cases=len(cases),old=args.expect_old_rejection,output=str(out))))
    return 0 if passed else 1


if __name__=='__main__':
    raise SystemExit(main())
