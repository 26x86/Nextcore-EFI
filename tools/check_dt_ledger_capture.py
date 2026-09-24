#!/usr/bin/env python3
"""Validate raw authored capture evidence and reject copied malformed controls."""
import argparse
import copy
import json
from pathlib import Path
import tempfile
from verify_dt_ledger_ovmf import validate_case, validate_report, parse_records, markers, sha

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--serial', type=Path, help='Raw serial; defaults to the report sibling serial.log')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    serial = args.serial or args.report.with_name('serial.log')
    reader = Path(__file__).with_name('verify_dt_ledger_ovmf.py')
    inputs = {'report':args.report, 'serial':serial, 'checker':Path(__file__), 'reader':reader}
    if args.output.resolve() in {p.resolve() for p in inputs.values()}:
        parser.error('output must not overwrite an input')
    try:
        before = {key:sha(path) for key,path in inputs.items()}
        report = json.loads(args.report.read_text())
    except (OSError, ValueError) as error:
        args.output.write_text(json.dumps({'passed':False,'error':str(error)},indent=2)+'\n')
        return 1
    positive = validate_report(report, serial)
    if not positive['passed']:
        args.output.write_text(json.dumps({'passed':False,'capture_validation':positive},indent=2)+'\n')
        return 1
    identity = lambda c: tuple(c[k] for k in ('name','granule','upper'))
    data = {identity(c):c for c in report['data']}
    case = next(c for c in report['cases'] if c['name']=='roundtrip')
    blob = data[identity(case)]
    mutations = []
    for name,target,key,value in [
        ('pass_true_wrong_retirement','case','retired','17'),
        ('pass_true_wrong_far','case','far','1'),
        ('pass_true_wrong_ram_digest','data','ram_sha','00'*32),
        ('pass_true_table_mutation','data','tables_after_sha','00'*32),
        ('wrong_property_offset','data','value_offset','80'),
        ('missing_field','case','completed',None),
        ('extra_field','case','fabricated','true'),
        ('host_address_above_u64','case','ram_host',str(1<<64)),
        ('host_span_wraps_u64','case','ram_host',hex((1<<64)-16384)),
    ]:
        c,d = copy.deepcopy(case),copy.deepcopy(blob)
        row = c if target=='case' else d
        if value is None: row.pop(key)
        else: row[key] = value
        result = validate_case(c,d)
        mutations.append({'name':name,'rejected':not result['passed'],'error':result.get('error')})
    _,_,errors,_ = parse_records(['NXDT: CASE name=roundtrip name=invalid-dt'])
    mutations.append({'name':'duplicate_field','rejected':errors==['duplicate key'],'errors':errors})
    # Report controls preserve the original capture; raw variants use temp files.
    with tempfile.TemporaryDirectory(prefix='nextcore-dt-reader-') as scratch:
        scratch = Path(scratch)
        for name in ('failed_envelope','passed_not_boolean','wrong_schema','missing_envelope',
                     'duplicate_matrix','missing_matrix','raw_marker_mismatch','raw_fail_marker',
                     'unknown_raw_marker','raw_duplicate_field','missing_raw_serial',
                     'missing_input_role','invalid_input_digest','changed_input_digest',
                     'scope_flag_changed','forged_host_validation','serial_digest_mismatch',
                     'duplicate_count_mismatch'):
            r = copy.deepcopy(report)
            raw = serial
            if name=='failed_envelope':
                r['passed']=False; r['parse_errors']=['invalid token']
            elif name=='passed_not_boolean': r['passed']=1
            elif name=='wrong_schema': r['schema']='unrelated'
            elif name=='missing_envelope': r={'cases':r['cases'],'data':r['data']}
            elif name in ('duplicate_matrix','missing_matrix'):
                if name=='duplicate_matrix':
                    r['cases']=[r['cases'][0]]*8; r['data']=[r['data'][0]]*8
                else:
                    r['cases']=r['cases'][:-1]; r['data']=r['data'][:-1]
                lines=[r['markers'][0]]
                for c,d in zip(r['cases'],r['data']):
                    lines.extend(('NXDT: DATA '+' '.join(k+'='+v for k,v in d.items()),
                                  'NXDT: CASE '+' '.join(k+'='+v for k,v in c.items())))
                lines.append('NXDT: PASS cases=8 macos_boot_verified=false')
                r['markers']=lines; r['adjacent_transport_duplicate_lines']=0
                raw=scratch/(name+'.log'); raw.write_text('\n'.join(lines)+'\n')
                r.pop('serial_sha256',None)
            elif name=='raw_marker_mismatch': r['markers']=r['markers'][:-1]
            elif name in ('raw_fail_marker','unknown_raw_marker','raw_duplicate_field'):
                lines=list(r['markers'])
                if name=='raw_fail_marker': lines[-1]='NXDT: FAIL case=8 status=COMPROMISED_DATA'
                elif name=='unknown_raw_marker': lines.insert(-1,'NXDT: UNEXPECTED fabricated=true')
                else:
                    at=next(i for i,v in enumerate(lines) if v.startswith('NXDT: CASE '))
                    lines[at]+=' name=roundtrip'
                r['markers']=lines; r.pop('serial_sha256',None)
                raw=scratch/(name+'.log'); raw.write_text('\n'.join(lines)+'\n')
            elif name=='missing_raw_serial': raw=scratch/'absent.log'
            elif name=='missing_input_role': r['input_sha256_before'].pop('runner')
            elif name=='invalid_input_digest': r['input_sha256_before']['runner']='not-sha256'
            elif name=='changed_input_digest': r['input_sha256_after']['runner']='00'*32
            elif name=='scope_flag_changed': r['normal_boot_verified']=True
            elif name=='forged_host_validation': r['host_validations']=[{'passed':True}]*8
            elif name=='serial_digest_mismatch': r['serial_sha256']='00'*32
            elif name=='duplicate_count_mismatch': r['adjacent_transport_duplicate_lines']+=1
            result=validate_report(r,raw)
            mutations.append({'name':name,'rejected':not result['passed'],'error':result.get('error')})
    after = {key:sha(path) for key,path in inputs.items()}
    passed = all(m['rejected'] for m in mutations) and before==after
    record={'passed':passed,'actual_cases_checked':8,'capture_validation':positive,
            'tampered_case_rejections':mutations,'input_paths':{k:str(p.resolve()) for k,p in inputs.items()},
            'input_sha256_before':before,'input_sha256_after':after,
            'historical_input_hashes_are_recorded_provenance':True}
    args.output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'passed':passed,'negative_cases':len(mutations)}))
    return 0 if passed else 1

if __name__=='__main__': raise SystemExit(main())
