#!/usr/bin/env python3
"""Offline owner-authorized version freeze; no prior release is required."""
import argparse,json,os,pathlib,re,subprocess,tomllib

def check(root):
    policy=json.loads((root/'.github/version-policy.json').read_text())
    if policy.get('schema') != 1:
        raise ValueError('Unsupported version policy schema')
    for file,expected in policy['versions'].items():
        p=root/file
        data=json.loads(p.read_text()) if p.suffix=='.json' else tomllib.loads(p.read_text())
        actual=data.get('version') if p.suffix=='.json' else data.get('project',data.get('package',{})).get('version')
        if actual!=expected: raise ValueError(f'{file}: version {actual} differs from frozen {expected}; explicit owner authorization required')
        m=re.fullmatch(r'0\.(\d+)\.(\d+)',actual)
        if not m or int(m[1])>=24: raise ValueError(f'{file}: version is outside pre-0.24.0 policy')
    tracked=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')
    for file in tracked:
        if not file or file.startswith(('evidence/', 'releases/')): continue
        path=root/file
        if path.name=='uv.lock':
            for package in tomllib.loads(path.read_text()).get('package',[]):
                expected=policy.get('owned_dependency_versions',{}).get(package['name'])
                if expected and package['version'] != expected:
                    raise ValueError(f"{file}: {package['name']} {package['version']} differs from authorized {expected}")
    return policy

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
    args=parser.parse_args()
    check(args.root)
    print('Frozen pre-0.24.0 versions verified; no release baseline or publication required.')
