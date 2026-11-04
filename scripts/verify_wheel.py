"""Verify distribution contents match the current runtime and protocol files."""
from pathlib import Path
import sys
import zipfile
root = Path(__file__).resolve().parents[1]
expected = {p.relative_to(root / 'src').as_posix(): p.read_bytes()
            for p in (root / 'src').rglob('*')
            if p.is_file() and '__pycache__' not in p.parts}
resource = root / 'proto/spanopticon/v1/contractecho.proto'
if resource.exists():
    expected['controlplane_proto_data/contractecho.proto'] = resource.read_bytes()
wheel, = Path(sys.argv[1]).glob('*.whl')
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    runtime = {name for name in names if '.dist-info/' not in name}
    assert len(names) == len(set(names)) and runtime == set(expected), 'Wheel inventory differs'
    for name, data in expected.items():
        assert archive.read(name) == data, f'Wheel bytes differ: {name}'
print('Wheel runtime and resources match the current source')
