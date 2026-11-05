import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile
import pytest

spec = importlib.util.spec_from_file_location('model_export', Path(__file__).resolve().parents[1]/'scripts/export_release_contract.py')
exporter = importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)


def wheel(tmp_path, version='0.2.0', change=None):
    files = {'hypermesh_gateway_service/__init__.py': b'__all__ = ["Model"]\n', 'hypermesh_gateway_service/model.py': b'class Model: pass\n',
             f'hypermesh_gateway_service-{version}.dist-info/METADATA': f'Name: hypermesh-gateway-service\nVersion: {version}\n'.encode()}
    if change: change(files)
    path = tmp_path/'test.whl'
    with zipfile.ZipFile(path,'w') as z:
        for name,data in files.items():z.writestr(name,data)
    return path


def test_version_only_change_preserves_contract(tmp_path):
    a,_ = exporter.snapshot(wheel(tmp_path));b,e = exporter.snapshot(wheel(tmp_path,'0.24.0'))
    assert a == b
    assert e['version'] == '0.24.0'
    assert e['wheel_sha256'] == hashlib.sha256((tmp_path/'test.whl').read_bytes()).hexdigest()


def test_runtime_change_is_detected_without_execution(tmp_path):
    first,_=exporter.snapshot(wheel(tmp_path))
    def change(f):f['hypermesh_gateway_service/model.py']=b'raise RuntimeError("do not import")\n'
    second,_=exporter.snapshot(wheel(tmp_path,change=change))
    assert first != second


@pytest.mark.parametrize('change',[
    lambda f:f.pop('hypermesh_gateway_service/__init__.py'),
    lambda f:f.update({'other.py':b'unknown surface'}),
    lambda f:f.update({'hypermesh_gateway_service/../escape.py':b'escape'}),
    lambda f:f.update({'hypermesh_gateway_service-0.2.0.dist-info/METADATA':b'Name: other\nVersion: 0.2.0\n'}),
])
def test_invalid_inventory_or_identity_rejected(tmp_path,change):
    with pytest.raises(ValueError):exporter.snapshot(wheel(tmp_path,change=change))


@pytest.mark.parametrize('field,value', [
    ('Requires-Python', '>=3.14'),
    ('Requires-Dist', 'example>=2'),
    ('Provides-Extra', 'grpc'),
])
def test_installer_metadata_changes_are_detected(tmp_path, field, value):
    before, _ = exporter.snapshot(wheel(tmp_path))
    def change(files):
        metadata = next(n for n in files if n.endswith('/METADATA'))
        files[metadata] += f'{field}: {value}\n'.encode()
    after, _ = exporter.snapshot(wheel(tmp_path, change=change))
    assert before != after


def test_entry_point_changes_are_detected_without_execution(tmp_path):
    before, _ = exporter.snapshot(wheel(tmp_path))
    def change(files):
        prefix = next(n for n in files if n.endswith('/METADATA')).removesuffix('METADATA')
        files[prefix + 'entry_points.txt'] = b'[console_scripts]\nexample = missing.module:main\n'
    after, _ = exporter.snapshot(wheel(tmp_path, change=change))
    assert before != after


def test_dependency_header_order_does_not_change_contract(tmp_path):
    def change(order):
        def apply(files):
            metadata = next(n for n in files if n.endswith('/METADATA'))
            files[metadata] += ''.join(f'Requires-Dist: {name}>=1\n' for name in order).encode()
        return apply
    before, _ = exporter.snapshot(wheel(tmp_path, change=change(['alpha', 'beta'])))
    after, _ = exporter.snapshot(wheel(tmp_path, change=change(['beta', 'alpha'])))
    assert before == after
