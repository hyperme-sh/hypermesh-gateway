"""Gateway case transferred from Panopticon's ticket installation test."""
import os
import subprocess
import sys


def test_installed_package_does_not_require_hypermesh_service(tmp_path):
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("UV_NO_SYNC", None)
    environment["FASTAPI_ENV"] = "test"
    subprocess.run([sys.executable, "-I", "-c", "\nimport importlib.util, sys\nfrom hypermesh_gateway_service.app import create_app\nfrom hypermesh_ticket import honor_ticket\nassert create_app()\nassert callable(honor_ticket)\nassert importlib.util.find_spec('hypermesh_service') is None\nassert not any(name.startswith('hypermesh_service') for name in sys.modules)\n"], cwd=tmp_path,
                   env=environment, check=True, capture_output=True, text=True)
