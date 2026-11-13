"""Offline shell cleanup contracts; Docker and filesystem removals are substitutes."""
from pathlib import Path
import re
import subprocess
import pytest


@pytest.mark.parametrize("inspect_fails", [False, True])
def test_failure_state_precedes_cleanup_and_preserves_exit(tmp_path, inspect_fails):
    source = (Path(__file__).resolve().parents[1] / "scripts/check-runtime-image.sh").read_text()
    cleanup = re.search(r"cleanup\(\) \{.*?\n\}", source, re.S).group()
    events = tmp_path / "events"
    shell = r"""
set -euo pipefail
server=owned-fixture
probe=owned-probe
image=owned-image
scratch=owned-scratch
docker() {
  printf '%s\n' "$*" >> "$EVENTS"
  if [[ "$1" == inspect ]]; then
    [[ "$INSPECT_FAILS" == false ]] || return 1
    printf 'gateway-runtime state=exited exit=137 oom=true restarting=false\n'
  fi
}
timeout() {
  [[ "$1" == 10 ]]
  shift
  "$@"
}
rm() { printf 'remove %s\n' "$*" >> "$EVENTS"; }
"""
    result = subprocess.run(["bash", "-c", shell + cleanup + "\ntrap cleanup EXIT\nexit 137\n"],
                            env={"PATH":"/usr/bin:/bin", "EVENTS":str(events),
                                 "INSPECT_FAILS":str(inspect_fails).lower()},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 137
    assert "gateway-runtime command-exit=137" in result.stderr
    assert ("state=unavailable" if inspect_fails else "oom=true") in result.stderr
    commands = events.read_text().splitlines()
    assert commands[0].startswith("inspect --format gateway-runtime state=")
    assert commands[1:] == ["rm -f owned-fixture", "remove -f owned-probe",
                            "image rm owned-image", "remove -rf owned-scratch"]
    assert ".State.Error" not in commands[0] and ".Config" not in commands[0]
