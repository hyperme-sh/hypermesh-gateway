"""Reject skipped cases or unequal source/wheel/sdist test inventories."""
from collections import Counter
import sys
from xml.etree import ElementTree

inventories = []
for path in sys.argv[1:]:
    root = ElementTree.parse(path).getroot()
    cases = list(root.iter('testcase'))
    assert cases, f'No executed tests: {path}'
    assert not any(list(root.iter(tag)) for tag in ('skipped', 'failure', 'error')), path
    inventories.append(Counter((case.attrib['classname'].removeprefix('tests.'), case.attrib['name']) for case in cases))
assert len(inventories) == 3 and all(i == inventories[0] for i in inventories[1:]), 'Test inventories differ'
print(f'{sum(inventories[0].values())} matching cases passed in source, wheel and sdist; no skips')
