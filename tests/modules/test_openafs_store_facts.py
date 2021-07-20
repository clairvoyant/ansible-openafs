import sys
import pytest
sys.path.append('../plugins/modules')
sys.path.append('../../plugins/modules')
import openafs_store_facts

def test_update():
    facts = {}
    key = 'foo'
    value = 'bar'
    openafs_store_facts.update(facts, key, value)
    assert 'foo' in facts
    assert facts['foo'] == 'bar'
