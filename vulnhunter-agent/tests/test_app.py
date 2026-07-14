import pytest
import runpy
from vulnhunter.app import main

def test_main(capsys):
    main()
    captured = capsys.readouterr()
    assert captured.out.strip() == "Hello, Python Project!"

def test_main_execution():
    runpy.run_module('vulnhunter.app', run_name='__main__')
