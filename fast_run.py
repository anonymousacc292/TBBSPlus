#!/usr/python
import subprocess

run = '''
RUSTFLAGS="-Awarnings" cargo bench --bench n_out_of_n_sign
'''
print(run)
subprocess.call(["bash", "-c", run])

run = '''
RUSTFLAGS="-Awarnings" cargo bench --bench n_out_of_n_keygen
'''
print(run)
subprocess.call(["bash", "-c", run])

run = '''
RUSTFLAGS="-Awarnings" cargo bench --bench t_out_of_n_sign
'''
print(run)
subprocess.call(["bash", "-c", run])



