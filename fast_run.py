#!/usr/python
import subprocess

run = '''
cargo bench --bench n_out_of_n_sign
'''
print(run)
subprocess.call(["bash", "-c", run])

run = '''
cargo bench --bench n_out_of_n_keygen
'''
print(run)
subprocess.call(["bash", "-c", run])

run = '''
cargo bench --bench t_out_of_n_sign
'''
print(run)
subprocess.call(["bash", "-c", run])



