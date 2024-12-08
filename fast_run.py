#!/usr/python
import subprocess

run = '''
RUSTFLAGS="-Awarnings" cargo bench --bench comp_sign
'''
print(run)
subprocess.call(["bash", "-c", run])

run = '''
cd crypto
RUSTFLAGS="-Awarnings" cargo test --release --package bbs_plus --lib -- threshold::threshold_bbs_plus::tests::signing_n_out_of_n threshold::threshold_bbs_plus::tests::signing_t_out_of_n --exact --show-output
'''
print(run)
subprocess.call(["bash", "-c", run])

# run = '''
# RUSTFLAGS="-Awarnings" cargo bench --bench comp_client
# '''
# print(run)
# subprocess.call(["bash", "-c", run])



