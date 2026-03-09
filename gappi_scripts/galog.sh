#! /bin/bash

bpftrace ./ga_log_calls.bt | python3 ./stats.py
