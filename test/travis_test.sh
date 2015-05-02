#!/bin/bash

set -e

cd test
./crypto.py
./test.py
