#!/bin/bash
# Copyright (c) 2023, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
set -e

cd ../hostapd
cp defconfig .config
make -j 4
