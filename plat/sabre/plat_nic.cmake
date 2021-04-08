#
# i.MX6 Sabre Lite board/QEMU configuration
#
# Copyright (C) 2021, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

set(LibEthdriverNumPreallocatedBuffers 32 CACHE STRING "" FORCE)

DeclareCAmkESComponents_for_NICs()
