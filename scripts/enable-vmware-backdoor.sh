#!/usr/bin/env bash
set -eu

if grep -q AuthenticAMD /proc/cpuinfo; then
    KVM_MOD="kvm-amd"
elif grep -q GenuineIntel /proc/cpuinfo; then
    KVM_MOD="kvm-intel"
else
    echo "Unsupported CPU vendor"
    exit 1
fi

sudo modprobe -r "$KVM_MOD"
sudo modprobe -r kvm
sudo modprobe  kvm enable_vmware_backdoor=y
sudo modprobe  "$KVM_MOD"
cat /sys/module/kvm/parameters/enable_vmware_backdoor | grep -q Y && echo OK || echo KVM module problem
