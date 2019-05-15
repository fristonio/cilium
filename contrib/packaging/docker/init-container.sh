#!/bin/sh

if [ "${CLEAN_CILIUM_STATE}" = "true" ] \
   || [ "${CLEAN_CILIUM_BPF_STATE}" = "true" ]; then
cilium cleanup -f
fi

if [ "${CILIUM_WAIT_BPF_MOUNT}" = "true" ]; then
	until mount | grep bpf; do echo "BPF filesystem is not mounted yet"; sleep 1; done
fi;
