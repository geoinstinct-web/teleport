#!/bin/bash
#
# Example of how etcd must be started in the full TLS mode, i.e.
#   - server cert is checked by clients
#   - client cert is checked by the server
#
# NOTE: this file is also used to run etcd tests.
#
HERE=$(readlink -f $0)
cd "$(dirname $HERE)" || exit

mkdir -p data
etcd --name teleportstorage \
     --data-dir data/etcd \
     --initial-cluster-state new \
     --advertise-client-urls=http://127.0.0.1:2379 \
     --listen-client-urls=http://127.0.0.1:2379
