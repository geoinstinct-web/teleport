#!/bin/bash
export TELEPORT_TEST_MODE=true
export TELEPORT_TESTVAR_LOCAL_IP=10.1.2.3
export TELEPORT_TESTVAR_LOCAL_HOSTNAME=ip-10-1-2-3.ec2.internal
export TELEPORT_TESTVAR_PUBLIC_IP=1.2.3.4

TEST_SUITE="$(basename ${BATS_TEST_FILENAME%%.bats})"

setup_file() {
    load fixtures/test-setup.bash

    # write_confd_file is a function defined to set up fixtures inside each test
    write_confd_file

    # generate config
    run ${BATS_TEST_DIRNAME?}/../bin/teleport-generate-config
    export GENERATE_EXIT_CODE=$?
    # store all the lines in a given block, stops capturing on newlines
    # any use of the block must be quoted to retain newlines
    export TELEPORT_BLOCK=$(awk '/teleport:/,/^$/' ${TELEPORT_CONFIG_PATH?})
    export AUTH_BLOCK=$(awk '/auth_service:/,/^$/' ${TELEPORT_CONFIG_PATH?})
    export PROXY_BLOCK=$(awk '/proxy_service:/,/^$/' ${TELEPORT_CONFIG_PATH?})
    export NODE_BLOCK=$(awk '/ssh_service:/,/^$/' ${TELEPORT_CONFIG_PATH?})
}

teardown_file() {
    load fixtures/test-teardown.bash
}
