#!/bin/sh
# Sourced by the container scripts (unit_tests.sh, show_check.sh). Creates, in this
# container's own /etc, the accounts the tests and the collector need (names and ids match
# tests/conftest.py). Written directly, since minimal images may lack useradd. The ids are
# in the system range, like the real accounts, and must not be taken: proc.account refuses
# a uid shared by two entries.
#
#   motp-test    881  test user; also a member of motp-test-x, so a child that kept its
#                     supplementary groups would show it
#   motp-test2   882  second test user; member of the admin group motp-admin
#   motp-test-x  883  supplementary group of motp-test
#   motp         884  the built-in probe user (D21)
#   motp-plugin  885  the plugin user (D21)
#   motp-admin   886  the admin group of the collector tests (D33)

id_taken() { cut -d: -f3 "$1" | grep -qx "$2"; }

add_account() {
    if ! grep -q "^$1:" /etc/passwd; then
        if id_taken /etc/passwd "$2" || id_taken /etc/group "$2"; then
            echo "account id $2 is taken in this image" >&2
            exit 1
        fi
        echo "$1:x:$2:" >> /etc/group
        echo "$1:x:$2:$2:MOTP test:/nonexistent:/bin/false" >> /etc/passwd
    fi
}

add_group() {
    if ! grep -q "^$1:" /etc/group; then
        id_taken /etc/group "$2" && { echo "group id $2 is taken" >&2; exit 1; }
        echo "$1:x:$2:$3" >> /etc/group
    fi
}

add_account motp-test 881
add_account motp-test2 882
add_group motp-test-x 883 motp-test
add_account motp 884
add_account motp-plugin 885
add_group motp-admin 886 motp-test2
