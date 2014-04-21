#!/bin/sh

echo "Stab called: $0 $@"

case "$1" in
  *dhcp*)
    trap "echo SIGHUP" SIGHUP
    trap "echo SIGINT" SIGINT
    trap "echo SIGPIPE" SIGPIPE

    (
    echo "Simulating udhcpc daemon"
    sleep 3
    echo "Exiting form udhcp simulation"
    ) &
    echo "Bootstrap end"
    ;;

  *upwd*)
    cat
    echo "Stop applying users"
    ;;

esac

