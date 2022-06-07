#!/usr/bin/env bash

set -o errexit  # Used to exit upon error, avoiding cascading errors
set -o pipefail # Unveils hidden failures
set -o nounset  # Exposes unset variables

CONTAINERS_BASE_DIR=/var/lib/socker/containers

do_install() {
    script_path=$(realpath $0)
    echo "install -m 755 ${script_path} /usr/local/bin/socker"
    install -m 755 ${script_path} /usr/local/bin/socker
}

parse_args_create() {
    while [[ $# -ne 0 && "$1" =~ ^- && ! "$1" == "--" ]]; do case $1 in
    --rootfs)
        shift; arg_rootfs=$1
        ;;
    -*)
        error_arg $1
        exit 1
        ;;
    esac; shift; done
    if [[ $# -ne 0 && "$1" == '--' ]]; then shift; fi

    [[ $# -ne 0 ]] || { error "cmdline not provided"; exit 1; }
    arg_cmdline="$@"

    # TODO: check for essential arguments
}

gen_random_id() {
    head -c6 /dev/urandom | hexdump '-e"%x"'
}

do_create() {
    local container_id="$(gen_random_id)"
    local container_dir="$CONTAINERS_BASE_DIR/$container_id"
    mkdir -p "$container_dir"

    # If --rootfs is pointed to a dir, just use it.
    if [[ -d "$arg_rootfs" ]]; then
        ln -s -f "$(realpath $arg_rootfs)" "$container_dir/rootfs"
    elif [[ -f "$arg_rootfs" ]] && [[ "$arg_rootfs" =~ \.tar(.gz|.xz)?$ ]]; then
        mkdir -p "$container_dir/rootfs"
        tar -xf "$arg_rootfs" --directory="$container_dir/rootfs"
    else
        error "bad rootfs"; exit 1
    fi
    echo "$arg_cmdline" >"$container_dir/cmdline"


    echo "Created" >"$container_dir/status"
    touch "$container_dir/lock"

    echo "$container_id"
}

do_ps() {
    echo -e "CONTAINER ID\tSTATUS\tCOMMAND"
    for container_id in $(ls "$CONTAINERS_BASE_DIR"); do
        echo -e "$container_id\t$(cat $CONTAINERS_BASE_DIR/$container_id/status)\t$(cat $CONTAINERS_BASE_DIR/$container_id/cmdline)"
    done
}

lock_container() {
    # open "lock" file with fd 100
    exec 100<"$CONTAINERS_BASE_DIR/$1/lock"
    flock -x -n --timeout 1 100
}

unlock_container() {
    flock -u 100
    exec 100<&-
}

init_network() {
    # create default vbridge
    if ! brctl show | grep vbridge_default >/dev/null; then
        brctl addbr vbridge_default
        ip link set vbridge_default up
    fi
}

parse_args_start() {
    arg_container_id=$1
}

do_start() {
    container_id="$arg_container_id"
    # Check status of this container
    [[ -d "$CONTAINERS_BASE_DIR/$container_id" ]] || { error "Container $container_id does not exist"; exit 1; }

    if [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
        error "Container $container_id is already running"
        exit 1
    fi

    init_network

    # This subshell process (named as 'socker-shim') shall run as long as the container run
    #   socker-shim─┬─2*[bash───cat]
    #                └─unshare───<container pid 1>
    (
        # nohup
        trap "" HUP

        subshell_pid=$(exec sh -c 'echo "$PPID"')
        # Change short name of this subshell process
        echo -n "socker-shim" > /proc/$subshell_pid/comm
        # Close all fd except {0,1,2}
        for fd in $(ls /proc/$subshell_pid/fd); do
            if [[ $fd -gt 2 ]]; then
                eval "exec $fd>&-"
            fi
        done
        # Redirect stdin to null
        exec </dev/null

        # Create a cgroup for init process
        local cgroup_dir="/sys/fs/cgroup/socker-$container_id"
        mkdir -p $cgroup_dir

        # Update status of container to Running
        lock_container "$container_id" || { error "Failed to lock container $container_id. exit now"; exit 1; }
        # We need to check again
        if [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
            error "Container $container_id is already running"
            exit 1
        fi
        echo "Running" >"$CONTAINERS_BASE_DIR/$container_id/status"
        unlock_container

        local shim_status=0
        veth_container="v${container_id:0:7}"
        veth_host="veth${container_id:0:7}"

        # Failure is allowed now, but we need to catch all errors
        set +o errexit
        # Create pipe to communicate with init process
        local fifo=$CONTAINERS_BASE_DIR/$container_id/fifo
        rm -f $fifo
        [[ $shim_status -eq 0 ]] && { mkfifo $fifo && exec 3<>$fifo 4>$fifo && exec 3<$fifo && rm -f $fifo || shim_status=$? ; } # socker-shim -> init
        [[ $shim_status -eq 0 ]] && { mkfifo $fifo && exec 5<>$fifo 6>$fifo && exec 5<$fifo && rm -f $fifo || shim_status=$? ; } # socker-shim <- init

        if [[ $shim_status -eq 0 ]]; then
            ip link delete $veth_host 2>/dev/null
            ip link delete $veth_container 2>/dev/null

            ip link add $veth_container type veth peer name $veth_host &&
            brctl addif vbridge_default $veth_host &&
            ip link set $veth_host up

            shim_status=$?
        fi

        if [[ $shim_status -ne 0 ]]; then
            # Failed before we launch the container 
            error "There is a fault in the socker-shim process, before launch the container."
            echo "Exited ($shim_status)" >"$CONTAINERS_BASE_DIR/$container_id/status"
            # Do clean up
            rm -f $fifo
            rmdir $cgroup_dir 2>/dev/null
            ip link delete $veth_host 2>/dev/null
            ip link delete $veth_container 2>/dev/null

            exit $shim_status
        fi

        local container_exit_status=0
        # TODO: limit the capabilities of the init process
        # TODO: check cmdline for shell script escaping errors
        # Run container with unshare in a empty environment
        # Note: It is necessary to use --fork since we are creating a new pid_namespace
        env -i \
            unshare --pid --user --mount --net \
            --fork --kill-child \
            --map-user=0 --map-group=0 \
            /bin/sh -c "set -o errexit ; \
                exec 5<&- 4>&- ; \
                read PID _ </proc/self/stat ; \
                echo \$PID > $CONTAINERS_BASE_DIR/$container_id/pid ; \
                echo 'pid ready' >&6 ; \
                echo 1 > $cgroup_dir/cgroup.procs ; \
                exec unshare --cgroup /bin/sh -c ' \
                    set -o errexit ; \
                    mount -t proc proc $CONTAINERS_BASE_DIR/$container_id/rootfs/proc ; \
                    mount -t sysfs -o ro sys $CONTAINERS_BASE_DIR/$container_id/rootfs/sys ; \
                    mount -t cgroup2 cgroup $CONTAINERS_BASE_DIR/$container_id/rootfs/sys/fs/cgroup ; \
                    read event_veth_set <&3 ; \
                    ip link set $veth_container name eth0 ; \
                    ip link set lo up ; \
                    ip link set eth0 up ; \
                    exec 3<&- 6>&- ; \
                    exec chroot $CONTAINERS_BASE_DIR/$container_id/rootfs $(cat $CONTAINERS_BASE_DIR/$container_id/cmdline)' \
                " & pid_of_unshare=$!

        # prevent from waiting for a died writer or reader
        exec 3<&- 6>&-

        if [[ $shim_status -eq 0 ]]; then
            # wait for pid ready
            read evet_pid_ready <&5 &&
            read pid_of_init < $CONTAINERS_BASE_DIR/$container_id/pid &&
            ip link set $veth_container netns $pid_of_init &&
            # send veth set event
            echo 'veth set' >&4

            shim_status=$?
        fi

        exec 5<&- 4>&-

        if [[ $shim_status -ne 0 ]]; then
            if [[ ! -e /proc/$pid_of_unshare ]]; then
                # The init process has already exited, so we assume that the failure is caused by the init process
                error "There is a fault in the init process."
                wait $pid_of_unshare || local container_exit_status=$?
                shim_status=$container_exit_status
            else
                # The init process is still alive, which means that the error is caused by socker-shim
                error "There is a fault in the socker-shim process."
                kill -KILL $pid_of_unshare
                wait $pid_of_unshare
            fi
        else
            # socker-shim did not cause an error, so let's wait for the init process to exit
            wait $pid_of_unshare || local container_exit_status=$?
            shim_status=$container_exit_status
        fi

        echo "Exited ($shim_status)" >"$CONTAINERS_BASE_DIR/$container_id/status"

        # Do clean up
        rmdir $cgroup_dir 2>/dev/null
        ip link delete $veth_host 2>/dev/null
        ip link delete $veth_container 2>/dev/null

        exit $shim_status

    # Replace stdout and stderr with anonymous pipe. This may looks dirty but, safer. :)
    ) 1> >(cat >>"$CONTAINERS_BASE_DIR/$container_id/stdout") \
    2> >(cat >>"$CONTAINERS_BASE_DIR/$container_id/stderr") &
    echo $container_id
}

parse_args_exec() {
    arg_interactive=0
    arg_tty=0

    while [[ $# -ne 0 && "$1" =~ ^- && ! "$1" == "--" ]]; do case $1 in
    -i | --interactive)
        arg_interactive=1
        ;;
    -t | --tty)
        arg_tty=1
        ;;
    -*)
        error_arg $1
        exit 1
        ;;
    esac; shift; done
    if [[ $# -ne 0 && "$1" == '--' ]]; then shift; fi

    [[ $# -ne 0 ]] || { error "container_id not provided"; exit 1; }
    arg_container_id="$1"
    shift

    [[ $# -ne 0 ]] || { error "cmdline not provided"; exit 1; }
    arg_cmdline="$@"
}

do_exec() {
    container_id="$arg_container_id"
    
    [[ -d "$CONTAINERS_BASE_DIR/$container_id" ]] || { error "Container $container_id does not exist"; exit 1; }
    [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]] || { error "Container $container_id is not running"; exit 1; }

    read pid <"$CONTAINERS_BASE_DIR/$container_id/pid"
    env -i nsenter --all --target "$pid" --root --wdns=/ $arg_cmdline
    # TODO: check `arg_interactive` and `arg_tty`
}

parse_args_stop() {
    arg_time=10
    while [[ $# -ne 0 && "$1" =~ ^- ]]; do case $1 in
    -t | --time)
        shift; arg_time=$1
        ;;
    -*)
        error_arg $1
        exit 1
        ;;
    esac; shift; done

    [[ $# -ne 0 ]] || { error "container_id not provided"; exit 1; }
    arg_container_id="$1"
}

do_stop() {
    container_id="$arg_container_id"

    if [[ -d "$CONTAINERS_BASE_DIR/$container_id" && $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
        read pid <"$CONTAINERS_BASE_DIR/$container_id/pid"
        kill -TERM "$pid"
        if [[ -d "/proc/$pid" ]]; then
            sleep "$arg_time"
            kill -KILL "$pid"
        fi
        local cgroup_dir="/sys/fs/cgroup/socker-$container_id"
        rmdir $cgroup_dir 2>/dev/null || true
    fi
    echo "$container_id"
}

parse_args_rm() {
    [[ $# -ne 0 ]] || { error "container_id not provided"; exit 1; }
    arg_container_id="$1"
}

do_rm() {
    container_id="$arg_container_id"

    [[ -d "$CONTAINERS_BASE_DIR/$container_id" ]] || { error "Container $container_id does not exist"; exit 1; }
    [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") != "Running" ]] || { error "Container $container_id is running. You need to stop it before remove."; exit 1; }
    rm -rf $CONTAINERS_BASE_DIR/$container_id
    echo "$container_id"
}

error_arg() {
    echo "[error] Unexpected argument: $1"
    echo ""
    usage
}

error() {
    echo "[error] $1" >&2
}

info() {
    echo "[info] $1" >&2
}

warning() {
    echo "[warning] $1" >&2
}

usage() {
    echo "Run cmd in a isolation network namespace."
    echo ""
    echo "usage:"
    echo "    socker <command> [options]"
    echo ""
    echo "command:"
    echo "      install                           Copy this script to /usr/local/bin/socker"
    echo "      create                            Create a container"
    echo "      start                             Start a container"
    echo "      ps                                List all containers"
}

# TODO: should we be root? consider an uid namespace
# if [[ ${EUID} -ne 0 ]]; then
#     error "This script must be run as root"
#     exit 1
# fi

# Exit if no argument provided
if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

# Parse command
case $1 in
install)
    do_install
    exit 0
    ;;
create)
    shift
    parse_args_create "$@"
    do_create
    exit 0
    ;;
ps)
    do_ps
    exit 0
    ;;
start)
    shift
    parse_args_start "$@"
    do_start
    exit 0
    ;;
exec)
    shift
    parse_args_exec "$@"
    do_exec
    exit 0
    ;;
stop)
    shift
    parse_args_stop "$@"
    do_stop
    exit 0
    ;;
rm)
    shift
    parse_args_rm "$@"
    do_rm
    exit 0
    ;;
*)
    error_arg $1
    exit 1
    ;;
esac
