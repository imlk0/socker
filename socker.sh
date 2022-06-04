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
    while true; do
        [[ $# -ne 0 ]] || break
        case $1 in
        --rootfs=*)
            arg_rootfs="${1:9}"
            shift
            ;;
        -)
            shift
            break
            ;;
        -*)
            error_arg $1
            exit 1
            ;;
        *)
            break
            ;;
        esac
        arg_cmd="$@"
    done

    # TODO: check for essential arguments
}

gen_random_id() {
    # TODO: real random id
    echo "random_id"
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

    echo "$arg_cmd" >"$container_dir/cmdline"
    echo "Created" >"$container_dir/status"
    touch "$container_dir/lock"

    echo "$container_id"
}

do_ls() {
    echo -e "CONTAINER ID\tSTATUS\tCOMMAND"
    for container_id in $(ls "$CONTAINERS_BASE_DIR"); do
        echo -e "$container_id\t$(cat $CONTAINERS_BASE_DIR/$container_id/status)\t$(cat $CONTAINERS_BASE_DIR/$container_id/cmdline)"
    done
}

parse_args_exec() {
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

parse_args_start() {
    container_id=$1
}

do_start() {
    # Check status of this container
    [[ -d "$CONTAINERS_BASE_DIR/$container_id" ]] || { error "Container $container_id does not exist"; exit 1; }

    if [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
        error "Container $container_id is already running"
        exit 1
    fi

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
        # Close stdin
        exec 0>&-

        # Update status of container to Running
        lock_container "$container_id" || { error "Failed to lock container $container_id. exit now"; exit 1; }
        # We need to check again
        if [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
            error "Container $container_id is already running"
            exit 1
        fi
        echo "Running" >"$CONTAINERS_BASE_DIR/$container_id/status"
        unlock_container

        local exit_status=0
        # TODO: should we persistent namespace in file? (by unshare --pid=<path of file>)
        # Run container with unshare in a empty environment
        # Note: It is necessary to use --fork since we are creating a new pid_namespace
        env -i \
            unshare --pid --user --mount --net \
            --fork --kill-child \
            --map-user=0 --map-group=0 \
            /bin/sh -c "read -d ' ' PID </proc/self/stat ; \
                echo \$PID > $CONTAINERS_BASE_DIR/$container_id/pid ; \
                mount -t proc proc $CONTAINERS_BASE_DIR/$container_id/rootfs/proc ; \
                exec chroot $CONTAINERS_BASE_DIR/$container_id/rootfs $(cat $CONTAINERS_BASE_DIR/$container_id/cmdline)" || { local exit_status=$?; true; }

        # Update status of container to exited
        lock_container "$container_id" || { error "Failed to lock container $container_id. exit now"; exit 1; }
            echo "Exited ($exit_status)" >"$CONTAINERS_BASE_DIR/$container_id/status"
        unlock_container

    # Replace stdout and stderr with anonymous pipe. This may looks dirty but, safer. :)
    ) 1> >(cat >>"$CONTAINERS_BASE_DIR/$container_id/stdout") \
    2> >(cat >>"$CONTAINERS_BASE_DIR/$container_id/stderr") &
    echo $container_id
}

error_arg() {
    error "Unexpected argument: $1"
    echo ""
    usage
}

error() {
    echo -e "[error] $1"
}

info() {
    echo -e "[info] $1"
}

warning() {
    echo -e "[warning] $1"
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
    echo "      ls                                List all containers"
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
ls)
    do_ls
    exit 0
    ;;
start)
    shift
    parse_args_start "$@"
    do_start
    exit 0
    ;;
exec)
    parse_args_exec "$@"
    do_exec
    exit 0
    ;;
stop)
    parse_args_stop "$@"
    do_stop
    exit 0
    ;;
rm)
    do_rm
    exit 0
    ;;
*)
    error_arg
    exit 1
    ;;
esac
