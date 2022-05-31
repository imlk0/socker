#!/usr/bin/env bash

set -o errexit    # Used to exit upon error, avoiding cascading errors
set -o pipefail   # Unveils hidden failures
set -o nounset    # Exposes unset variables

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

gen_random_name(){
    # TODO: real random name
    echo "random_name"
}

do_create(){
    local container_name="$(gen_random_name)"
    local container_dir="/var/lib/socker/containers/$container_name"
    mkdir -p "$container_dir"

    # If --rootfs is pointed to a dir, just use it.
    if [[ -d "$arg_rootfs" ]]; then
        ln -s -f "$(realpath $arg_rootfs)" "$container_dir/rootfs"
    elif [[ -f "$arg_rootfs" ]] && [[ "$arg_rootfs" =~ \.tar(.gz|.xz)?$ ]]; then
        mkdir -p "$container_dir/rootfs"
        tar -xf "$arg_rootfs" --directory="$container_dir/rootfs"
    else
        error "bad rootfs" ; exit 1
    fi

    echo "$arg_cmd" > "$container_dir/cmdline"
    echo "created" > "$container_dir/status"
}

parse_args_exec() {
    
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
    shift
    parse_args_ls "$@"
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
