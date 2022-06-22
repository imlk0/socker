#!/usr/bin/env bash

set -o errexit  # Used to exit upon error, avoiding cascading errors
set -o pipefail # Unveils hidden failures
set -o nounset  # Exposes unset variables

CONTAINERS_BASE_DIR=/var/lib/socker/containers
DEFAULT_BRIDGE=vbridge_default
DEFAULT_BRIDGE_IP=192.168.101.1
DEFAULT_BRIDGE_IP_PREFIX=192.168.101

is_cgroup2=`[[ -e /sys/fs/cgroup/cgroup.controllers ]]; echo $?`

warning_on_no_cgroup2() {
    [[ $is_cgroup2 -eq 0 ]] || warning "Seems that your host side is not using cgroup2, in which case we will suppress all features that depend on it."
}

do_install() {
    script_path=$(realpath $0)
    echo "install -m 755 ${script_path} /usr/local/bin/socker"
    install -m 755 ${script_path} /usr/local/bin/socker
}

usage_create() {
    echo "usage:    socker create [options] <cmdline>"
    echo ""
    echo "options:"
    echo "      --rootfs      (required) A path to the rootfs.tar[.gz|.xz] file, or an unpacked rootfs directory"
    echo "      --ip          The ipv4 address inside the container, should be in range ${DEFAULT_BRIDGE_IP}/24. If not specified, will automatically select one"
    usage_cgroup_options
}

parse_args_create() {
    arg_ip=""

    while [[ $# -ne 0 && "$1" =~ ^- && ! "$1" == "--" ]]; do case $1 in
    --rootfs)
        shift; arg_rootfs=$1
        ;;
    --ip)
        shift; arg_ip=$1
        ;;
    -h | --help)
        usage_create
        exit 0
        ;;
    -*)
        if [[ $# -ge 2 ]] && parse_arg_cgroup "$1" "$2" ; then
            shift ;
        else
            error_arg $1
            usage_create
            exit 1
        fi
        ;;
    esac; shift; done
    if [[ $# -ne 0 && "$1" == '--' ]]; then shift; fi

    [[ $# -ne 0 ]] || { error "cmdline not provided"; exit 1; }
    arg_cmdline="$@"

    # TODO: check for essential arguments
}

gen_random_id() {
    head -c6 /dev/urandom | hexdump -e '1/1 "%.2x"'
}

assign_ip() {
    local ip_in_use=($DEFAULT_BRIDGE_IP)
    local ip=""
    for network_config in $CONTAINERS_BASE_DIR/*/network; do
        read ip < $network_config
        if [[ ! -z $ip ]]; then ip_in_use+=("$ip"); fi
    done 2>/dev/null
    # We assume that the host number takes up 8 bits
    for host_num in {1..254}; do
        ip="${DEFAULT_BRIDGE_IP_PREFIX}.${host_num}"
        if [[ ! " ${ip_in_use[@]} " =~ " $ip " ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

do_create() {
    local container_id="$(gen_random_id)"
    local container_dir="$CONTAINERS_BASE_DIR/$container_id"
    mkdir -p "$container_dir"

    if [[ -z "$arg_ip" ]]; then
        arg_ip="$(assign_ip)"
        if [[ $? -ne 0 ]]; then
            error "failed to find a free ip address"
            exit 1
        fi
    fi

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
    echo "$arg_ip" >"$container_dir/network"
    load_cgroup_config_or_default "$container_id"
    merge_and_save_cgroup_config "$container_id"
    echo "Created" >"$container_dir/status"
    touch "$container_dir/lock"

    echo "$container_id"
}

do_ps() {
    printf "%s\t%-30.30s\t%-15.15s\t%s\n" "CONTAINER ID" "COMMAND" "STATUS" "NETWORK"
    if [[ -e "$CONTAINERS_BASE_DIR" ]]; then
        for container_id in $(ls "$CONTAINERS_BASE_DIR"); do
            local cmdline=$(cat $CONTAINERS_BASE_DIR/$container_id/cmdline 2>/dev/null)
            local status=$(cat $CONTAINERS_BASE_DIR/$container_id/status 2>/dev/null)
            local network=$(cat $CONTAINERS_BASE_DIR/$container_id/network 2>/dev/null)

            printf "%s\t%-30.30s\t%-15.15s\t%s\n" "$container_id" "$cmdline" "$status" "$network"
        done
    fi
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
    if ! brctl show | grep ${DEFAULT_BRIDGE} >/dev/null; then
        brctl addbr ${DEFAULT_BRIDGE}
        ip link set ${DEFAULT_BRIDGE} up
        ip addr add ${DEFAULT_BRIDGE_IP}/24 dev ${DEFAULT_BRIDGE}
        echo 1 > /proc/sys/net/ipv4/ip_forward
        iptables -t nat -A POSTROUTING -s ${DEFAULT_BRIDGE_IP}/24 ! -o ${DEFAULT_BRIDGE} -j MASQUERADE
        iptables -t filter -A FORWARD -i any -o ${DEFAULT_BRIDGE} -j ACCEPT
        iptables -t filter -A FORWARD -i ${DEFAULT_BRIDGE} -o ${DEFAULT_BRIDGE} -j ACCEPT
        iptables -t filter -A FORWARD -i ${DEFAULT_BRIDGE} ! -o ${DEFAULT_BRIDGE} -j ACCEPT
    fi
}

reset_network() {
    # delete default vbridge
    if brctl show | grep ${DEFAULT_BRIDGE} >/dev/null; then
        ip link set ${DEFAULT_BRIDGE} down
        brctl delbr ${DEFAULT_BRIDGE}
    fi
    iptables -t nat -D POSTROUTING -s ${DEFAULT_BRIDGE_IP}/24 ! -o ${DEFAULT_BRIDGE} -j MASQUERADE 2>/dev/null || true
    iptables -t filter -D FORWARD -i any -o ${DEFAULT_BRIDGE} -j ACCEPT 2>/dev/null || true
    iptables -t filter -D FORWARD -i ${DEFAULT_BRIDGE} -o ${DEFAULT_BRIDGE} -j ACCEPT 2>/dev/null || true
    iptables -t filter -D FORWARD -i ${DEFAULT_BRIDGE} ! -o ${DEFAULT_BRIDGE} -j ACCEPT 2>/dev/null || true
}

parse_args_start() {
    arg_container_id=$1
}

do_start() {
    warning_on_no_cgroup2

    container_id="$arg_container_id"
    # Check status of this container
    [[ -d "$CONTAINERS_BASE_DIR/$container_id" ]] || { error "Container $container_id does not exist"; exit 1; }

    if [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
        error "Container $container_id is already running"
        exit 1
    fi

    init_network
    read container_ip < $CONTAINERS_BASE_DIR/$container_id/network

    # Read cgroup config from file
    load_cgroup_config_or_default "$container_id"

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
        [ $is_cgroup2 -ne 0 ] || mkdir -p $cgroup_dir

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

        # Setup veth pair
        if [[ $shim_status -eq 0 ]]; then
            ip link delete $veth_host 2>/dev/null
            ip link delete $veth_container 2>/dev/null

            ip link add $veth_container type veth peer name $veth_host &&
            brctl addif ${DEFAULT_BRIDGE} $veth_host &&
            ip link set $veth_host up

            shim_status=$?
        fi

        # Setup files to be mount --bind
        if [[ $shim_status -eq 0 ]]; then
            local bind_files="$CONTAINERS_BASE_DIR/$container_id/bind_files"

            mkdir -p "$bind_files" &&
            mkdir -p "$bind_files/etc" &&
            cp /etc/resolv.conf "$bind_files/etc/resolv.conf" &&
            printf "$container_id" > "$bind_files/etc/hostname" &&
            printf "127.0.0.1\tlocalhost\n::1\tlocalhost\n%s\t%s\n" "$container_ip" "$container_id" > "$bind_files/etc/hosts"

            shim_status=$?
        fi

        # Setup cgroup
        if [[ $shim_status -eq 0 ]]; then
            [ $is_cgroup2 -ne 0 ] || apply_cgroup_config "$cgroup_dir"
            shim_status=$?
        fi

        if [[ $shim_status -ne 0 ]]; then
            # Failed before we launch the container 
            error "There is a fault in the socker-shim process, before launch the container."
            echo "Exited ($shim_status)" >"$CONTAINERS_BASE_DIR/$container_id/status"
            # Do clean up
            rm -f $fifo
            [ $is_cgroup2 -ne 0 ] || rmdir $cgroup_dir 2>/dev/null
            ip link delete $veth_host 2>/dev/null
            ip link delete $veth_container 2>/dev/null

            exit $shim_status
        fi

        local rootfs="$CONTAINERS_BASE_DIR/$container_id/rootfs"
        local container_exit_status=0
        # TODO: limit the capabilities of the init process
        # TODO: check cmdline for shell script escaping errors
        # Run container with unshare in a empty environment
        # Note: It is necessary to use --fork since we are creating a new pid_namespace
        # Note: We have to put the init process into the target cgroup before set it into a new cgroup_namespace,
        #       that is why we separate the `unshare --cgroup` from the previous `unshare`
        env -i \
            unshare --pid --user --mount --net --uts \
            --fork --kill-child \
            /bin/sh -c "set -o errexit ; \
                exec 5<&- 4>&- ; \
                read PID _ </proc/self/stat ; \
                echo \$PID > $CONTAINERS_BASE_DIR/$container_id/pid ; \
                echo 'pid ready' >&6 ; \
                read event_pid_map <&3 ; \
                [ $is_cgroup2 -ne 0 ] || echo 1 > $cgroup_dir/cgroup.procs ; \
                exec unshare --cgroup /bin/sh -c ' \
                    set -o errexit ; \
                    mount -t proc proc $rootfs/proc ; \
                    mount -t sysfs -o ro sys $rootfs/sys ; \
                    mount -t cgroup2 cgroup $rootfs/sys/fs/cgroup ; \
                    mount --bind $bind_files/etc/resolv.conf $rootfs/etc/resolv.conf ; \
                    mount --bind $bind_files/etc/hosts $rootfs/etc/hosts ; \
                    mount --bind $bind_files/etc/hostname $rootfs/etc/hostname ; \
                    hostname $container_id ; \
                    read event_veth_set <&3 ; \
                    ip link set $veth_container name eth0 ; \
                    ip link set lo up ; \
                    ip link set eth0 up ; \
                    ip addr add $container_ip/24 dev eth0 ; \
                    ip route add default via ${DEFAULT_BRIDGE_IP} ; \
                    exec 3<&- 6>&- ; \
                    exec env -i \
                        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
                        HOSTNAME=$container_id \
                        chroot $rootfs $(cat $CONTAINERS_BASE_DIR/$container_id/cmdline)' \
                " & pid_of_unshare=$!

        # prevent from waiting for a died writer or reader
        exec 3<&- 6>&-

        if [[ $shim_status -eq 0 ]]; then
            # wait for pid ready
            read evet_pid_ready <&5 &&
            read pid_of_init < $CONTAINERS_BASE_DIR/$container_id/pid &&
            # set uid_map and gid_map
            echo -n "0 0 65536" > "/proc/$pid_of_init/uid_map" &&
            echo -n "0 0 65536" > "/proc/$pid_of_init/gid_map" &&
            echo 'uid map' >&4 &&
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
        [ $is_cgroup2 -ne 0 ] || rmdir $cgroup_dir 2>/dev/null
        ip link delete $veth_host 2>/dev/null
        ip link delete $veth_container 2>/dev/null

        exit $shim_status

    # Replace stdout and stderr with anonymous pipe. This may looks dirty but, safer. :)
    ) 1> >(cat >>"$CONTAINERS_BASE_DIR/$container_id/stdout") \
    2> >(cat >>"$CONTAINERS_BASE_DIR/$container_id/stderr") &
    echo $container_id
}

usage_exec() {
    echo "usage:    socker exec <container> <cmdline>"
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
    -h | --help)
        usage_exec
        exit 0
        ;;
    -*)
        error_arg $1
        usage_exec
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
    local cgroup_dir="/sys/fs/cgroup/socker-$container_id"
    local rootfs="$CONTAINERS_BASE_DIR/$container_id/rootfs"
    env -i nsenter --pid --user --mount --net --uts --target "$pid" /bin/sh -c \
        "[ $is_cgroup2 -ne 0 ] || echo \$\$ >> $cgroup_dir/cgroup.procs ; \
        exec env -i \
            PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
            HOSTNAME=$container_id \
            TERM=xterm \
            nsenter --target $pid --cgroup chroot $rootfs $arg_cmdline"
    # TODO: check `arg_interactive` and `arg_tty`
}

usage_stop() {
    echo "usage:    socker stop [options] <container>"
    echo ""
    echo "options:"
    echo "   -t, --time      Seconds to wait for stop before killing it (default 10)"
}

parse_args_stop() {
    arg_time=10
    while [[ $# -ne 0 && "$1" =~ ^- ]]; do case $1 in
    -t | --time)
        shift; arg_time=$1
        ;;
    -h | --help)
        usage_stop
        exit 0
        ;;
    -*)
        error_arg $1
        usage_stop
        exit 1
        ;;
    esac; shift; done

    [[ $# -ne 0 ]] || { error "container_id not provided"; exit 1; }
    arg_container_id="$1"
}

stop_container() {
    local container_id=$1
    local timeout=$2

    if [[ -d "$CONTAINERS_BASE_DIR/$container_id" && $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
        read pid <"$CONTAINERS_BASE_DIR/$container_id/pid"
        if [[ -d "/proc/$pid" ]]; then
            kill -TERM "$pid"
            if [[ -d "/proc/$pid" ]]; then
                sleep "$timeout"
                kill -KILL "$pid"
            fi
        else # The container exited due to an uncaught error in socker-shim. Here we mark the status as Exited directly
            echo "Exited" >"$CONTAINERS_BASE_DIR/$container_id/status"
        fi
    fi
    local cgroup_dir="/sys/fs/cgroup/socker-$container_id"
    [ $is_cgroup2 -ne 0 ] || rmdir $cgroup_dir 2>/dev/null || true
}

do_stop() {
    local container_id="$arg_container_id"
    stop_container "$container_id" "$arg_time"
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


usage_cgroup_options(){
    echo "      --cpuset-cpus CPU(s) numbers on which the container is to run, e.g. 0-4,6,8-10. See 'cpuset.cpus' in cgroup v2"
    echo "      --cpu-shares  Relative weights of CPU shares, in the range [1, 10000]. See 'cpu.weight' in cgroup v2"
    echo "      --memory      Max memory can be used (in bytes), e.g. 1G or 512M or max (default: max). See 'memory' in cgroup v2"
    echo "      --pids-limit  Maximum number of pids allowed in the container (default: max). See 'pids.max' in cgroup v2"
}

parse_arg_cgroup() {
    case $1 in
    --cpuset-cpus)
        arg_cpuset_cpus=$2
        ;;
    --cpu-shares)
        arg_cpu_shares=$2
        ;;
    --memory)
        arg_memory=$2
        ;;
    --pids-limit)
        arg_pids_limit=$2
        ;;
    *)
        return 1
        ;;
    esac
    return 0
}

merge_and_save_cgroup_config() {
    local container_id="$1"
    local config_file="$CONTAINERS_BASE_DIR/$container_id/cgroup"
    :> "$config_file"
    # If $arg_xxxx is not set, use the value of $cgroup_xxxx, otherwise use $arg_xxxx
    echo "cgroup_cpuset_cpus='${arg_cpuset_cpus-${cgroup_cpuset_cpus}}'" >> "$config_file"  # cpuset.cpus
    echo "cgroup_cpu_shares='${arg_cpu_shares-${cgroup_cpu_shares}}'" >> "$config_file"     # cpu.weight
    echo "cgroup_memory='${arg_memory-${cgroup_memory}}'" >> "$config_file"                 # memory.max
    echo "cgroup_pids_limit='${arg_pids_limit-${cgroup_pids_limit}}'" >> "$config_file"     # pids.max
}

load_cgroup_config_or_default() {
    local container_id="$1"
    local config_file="$CONTAINERS_BASE_DIR/$container_id/cgroup"
    # load default value
    cgroup_cpuset_cpus=""
    cgroup_cpu_shares=""
    cgroup_memory=""
    cgroup_pids_limit=""
    # override with value from config file
    [[ ! -e "$config_file" ]] || source "$config_file" # OK, this is indeed very unsafe, but the simplest
}

apply_cgroup_config() {
    local cgroup_dir="$1"

    warning_on_missing() {
        [[ -e $1 ]] || warning "This kernel does not support this cgroup2 parameter: $(basename $1)"
        [[ ! -e $1 ]] # return true if not exist
    }

    warning_on_missing "$cgroup_dir/cpuset.cpus" || echo "$cgroup_cpuset_cpus" > "$cgroup_dir/cpuset.cpus" # For cpuset.cpus, a empty value is valid
    [[ -z "$cgroup_cpu_shares" ]] || warning_on_missing "$cgroup_dir/cpu.weight" || echo "$cgroup_cpu_shares" > "$cgroup_dir/cpu.weight"
    [[ -z "$cgroup_memory" ]] || warning_on_missing "$cgroup_dir/memory.max" || echo "$cgroup_memory" > "$cgroup_dir/memory.max"
    [[ -z "$cgroup_pids_limit" ]] || warning_on_missing "$cgroup_dir/pids.max" || echo "$cgroup_pids_limit" > "$cgroup_dir/pids.max"
}

usage_update() {
    echo "usage:    socker update [options] <container>"
    echo ""
    echo "options:"
    usage_cgroup_options
}

parse_args_update() {
    while [[ $# -ne 0 && "$1" =~ ^- ]]; do case $1 in
    -h | --help)
        usage_update
        exit 0
        ;;
    -*)
        if [[ $# -ge 2 ]] && parse_arg_cgroup "$1" "$2" ; then
            shift ;
        else
            error_arg $1
            usage_update
            exit 1
        fi
        ;;
    esac; shift; done

    [[ $# -ne 0 ]] || { error "container_id not provided"; exit 1; }
    arg_container_id="$1"
    shift
}

do_update() {
    local container_id="$arg_container_id"
    # update and save cgroup config
    load_cgroup_config_or_default "$container_id"
    merge_and_save_cgroup_config "$container_id"

    warning_on_no_cgroup2

    if [[ $(cat "$CONTAINERS_BASE_DIR/$container_id/status") == "Running" ]]; then
        # reload and apply cgroup config
        load_cgroup_config_or_default "$container_id"
        local cgroup_dir="/sys/fs/cgroup/socker-$container_id"
        [ $is_cgroup2 -ne 0 ] || apply_cgroup_config "$cgroup_dir"
    fi
}

do_reset() {
    # Force stop and remove all containers
    if [[ -e $CONTAINERS_BASE_DIR ]]; then
        for container_id in $(ls "$CONTAINERS_BASE_DIR"); do
            stop_container "$container_id" 0
        done
        rm -rf "$CONTAINERS_BASE_DIR"
    fi
    # reset network
    reset_network
}

error_arg() {
    echo "[error] Unexpected argument: $1"
    echo ""
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
    echo "usage:"
    echo "    socker <command> [options]"
    echo ""
    echo "command:"
    echo "    install         Copy this script to /usr/local/bin/socker"
    echo "    create          Create a container"
    echo "    start           Start a container"
    echo "    exec            Execute a command in a running container"
    echo "    update          Update configuration of container"
    echo "    stop            Stop a running container"
    echo "    rm              Remove a container"
    echo "    ps              List all containers"
    echo "    reset           Remove all containers and reset network. In short, reset everything"
}

if [[ ${EUID} -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

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
update)
    shift
    parse_args_update "$@"
    do_update
    exit 0
    ;;
reset)
    shift
    do_reset
    exit 0
    ;;
*)
    error_arg $1
    usage
    exit 1
    ;;
esac
