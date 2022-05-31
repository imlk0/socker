#!/usr/bin/env bash

set -o errexit    # Used to exit upon error, avoiding cascading errors
set -o pipefail   # Unveils hidden failures
set -o nounset    # Exposes unset variables

outer_addr=''
inner_addr=''
net_ns_name="rn$$"
veth_outer_name="rn$$_vo"
veth_inner_name="rn$$_vi"
out_interface=''

need_internet=0
cmd_user=
publish_list=()
forward_list=()


in_subnet() {
    local subnet mask subnet_split ip_split subnet_mask subnet_start subnet_end ip rval
    local readonly BITMASK=0xFFFFFFFF

    IFS=/ read subnet mask <<<"${1}"
    IFS=. read -a subnet_split <<<"${subnet}"
    IFS=. read -a ip_split <<<"${2}"

    subnet_mask=$(($BITMASK << $((32 - $mask)) & $BITMASK))
    subnet_start=$((${subnet_split[0]} << 24 | ${subnet_split[1]} << 16 | ${subnet_split[2]} << 8 | ${subnet_split[3]} & ${subnet_mask}))
    subnet_end=$(($subnet_start | ~$subnet_mask & ${BITMASK}))
    ip=$((${ip_split[0]} << 24 | ${ip_split[1]} << 16 | ${ip_split[2]} << 8 | ${ip_split[3]} & ${BITMASK}))

    (($ip >= $subnet_start)) && (($ip <= $subnet_end)) && rval=0 || rval=1
    return ${rval}
}

setup_addr() {
    local ip ok
    for ip_num in {0..255}; do
        ip="192.168.${ip_num}.1"
        ok=1
        for subnet in $(ip addr | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9][0-9]?\b"); do
            in_subnet ${subnet} ${ip} && {
                ok=0
                break
            }
        done
        if [[ ${ok} -eq 1 ]]; then
            outer_addr="192.168.${ip_num}.1"
            inner_addr="192.168.${ip_num}.2"
            return
        fi
    done
    error "Unable to find unused subnet in range 192.168.0.0 - 192.168.255.0, please customize it" ; exit 1
}

setup_interface() {
    local dev
    dev=$(ip -4 route list 0/0 | cut -d ' ' -f 5)
    if [[ ${dev} == "" ]]; then
        error "Can not identify the default gateway interface. You must specify it by --out-if" ; exit 1
    fi
    out_interface=$dev
}

# start up env
start_up() {
    # add net namespace
    ip netns add ${net_ns_name}

    # add veth
    ip link add ${veth_outer_name} type veth peer name ${veth_inner_name}
    # setup veth_outer
    ip link set ${veth_outer_name} up
    ip addr add ${outer_addr}/24 dev ${veth_outer_name}

    # setup veth_inner
    ip link set ${veth_inner_name} netns ${net_ns_name}
    ip netns exec ${net_ns_name} ip link set ${veth_inner_name} up
    ip netns exec ${net_ns_name} ip addr add ${inner_addr}/24 dev ${veth_inner_name}
    # enable loopback
    ip netns exec ${net_ns_name} ip link set lo up

    if [[ ${need_internet} -eq 1 ]]; then
        # add default route
        ip netns exec ${net_ns_name} ip route add default via ${outer_addr}
        # enable NAT
        bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
        iptables -t nat -A POSTROUTING -s ${inner_addr}/24 -o ${out_interface} -j MASQUERADE
        iptables -t filter -A FORWARD -i ${out_interface} -o ${veth_outer_name} -j ACCEPT
        iptables -t filter -A FORWARD -o ${out_interface} -i ${veth_outer_name} -j ACCEPT
    fi
}

# shut down env
shut_down() {
    if [[ ${need_internet} -eq 1 ]]; then
        # disable NAT
        iptables -t nat -D POSTROUTING -s ${inner_addr}/24 -o ${out_interface} -j MASQUERADE
        iptables -t filter -D FORWARD -i ${out_interface} -o ${veth_outer_name} -j ACCEPT
        iptables -t filter -D FORWARD -o ${out_interface} -i ${veth_outer_name} -j ACCEPT
    fi
    # delete veth
    ip link delete ${veth_outer_name}
    # delete net namespace
    ip netns delete ${net_ns_name}
}

setup_port_mapping() {
    for publish in ${publish_list[@]}; do
        type=
        if [[ ${type} == */* ]]; then
            type=${publish##*/}
        fi
        type=${type:-"tcp"}
        port_map=${publish%/*}
        port_src=${port_map%:*}
        port_dest=${inner_addr}:${port_map##*:}
        info "publish: host[0.0.0.0:${port_src}]\t--(${type})->\tcontainer[${port_dest}]"
        socat -lf/dev/null ${type}-listen:${port_src},fork ${type}:${port_dest} &
    done

    for forward in ${forward_list[@]}; do
        type=
        if [[ ${type} == */* ]]; then
            type=${forward##*/}
        fi
        type=${type:-"tcp"}
        port_map=${forward%/*}
        port_src=${port_map%:*}
        port_dest=${port_map##*:}
        if [[ ${port_src} != *:* ]]; then
            port_src=127.0.0.1:${port_src}
        fi
        info "forward: host[${port_src}]\t<-(${type})--\tcontainer[0.0.0.0:${port_dest}]"
        unix_file="/tmp/socker$$_${type}_${port_src}_${port_dest}"
        socat -lf/dev/null unix-listen:\"${unix_file}\",fork ${type}:${port_src} &
        ip netns exec ${net_ns_name} socat -lf/dev/null ${type}-listen:${port_dest},fork unix-connect:\"${unix_file}\" &
    done
}

do_install(){
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

kill_this() {
    shut_down
    pkill -P $$
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
    echo "options:"
    echo "    --internet                          Enable Internet access"
    echo "    --out-if=<interface>                Specify the default network interface, only required if --internet is specified."
    echo "    --user=<username>                   The user that the program runs as."
    echo "    --forward=[host:]<port>:<port>      Forward a external port([host:]<port>) to the inside the container."
    echo "    --publish=<port>:<port>             Publish the port inside the container to the host."


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
    do_exec
    exit 0
    ;;
stop)
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


while true; do
    case $1 in
    --internet) # need internet access
        need_internet=1
        shift
        ;;
    --user=*)
        cmd_user=${1:7}
        shift
        ;;
    --out-if=*)
        out_interface=${1:9}
        shift
        ;;
    --publish=*:*)
        publish_list+=(${1:10})
        shift
        ;;
    --forward=*:*)
        forward_list+=(${1:10})
        shift
        ;;
    -)
        shift
        break
        ;;
    -*)
        usage
        exit 1
        ;;
    *)
        break
        ;;
    esac
done


setup_addr

[[ ${out_interface} == "" ]] && setup_interface

trap kill_this EXIT

start_up
setup_port_mapping

# TODO: change this
cmd="$*"

if [[ ${cmd_user} == "" ]]; then
    cmd_user=${SUDO_USER}
fi
if [[ ${cmd_user} != "" ]]; then
    cmd="sudo -u ${cmd_user} ${cmd}"
else
    warning "\${SUDO_USER} is empty and cmd will run as root"
fi
ip netns exec ${net_ns_name} ${cmd}