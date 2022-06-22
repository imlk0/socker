# 🦪 socker

`socker` is a container engine written in Bash shell scripting language. The name socker comes from `shell` + `docker`.

This is implemented to be a homework, and we cannot provide any security/stability guarantees (although we do try), please do not use it for production environments.

# Dependencies

We use all common (in terms of the toolset provided by busybox for example) tools. The external tools that require additional checking are
- ip
- iptables
- brctl

# Usage

```
usage:
    socker <command> [options]

command:
    install         Copy this script to /usr/local/bin/socker
    create          Create a container
    start           Start a container
    exec            Execute a command in a running container
    update          Update configuration of container
    stop            Stop a running container
    rm              Remove a container
    ps              List all containers
    reset           Remove all containers and reset network. In short, reset everything
```

# Examples

- Create a container from rootfs (.tar file)
```sh
sudo ./socker.sh create --rootfs ./images/ubuntu.tar /bin/sleep infinity
```

- List all containers

```sh
sudo ./socker.sh ps
```

```txt
CONTAINER ID    COMMAND                         STATUS          NETWORK
a7a134754c26    /bin/sleep infinity             Created         192.168.101.2
```

- Start a container and show it's status

```sh
sudo ./socker.sh start a7a134754c26
sudo ./socker.sh ps
```
```txt
CONTAINER ID    COMMAND                         STATUS          NETWORK
a7a134754c26    /bin/sleep infinity             Running         192.168.101.2
```

- Execute command in a running container

```sh
sudo ./socker.sh exec a7a134754c26 ps -ef
```
```txt
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 07:08 ?        00:00:00 /bin/sleep infinity
root          15       0  0 07:10 ?        00:00:00 ps -ef
```
- Stop and remove a container

```sh
sudo ./socker.sh stop a7a134754c26
sudo ./socker.sh rm a7a134754c26
```