example：

```sh
sudo ./socker.sh create --rootfs ./images/busybox.tar /bin/sleep infinity
sudo ./socker.sh ps
sudo ./socker.sh start 37c2064da778
sudo ./socker.sh update --memory 512M 37c2064da778
sudo ./socker.sh exec 37c2064da778 sh
sudo ./socker.sh stop -t 1 37c2064da778
sudo ./socker.sh rm 37c2064da778
```

for dev：
- Show output of specific container
    ```sh
    tail -f /var/lib/socker/containers/37c2064da778/std*
    ```
- Track the execution of the script
    ```sh
    sudo bash -x ./socker.sh start 37c2064da778
    ```
