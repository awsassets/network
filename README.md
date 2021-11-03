# network

A VPC written in golang.

Assign internal IP addresses to servers where all traffic sent internally is encrypted.

## OS Building

#### Linux
```
go build .
./network 
```

```
./network --create node --create_name node
```

#### Windows (running relay or node requires admin)
```
go build .
./network.exe
```

```
./network --create node --create_name node
```

If you want the DNS to resolve inside WSL you need to do a bit of configuring.
1. Enable a DNS_PROXY (look at Env Variables no 1)
2. Modify the `/etc/resolv.conf` inside WSL adding the following lines
```
search internal.disembark # disembark auto generated
nameserver 172.10.0.52 # disembark auto generated
nameserver 8.8.8.8 # disembark auto generated
```
3. You can replace the `8.8.8.8` nameserver with anyother nameserver you want to use.

### Env Variables

1. (WINDOWS ONLY) If you want to auto configure the firewall, you can do so by setting the following env value:

`DISEMBARK_WINDOWS_FIREWALL=1`
By running
```
$env:DISEMBARK_WINDOWS_FIREWALL = '1'
```

Alternatively you can set the rule manually by typing
```
netsh advfirewall firewall add rule name="Disembark" dir=in action=allow protocol=ANY remoteip=10.10.0.0/16
```

2. If you want to change the DNS proxy so by setting the following env value:

`DISEMBARK_DNS_PROXY=8.8.8.8`
By running on widows
```
$env:DISEMBARK_DNS_PROXY = '8.8.8.8'
```

or 


```
export DISEMBARK_DNS_PROXY=8.8.8.8
```
