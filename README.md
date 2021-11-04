# network

A VPC written in golang.

Assign internal IP addresses to servers where all traffic sent internally is encrypted.

## OS Specific

#### Linux (requires root)

The make file exists to help build and test code.

```
$ make          # builds windows and linux
$ make windows  # builds only windows
$ make linux    # builds only linux
$ make deps     # installs all dependencies 
$ make lint     # runs the linter
$ make test     # runs all unit tests
```

List of arguments
```
$ ./bin/network --help
Usage of ./bin/network:
      --config string        Config file location (default "config.yaml")
      --create string        create a client/signal/relay-client/relay-server instance
      --create_name string   name of the instanced created by --create
      --logs string          Directory to contain log files (default "logs")
      --noheader             Disable the startup header
      --nologs               Disable file logging
pflag: help requested
exit status 2
```

#### Windows (requires admin)

This project makes use of wintun, the tunnel device for windows by WireGaurd.
You will have to download the dll file.
<a href="https://www.wintun.net/">https://www.wintun.net/</a>
Download the zip archive and extract the dll from the bin folder that corresponds to your CPU architecture.
Ie. AMD64  = 64 bit
    i386   = 32 bit

You can either place the DLL next to the binary or you can install it to your `C:/Windows/System32` folder for global use.

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
