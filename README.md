# dns server
Some implementations of rfc 1035.

There is a little explanation about some files that you would like to modify:

### domains.json
- domain (array): domain name
    - address (string): ipv4/ipv6 address
    - type (number): for ipv4 use 1, for ipv6 use 28

### nameservers.txt
Set nameservers ipv4 to handle with domains that are not in domains.json

### main.rs
Set ip to bind socket at some network interface.
