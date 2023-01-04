# UntrustedTLSCerts - nmap script for threat hunting purposes

## What does this script do:
Retrieves a server's x509 certificate and detects certificates which their
SubjectName is part of a list of suspicious names or IPs, or it is a self-signed certificate.

As enhanced functionality, I included:
- The result of looking for suspicious names in the SubjectAltName field as well.
- Output a warning if the validity period is less than 31 days or more than 1000 days.
- The result of looking for the fingerprint of the certificate (SHA1) in the .csv file (added as an extra column).
- Added an extra .csv file with malicious issuer information to do the same procedure above (SubjectName / CommonName) but with the issuer information.

# How to use:

To launch the script:

`nmap --script=untrustedTLScerts.nse ...`

It is recommended to include the script inside the nmap's scipts folder (mine is at `/usr/share/nmap/scripts`)

[+] This script accepts parameters (the Subject and Issuer list to check with) with the `--script-args`.

[+] The parameters accepted are `list` to specify the Subject list, and `issuer-list` to specify the Issuer list.

[+] By default, if not specified, both lists use a list called `list.csv` and `issuer_list.csv`. The format of the lists needs to be like the attached in this repository.

# Example of output

```
# Nmap 7.91 scan initiated Thu Nov 24 07:33:09 2022 as: nmap --script=untrustedTLScerts.nse -p443 -Pn -n -oN test1.txt 10.0.3.149
Nmap scan report for 10.0.3.149
Host is up (0.00048s latency).

PORT    STATE SERVICE
443/tcp open  https
| untrustedTLScerts: 
| -----------------------------------
| Subject CommonName: maliciousname.com
| Subject organizationName:JacoboyAngel
| Subject localityName:Spain
| Subject countryName:ES
| Subject Alternative Name: DNS:AnotherAltName.com
| -----------------------------------
| ---------------WARNING---------------
| Malicious ALTERNATIVE NAME found ---> DNS:AnotherAltName.com
| Found in line [1]: 12/02/2022;critical;AnotherAltName.com
| -----------------------------------
| ---------------WARNING---------------
| Malicious subject commonName found ---> maliciousname.com
| Found in line [2]: 14/02/2022;critical;maliciousname.com;b725d3cab335091c943a2f3494dc428627e97122
| -----------------------------------
| ---------------WARNING---------------
| Fingerprint of this certificate is on the blocklist ---> b725d3cab335091c943a2f3494dc428627e97122
| Found in line [2]: 14/02/2022;critical;maliciousname.com;b725d3cab335091c943a2f3494dc428627e97122
| -----------------------------------
| ---------------WARNING---------------
| Malicious issuer commonName found ---> maliciousname.com
| Found in line [2]: 14/02/2022;critical;maliciousname.com;b725d3cab335091c943a2f3494dc428627e97122
| -----------------------------------
| Be careful! Some information of this certificate appears in the blocklist.
| -----------------------------------
| Issuer CommonName: maliciousname.com
| Issuer organizationName:JacoboyAngel
| The certificate is self-signed as both subject and issuer certificates are the same.
| -----------------------------------
| Not valid before: 2022-11-20T13:14:28
| Not valid after:  2031-02-06T13:14:28
| ---------------WARNING---------------
|_The validity of this certificate is TOO LONG (3000 days!)

# Nmap done at Thu Nov 24 07:33:09 2022 -- 1 IP address (1 host up) scanned in 0.56 seconds


```

# untrustedTLScerts
