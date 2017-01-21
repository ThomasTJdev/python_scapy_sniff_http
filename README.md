Sniff HTTP traffic for pwd's etc.
========================================

Module for sniffing HTTP traffic and finding PWD's, cookies, etc.

## Requirements
* Python3
* scapy

## The script
 The script uses scapy to work with the packages. Regex is used for finding info.
 The main purpose is to extract password and username from packets.
 
### Regex
   The regex is for password looking for pass and pwd. Adjust appropiated.

License
-------

MIT, 2016 Thomas TJ (TTJ)

Other
-----

Want to try it with WMDframework? Check the module here [WMD](https://github.com/ThomasTJdev/WMD)
