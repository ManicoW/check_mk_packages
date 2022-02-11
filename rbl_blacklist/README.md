# rbl_blacklist check for check_mk

## Overview

Check_mk plugin to check if a host IPs are blacklisted. Create one check for each DNSBL list checked.

## Installation

### Check_mk server

* Requires Python 3.5 or higher.
* Use the mkp to install (https://docs.checkmk.com/latest/en/mkps.html).

### Monitored server

* Requires Python 3.5 or higher.
* Requires Python module netifaces.
* The agent should be run as a cached plugin, i.e. in /3600/ to run once an hour.
* The agent can be found in the Setup/Agents section of OMD

## TODO

* IPv6 support

## Inspiration

[checkmk-blacklist ](https://gitlab.com/larsfp/checkmk-blacklist) by Lars Falk-Petersen
[netifaces](https://github.com/HeinleinSupport/check_mk_extensions/tree/cmk2.0/netifaces) by Robert Sander / Heinlein Support GmbH
