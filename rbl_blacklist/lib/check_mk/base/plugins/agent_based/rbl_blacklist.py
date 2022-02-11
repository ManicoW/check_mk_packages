#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# Check_mk plugin for rbl_blacklist

# GPL (C) Nicolas Lafont <ndev@wdmedia.net>, 2022
# GPL (C) Lars Falk-Petersen <dev@falk-petersen.no>, 2020
# (c) 2013 Heinlein Support GmbH
#          Robert Sander <r.sander@heinlein-support.de>

# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  This file is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.

from .agent_based_api.v1.type_defs import (
    CheckResult,
    DiscoveryResult,
    HostLabelGenerator,
)

from .agent_based_api.v1 import (
    check_levels,
    register,
    Result,
    State,
    HostLabel,
    Service,
    )

return_status = State.UNKNOWN

def inventory_blacklist(section):
    '''
    the checkmk inventory function
    '''

    for line in section:
        yield Service(item=line[0])

def check_blacklist(item, section):
    '''
    the checkmk check function
    '''

    for line in section:
        if line[0] == item:
            message = ''
            status = State.UNKNOWN

            # Parse info from agent output
            count = None
            description = ' '.join(line[2:])
            try:
                count = int(line[1])
            except ValueError:
                print ("Error count: %s. " % line)
                continue

            if 0 < count:
                status = State.WARN
            else:
                status = State.OK

            message += "%s" % description
            yield Result(state=status, summary=message)
            return

register.check_plugin(
    name="blacklist",
    service_name="RBL %s",
    discovery_function=inventory_blacklist,
    check_function=check_blacklist,
)
