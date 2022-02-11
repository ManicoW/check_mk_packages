#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# Check_mk agent for rbl_blacklist
# GPL (C) Nicolas Lafont <ndev@wdmedia.net>, 2022
# GPL (C) Lars Falk-Petersen <dev@falk-petersen.no>, 2020

# TODO : Add IPv6 support

import os
import sys
import time
import socket
import ipaddress # Check if IP is private
from netifaces import interfaces, ifaddresses, AF_INET # Get IPs

version = 3
verbose = False

class Blacklists(object):
    """ A class to hold the data structure for blacklists. Avoid _ in names. """

    def __init__(self, name, domain, response={}, results='', removal='', always_black='', always_white=''):
        self.name = name # Shortname for check
        self.domain = domain # Domain for check
        self.response = response # If response == key, value is the list we're on
        self.results = results
        self.removal = removal # Url for removal. <IP> will be replaced by blacklisted IP.
        self.always_black = always_black # https://tools.ietf.org/html/rfc5782#section-5 says "IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes." but not everyone does. If they do (or have another test address) it's added here.
        self.always_white = always_white # https://tools.ietf.org/html/rfc5782#section-5 says "IPv4-based DNSxLs MUST NOT contain an entry for 127.0.0.1."

        # Sanity checks:

        if not self.domain.startswith('.'):
            raise ValueError('Domains must start with a dot, %s given.' % self.domain)
        if 2 > len(self.name):
            raise ValueError('Must have a name (over 1 character long), %s given.' % self.name)
        if self.removal and not self.removal.startswith('http'):
            raise ValueError('Removal must be a web address if not empty, %s given.' % self.removal)

    def check_list(self, external_ips, verbose = False):
        """
            Look-up reversed ip + blacklist domain, and use result as key in
            response dict to add url to results. Then return string if lists
            we're blacklisted in.

            Args:
                external_ips - dict { IP: reversed_ip }
        """
        if verbose:
            print('Checking list %s' % self.name)
            start_time = time.time()

        for ip in external_ips:
            if '.' in ip: # Check IPv4 address
                try:
                    self.results += ('%s listed in %s%s, ' % (
                        ip,
                        self.response[socket.gethostbyname(external_ips[ip] + self.domain)],
                        '' if 0 == len(self.removal) else ' %s ' % self.removal
                    )).replace('<IP>', ip)
                except socket.gaierror:
                    pass # Empty DNS response means not listed (or dead service...)
                except KeyError as err:
                    if verbose:
                        print("Error: blacklist %s responds with a code that is not listed, %s." % (self.domain, ip))

            else: # Check IPv6 address
                if verbose:
                    print("No IPv6 support yet")
        if verbose and self.results:
            print('results %s' % self.results)
            print ("Done in %s. " % round(time.time()-start_time, 3))
        return self.results


def reverse_ipv4 (ipv4):
    ''' Reverse IPv4 address, i.e. 127.0.0.1 -> 1.0.0.127 '''
    return ".".join(reversed(ipv4.split('.')))

def reverse_ipv6 (ipv4):
    ''' Reverse IPv6, remove :, add . for each character, i.e. 
        1234:0000:0000:0111 -> 1.1.1.0.0.0.0.0.0.0.0.0.4.3.2.1 '''
    return ".".join("".join(reversed(ip.split(':'))))

def is_ipv4 (ip):
    ''' Returns True if IPv4, False if IPv6. '''

    if '.' in ip:
        return True
    if ':' in ip:
        return False

    raise ValueError('IP %s seems not to be IPv4 or IPv6.' % ip)

def build_collection():
    ''' Build blacklist collection and return list '''

    collection = []
    collection += [
        Blacklists(
            name='abuse.ch', # No obvious way to loop-up, delist
            domain='.spam.abuse.ch',
            response={'127.0.0.2': 'spam.abuse.ch'},
            always_white='127.0.0.2'),
        Blacklists(
            name='anti-spam.cn',
            domain='.cblplus.anti-spam.org.cn',
            response={
                '127.0.8.2': 'cblplus.anti-spam.org.cn',
                '127.0.8.6': 'cblplus.anti-spam.org.cn'},
            removal='http://anti-spam.cn/appeal.action',
            always_white='127.0.0.2'),
        Blacklists(
            name='barracudacentral.org',
            domain='.b.barracudacentral.org',
            response={'127.0.0.2': 'b.barracudacentral.org'},
            removal='http://barracudacentral.org/rbl/removal-request',
            always_black='127.0.0.2'),
        Blacklists(
            name='cobion.com/IBM',
            domain='.dnsbl.cobion.com',
            response={
                '127.0.0.1': 'dnsbl.cobion.com',
                '127.0.0.2': 'dnsbl.cobion.com'},
            removal='https://exchange.xforce.ibmcloud.com/url/<IP>',
            always_white='127.0.0.2'),
        Blacklists(
            name='manitu.net', # No obvious way to loop-up, delist
            domain='.ix.dnsbl.manitu.net',
            response={'127.0.0.2': 'ix.dnsbl.manitu.net'},
            always_black='127.0.0.2'),
        Blacklists(
            name='rbl-dns.com',
            domain='.bl.rbl-dns.com',
            response={'127.0.0.2': 'spam.rbl-dns.com', '127.0.0.3': 'dul.rbl-dns.com'},
            removal='https://www.rbl-dns.com/bl?ip=<IP>',
            always_black='127.0.0.2'),
        Blacklists(
            name='rbl.jp', # No obvious way to loop-up, delist
            domain='.all.rbl.jp',
            response={'127.0.0.2': 'all.rbl.jp'},
            always_white='127.0.0.2'),
        Blacklists(
            name='realtimeblacklist.com',
            domain='.rbl.realtimeblacklist.com',
            response={'127.0.0.2': 'rbl.realtimeblacklist.com'},
            removal='https://realtimeblacklist.com/lookup/?<IP>',
            always_black='127.0.0.2'),
        Blacklists(
            name='redhawk.org',
            domain='.access.redhawk.org',
            response={'127.0.0.2': 'access.redhawk.org'},
            removal='https://www.redhawk.org/SpamHawk/query.php',
            always_black='127.0.0.2'),
        Blacklists(
            name='sorbs.net',
            domain='.dnsbl.sorbs.net',
            response={
                '127.0.0.2': 'http.dnsbl.sorbs.net',
                '127.0.0.3': 'socks.dnsbl.sorbs.net',
                '127.0.0.4': 'misc.dnsbl.sorbs.net',
                '127.0.0.5': 'smtp.dnsbl.sorbs.net',
                '127.0.0.6': 'spam.dnsbl.sorbs.net',
                '127.0.0.7': 'web.dnsbl.sorbs.net',
                '127.0.0.8': 'block.dnsbl.sorbs.net',
                '127.0.0.9': 'zombie.dnsbl.sorbs.net',
                '127.0.0.10': 'dul.dnsbl.sorbs.net',
                '127.0.0.11': 'badconf.rhsbl.sorbs.net',
                '127.0.0.12': 'nomail.rhsbl.sorbs.net'},
            removal='http://www.sorbs.net/cgi-bin/support',
            always_black='127.0.0.2'),
        Blacklists(
            name='spamhaus.org',
            domain='.zen.spamhaus.org',
            response={
                '127.0.0.2': 'sbl.spamhaus.org',
                '127.0.0.3': 'css.spamhaus.org',
                '127.0.0.4': 'cbl.abuseat.org',
                '127.0.0.5': 'www.njabl.org',
                '127.0.0.6': 'xbl.spamhaus.org',
                '127.0.0.7': 'xbl.spamhaus.org',
                '127.0.0.10': 'pbl.spamhaus.org',
                '127.0.0.11': 'pbl.spamhaus.org'},
            removal='https://www.spamhaus.org/query/ip/<IP>',
            always_black='127.0.0.2'),
        Blacklists(
            name='spamcop.net',
            domain='.bl.spamcop.net',
            response={'127.0.0.2': 'bl.spamcop.net'},
            removal='https://www.spamcop.net/w3m?action=checkblock&ip=<IP>',
            always_black='127.0.0.2'),
        Blacklists(
            name='spamrats.com',
            domain='.spam.spamrats.com',
            response={'127.0.0.38': 'spam.spamrats.com'},
            removal='http://spamrats.com/lookup.php?ip=<IP>',
            always_white='127.0.0.2'),
        Blacklists(
            name='spewsl2sorbs.net',
            domain='.l2.spews.dnsbl.sorbs.net',
            response={'127.0.0.2': 'l2.spews.dnsbl.sorbs.net'},
            removal='http://www.sorbs.net/general/using.shtml',
            always_black='127.0.0.2'),
        Blacklists(
            name='swinog.ch',
            domain='.dnsrbl.swinog.ch',
            response={'127.0.0.3': 'dnsrbl.swinog.ch'},
            removal='https://antispam.imp.ch/',
            always_white='127.0.0.2'),
        Blacklists(
            name='gbudb.net',
            domain='.truncate.gbudb.net',
            response={'127.0.0.2': 'truncate.gbudb.net'},
            removal='http://www.gbudb.com/truncate/how-ips-are-removed.jsp',
            always_black='127.0.0.2'),
        Blacklists(
            name='lashback.com',
            domain='.ubl.unsubscore.com',
            response={'127.0.0.2': 'ubl.unsubscore.com'},
            removal='http://blacklist.lashback.com/',
            always_black='127.0.0.2'),
        Blacklists(
            name='wbpl',
            domain='.db.wpbl.info',
            response={'127.0.0.2': 'db.wpbl.info'},
            always_black='127.0.0.2',
            removal='http://wpbl.info/cgi-bin/detail.cgi?ip=<IP>'),
        Blacklists(
            name='uceprotect-level1',
            domain='.dnsbl-1.uceprotect.net',
            response={'127.0.0.2': 'dnsbl-1.uceprotect.net'},
            always_black='127.0.0.2',
            removal='http://www.uceprotect.net/en/rblcheck.php?ipr=<IP>'),
        Blacklists(
            name='uceprotect-level2',
            domain='.dnsbl-2.uceprotect.net',
            response={'127.0.0.2': 'dnsbl-2.uceprotect.net'},
            always_black='127.0.0.2',
            removal='http://www.uceprotect.net/en/rblcheck.php?ipr=<IP>'),
        Blacklists(
            name='uceprotect-level3',
            domain='.dnsbl-3.uceprotect.net',
            response={'127.0.0.2': 'dnsbl-3.uceprotect.net'},
            always_black='127.0.0.2',
            removal='http://www.uceprotect.net/en/rblcheck.php?ipr=<IP>'),
        Blacklists(
            name='backscatterer.org',
            domain='.ips.backscatterer.org',
            response={'127.0.0.2': 'ips.backscatterer.org'},
            always_black='127.0.0.2',
            always_white='127.0.0.1',
            removal='http://www.backscatterer.org/?target=test'),

        # Removed blacklists:
        # bad.psky.me https://glockapps.com/blacklist/bad-psky-me/
        # psbl.surriel.com Listed as active in https://glockapps.com/blacklist/psbl-surriel-com/, but seems dead
        # virbl.dnsbl.bit.nl https://virbl.bit.nl/

    ]
    return collection

def get_check_frequency():
    '''
    Guess how often agent is run, based on digits in script path.
    I.e. /usr/lib/check_mk_agent/local/300/blacklist-agent.py => 300
    '''

    script_path = os.path.realpath(__file__)
    freq = ''

    for p in script_path.split(os.path.sep):
        if p.isdigit():
            freq = 'running every %s second, ' % int(p)
            break
    return freq

def get_host_and_IPs():
    ''' Fetch all public IPv4 addresses '''

    ipaddress_list = []

    # Fetch IPv4
    for ifaceName in interfaces():
        for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'127.0.0.1'}]):
            ipaddress_list.append(i['addr'])

    # Build a dict of public IPs with reverse as value (IP given on CLI is accepted)
    external_ips = {}
    for ip in ipaddress_list:
        if not ipaddress.ip_address(ip).is_private:
            if is_ipv4(ip):
                external_ips[ip] = reverse_ipv4(ip)
            else:
                # TODO: not handling IPv6 yet.
                if verbose:
                    external_ips[ip] = reverse_ipv6(ip)

    if verbose:
        print('external_ips %s, revips %s' 
            % ((','.join(external_ips.keys())), (','.join(external_ips.values()))))

    return external_ips
 
def main(verbose=False):
    print ('<<<blacklist>>>')

    # Set verbosity
    if 1 < len(sys.argv):
        for arg in sys.argv[1:]:
            if arg == 'verbose':
                verbose = True

    external_ips = get_host_and_IPs()

    # Ask all blacklist providers, and print results
    if external_ips:
        collection = build_collection()
        for provider in collection:
            result = provider.check_list(external_ips, verbose)

            print ('blacklist_%s %s %s' % (
                    provider.name,
                    result.count(','),
                    result if result else 'Not listed.')
            )

    # Check-name, 0, timestamp, version, frequency of run and IPs used.
    print ('blacklist_status %s %s, %sAgent version %s, IPs checked: %s. ' % \
        (
            0 if len(external_ips) else 1,
            time.strftime("%Y-%m-%d %H:%M"),
            get_check_frequency(),
            version,
            {", ".join(external_ips.keys())}
        )
    )

if __name__ == "__main__":
    main(verbose)
