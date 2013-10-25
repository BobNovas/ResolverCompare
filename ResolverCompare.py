#! /usr/bin/env python
# #######################################################################
# Copyright (c) 2013, Bob Novas, Shinkuro, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  - Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  - Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# #######################################################################

"""
$Id: ResolverCompare.py 476 2013-10-15 14:38:50Z bob.novas $

ResolverCompare: compare answers from two or more resolvers

Inputs:

    questions.dat, lists questions


"""

from difflib import Differ
import os
import string
import sys
import time
from optparse import OptionParser, NO_DEFAULT

from dns.message import Message
from dns.resolver import Resolver, NoAnswer, NXDOMAIN, YXDOMAIN, Answer, NoNameservers
from dns.exception import DNSException, Timeout
from dns.rcode import NOERROR
from dns.flags import AD, CD, DO
from dns import rdatatype

from rrSetSource import RRSetSource

rtt_stats = []

def usage():
    print("\nusage: %s -r <Resolver_1_ip>[/bind_ip] -r <Resolver_2_ip>[/bind_ip] [-y/-side-by-side] [-q/--quiet] [-t/--ttl_tolerance <tolerance>] <questions-file>\n"
          % (os.path.basename(sys.argv[0]), ))
    print(" questions file: each line has <name> <rdtype> [<rdclass>")

def usage_callback(option, opt_str, value, parser):
    usage()
    sys.exit()

def parse_args():
    """
    parse command line arguments
    """

    parser = OptionParser(add_help_option=False)

    try:
        parser.set_defaults(verbose=True, ttl_tolerance=-1, side_by_side=False, run_tests=False)

        parser.add_option("-r", "--resolver", action="append", dest="resolvers", type="string")
        parser.add_option("-q", "--quiet", action="store_false", dest="verbose")
        parser.add_option("-y", "--side-by-side", action="store_true", dest="side_by_side")
        parser.add_option("-t", "--ttl_tolerance", action="store", dest="ttl_tolerance", type="int")
        parser.add_option("-x", "--test", action="store_true", dest="run_tests")
        parser.add_option("-h", "--help", action="callback", callback=usage_callback)

        return parser.parse_args()

    finally:
        #parser has circular references and can be large
        parser.destroy()

def main():

    # parse and check command line args
    (options, args) = parse_args()
    if (len(options.ensure_value('resolvers', [])) != 2
        or len(args) != 1):
        usage()
        sys.exit()

    if options.run_tests:
        test()
        sys.exit()

    #copy arg values from parser output
    resolver_ips = options.resolvers
    verbose = options.verbose
    question_file = args[0]
    ttl_tolerance = int(options.ttl_tolerance)
    side_by_side = options.side_by_side

    #create dns resolvers (no dnssec for now)
    #source_ips is a list parallel to resolvers that contains the IPv4 address
    #to bind the query source address to -so you can control which interface the
    #query comes from - useful for testing on a machine with multiple nics.
    resolvers = []
    source_ips = []
    for resolver_ip in resolver_ips:

        resolver = Resolver()
        if resolver_ip.find('/') > 0:
            parts = resolver_ip.split('/')
            resolver.nameservers = [parts[0]]
            source_ips.append(parts[1])
        else:
            resolver.nameservers = [resolver_ip]
            source_ips.append(None)
        resolver.retry_servfail = True
        #resolver.use_edns(0, DO, 1200)
        resolver.lifetime = 5

        resolvers.append(resolver)

    #only compare 2 resolvers for now
    if len(resolvers) > 2:
        print("only 2 resolvers allowed for now..., picking first 2")
        resolvers = resolvers[:2]

    #loop over the question input and compare the results from the resolvers
    lineno = 0
    for line in file(question_file):

        #allow blank lines or lines that start with #
        if len(line.strip()) == 0 or line.lstrip().startswith("#"):
            continue

        #assume anything else is a question: <name> <rdtype> [<rdclass>]
        parts = line.strip().split(' ')
        name = parts[0].strip()
        rdtype = parts[1].strip()
        rdclass = parts[2].strip() if len(parts) > 2 else 'IN'
        lineno += 1

        results = []
        rtt_time = []
        for resolver, source_ip in zip(resolvers, source_ips):

            try:
                start_time = time.time()
                result = resolver.query(name, rdtype, rdclass, source=source_ip, raise_on_no_answer=False)
                end_time = time.time()

                results.append(result)
                rtt_time.append(end_time - start_time)

            except NXDOMAIN, nxd:
                results.append(nxd)
                rtt_time.append(-1)
            except YXDOMAIN, yxd:
                results.append(yxd)
                rtt_time.append(-1)
            except NoAnswer, noa:
                results.append(noa)
                rtt_time.append(-1)
            except Timeout, tmo:
                results.append(tmo)
                rtt_time.append(-1)
            except NoNameservers, nns:
                results.append(nns)
                rtt_time.append(-1)

        compare(Question(lineno, name, rdclass, rdtype),
                (resolvers[0], results[0], rtt_time[0]),
                (resolvers[1], results[1], rtt_time[1]),
                ttl_tolerance,
                verbose,
                side_by_side)

        rtt_stats.append(rtt_time)

    report_rtt_stats(resolver_ips)


def compare(q, t1, t2, ttl_tolerance, verbose, side_by_side):
    """
    use ResultHolder's to hold the results and compare them
    """
    ResultHolder(q, *t1).compare(ResultHolder(q, *t2), ttl_tolerance, verbose, side_by_side)

def report_rtt_stats(resolver_ips):

    n_resolvers = len(resolver_ips)

    rtt_mins = []
    rtt_maxs = []
    rtt_sums = []
    rtt_n = []

    for resolver_inx in range(n_resolvers):

        rtt_mins.append(1000000000.0)
        rtt_maxs.append(0.0)
        rtt_sums.append(0.0)
        rtt_n.append(0)

        for stat_tuple in rtt_stats:

            if stat_tuple[resolver_inx] != -1:
                rtt_mins[resolver_inx] = min(rtt_mins[resolver_inx], stat_tuple[resolver_inx])
                rtt_maxs[resolver_inx] = max(rtt_maxs[resolver_inx], stat_tuple[resolver_inx])
                rtt_sums[resolver_inx] += stat_tuple[resolver_inx]
                rtt_n[resolver_inx] += 1

    rpt = ''
    for resolver_inx in range(n_resolvers):
        rpt += ("%s min/avg/max = %d/%d/%d msec, " %
              (resolver_ips[resolver_inx],
               _ms(rtt_mins[resolver_inx]),
               _ms(rtt_sums[resolver_inx]/rtt_n[resolver_inx]),
               _ms(rtt_maxs[resolver_inx]), ))

    print("round trip times: %s" % (rpt[:-2], ))


class Question(object):
    """
    hold and represent a question
    """
    def __init__(self, lineno, name, rdclass, rdtype):
        self.lineno = lineno
        self.name = name
        self.rdclass = rdclass
        self.rdtype = rdtype

    def __str__(self):
        return "%d. %s %s %s" % (self.lineno, self.name, self.rdclass, self.rdtype, )


class ResultHolder(object):
    """
    hold everything there is about a result - the question, the resolver, and the result
    """
    def __init__(self, question, resolver, result, rtt_time):
        self.question = question
        self.resolver = resolver
        self.result = result
        self.rtt_time = rtt_time

    def summary(self):
        if isinstance(self.result, DNSException):
            return self.result
        else:
            return self.result.response

    def compare(self, other, ttl_tolerance, verbose, side_by_side):
        if not isinstance(other, ResultHolder):
            self.report("can't compare %s to %s" % (self.__class__, other.__class__, ))
            return

        if type(self.summary()) != type(other.summary()):
            self.report("different results: %s != %s" % (type(self.summary()), type(other.summary()), ))
            return

        if isinstance(self.summary(), DNSException):
            #exceptions match
            self.report("Equal")
            return

        elif isinstance(self.summary(), Message):

            my_response = self.result.response
            other_response = other.result.response

            my_rcode = my_response.rcode()
            other_rcode = other_response.rcode()
            if my_rcode != other_rcode:
                self.report("Different rcodes: %d != %d" % (my_rcode, other_rcode, ))
                return

            my_answ = RRSetSource(my_response.answer)
            my_answ_rrsets = my_answ.list_rrsets()
            other_answ = RRSetSource(other_response.answer)
            other_answ_rrsets = other_answ.list_rrsets()

            #if at least one result has an answer section, ...
            if len(my_answ_rrsets) != 0 or len(other_answ_rrsets) != 0:
                # compare the answer sections
                return self.compare_section(other, my_answ_rrsets, other_answ_rrsets, ttl_tolerance, verbose, side_by_side)

            else:
                #otherwise, compare the authority sections
                my_auth = RRSetSource(my_response.authority)
                my_auth_rrsets = my_auth.list_rrsets()
                other_auth = RRSetSource(other_response.authority)
                other_auth_rrsets = other_auth.list_rrsets()
                return self.compare_section(other, my_auth_rrsets, other_auth_rrsets, ttl_tolerance, verbose, side_by_side)

        else:
            raise ValueError("oops-program error...")


    def compare_section(self, other, my_rrsets, other_rrsets, ttl_tolerance, verbose, side_by_side):
        """
        Compare the RRsets in one section to the RRsets in another section
        """
        #count the number of different RR's based on any difference in the number of RRs in each RRset
        Same = Diff = 0

        #now compare RRs from the two RRsets
        my_cmp_rrsets = my_rrsets[:]
        other_cmp_rrsets = other_rrsets[:]
        for my_rrset in my_rrsets:
            if my_rrset in other_cmp_rrsets:
                my_cmp_rrsets.remove(my_rrset)
                other_cmp_rrsets.remove(my_rrset)
                Same += len(my_rrset)
        Diff += len(my_cmp_rrsets) + len(other_cmp_rrsets)
        N = Same + Diff

        if N == Same and Diff == 0:
            # the RRsets match...
            ttls_match = True
            if ttl_tolerance >= 0:
                for my_rrset, other_rrset in zip(my_rrsets, other_rrsets):
                    if abs(my_rrset.ttl - other_rrset.ttl) > ttl_tolerance:
                        txt_rdtype = rdatatype.to_text(my_rrset.rdtype)
                        if not side_by_side:
                            self.report("Equal but TTL of %s rrset differs (%d!=%d), rtt=%d/%d"
                                        % (txt_rdtype, my_rrset.ttl, other_rrset.ttl, _ms(self.rtt_time), _ms(other.rtt_time), ))
                        ttls_match = False
                        break

            if side_by_side:
                if not ttls_match:
                    self.report_side_by_side(my_rrsets, other_rrsets)
                else:
                    if verbose:
                        self.report("Equal (Size=%d, rtt=%d/%d)" % (N, _ms(self.rtt_time), _ms(other.rtt_time), ))
            else:
                if not ttls_match or verbose:
                    self.report("Equal (Size=%d, rtt=%d/%d)" % (N, _ms(self.rtt_time), _ms(other.rtt_time), ))

        else:
            # the RRsets differ
            if side_by_side:
                self.report_side_by_side(my_rrsets, other_rrsets)
            else:
                self.report("Differ: Size=%d, Equal: %d, Differ: %d, rtt=%d/%d" % (N, Same, Diff, _ms(self.rtt_time), _ms(other.rtt_time)))

    def report(self, message):
        print("%s, %s" % (self.question, message, ))

    def report_side_by_side(self, my_rrsets, other_rrsets):
        """
        """
        d = Differ()

        my_rrsets.sort(key=lambda rrset:rrset.rdtype)
        other_rrsets.sort(key=lambda rrset:rrset.rdtype)
        for x,y in zip(my_rrsets, other_rrsets):
            my_sorted_rrs = x.to_text().split('\n')
            my_sorted_rrs.sort(key=string.lower)
            other_sorted_rrs = y.to_text().split('\n')
            other_sorted_rrs.sort(key=string.lower)
            diff = [l.rstrip() for l in d.compare(my_sorted_rrs, other_sorted_rrs)]
            if len(diff) == 4 and diff[1].startswith('?') and diff[1].startswith('?'):
                qstlen = max(40, len(self.question.__str__()))
                cmplen = max(len(diff[0]), len(diff[2]))
                usecmplen = max(60, cmplen)
                fmt = "%%-%ds: %%-%ds|%%-%ds" % (qstlen, usecmplen, usecmplen, )
                print(fmt % (self.question, diff[0], diff[2], ))
                print(fmt % ("",            diff[1], diff[3], ))

            else:
                qstlen = max(40, len(self.question.__str__()))
                maxcmplen = 0
                for line in diff:
                    maxcmplen = max(maxcmplen, len(line))
                usecmplen = max(60, maxcmplen)
                fmt = "%%-%ds: %%-%ds|%%-%ds" % (qstlen, usecmplen, usecmplen, )
                question = self.question
                for line in diff:
                    if line.startswith("  "):
                        print(fmt % (question, line, line))
                    elif line.startswith("- "):
                        print(fmt % (question, line, ""))
                    elif line.startswith("+ "):
                        print(fmt % (question, "", line))
                    question = ""

def _ms(time_in_seconds):
    return int((time_in_seconds + .0005) *1000)


def test():
    """
    """
    import dns

    def mkDNSAnswer(response):
        q0 = response.question[0]
        qname = q0.name
        rdclass = q0.rdclass
        rdtype = q0.rdtype
        return dns.resolver.Answer(qname, rdtype, rdclass, response)


    def mkQuestion(line_no, dnsQuestion):
        name = dnsQuestion.name.to_text()
        rdclass = dns.rdataclass.to_text(dnsQuestion.rdclass)
        rdtype = dns.rdatatype.to_text(dnsQuestion.rdtype)
        return Question(line_no, name, rdclass, rdtype)

    line_no = 0

    shinkuro_dot_com_ns = 'id 24140\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nshinkuro.com. IN NS\n;ANSWER\nshinkuro.com. 14338 IN NS UDNS2.ULTRADNS.net.\nshinkuro.com. 14338 IN NS ns3.shinkuro.com.\nshinkuro.com. 14338 IN NS ns.shinkuro.com.\nshinkuro.com. 14338 IN NS UDNS1.ULTRADNS.net.\n;AUTHORITY\n;ADDITIONAL'
    shinkuro_dot_com_soa = 'id 35536\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nshinkuro.com. IN SOA\n;ANSWER\nshinkuro.com. 14017 IN SOA ns.shinkuro.com. steve.shinkuro.com. 2013100801 14400 3600 8640000 1800\n;AUTHORITY\n;ADDITIONAL'

    # test 1: missing RR
    line_no += 1
    response = dns.message.from_text(shinkuro_dot_com_ns)
    result = mkDNSAnswer(response)
    rh1 = ResultHolder(mkQuestion(line_no, response.question[0]), None, result, 0.1)
    response_2 = dns.message.from_text(shinkuro_dot_com_ns)
    del response_2.answer[0][0]
    result_2 = mkDNSAnswer(response_2)
    rh2 = ResultHolder(mkQuestion(line_no, response.question[0]), None, result_2, 0.2)
    rh1.compare(rh2, -1, True, True)

    # test 2: 2 missing RRs, one each side
    line_no += 1
    response = dns.message.from_text(shinkuro_dot_com_ns)
    del response.answer[0][1]
    result = mkDNSAnswer(response)
    rh1 = ResultHolder(mkQuestion(line_no, response.question[0]), None, result, 0.1)
    response_2 = dns.message.from_text(shinkuro_dot_com_ns)
    del response_2.answer[0][0]
    result_2 = mkDNSAnswer(response_2)
    rh2 = ResultHolder(mkQuestion(line_no, response.question[0]), None, result_2, 0.2)
    rh1.compare(rh2, -1, True, True)

    # test 3: differing SOA
    line_no += 1
    comcast_soa_string = 'id 27169\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\ncomcast.net. IN SOA\n;ANSWER\ncomcast.net. 7200 IN SOA dns101.comcast.net. domregtech.comcastonline.com. 2008181441 7200 3600 1209600 3600\n;AUTHORITY\n;ADDITIONAL'

    response = dns.message.from_text(shinkuro_dot_com_soa)
    result = mkDNSAnswer(response)
    rh1 = ResultHolder(mkQuestion(line_no, response.question[0]), None, result, 0.2)
    response_2 = dns.message.from_text(shinkuro_dot_com_soa.replace('2013100801', '2013100200'))
    result_2 = mkDNSAnswer(response_2)
    rh2 = ResultHolder(mkQuestion(line_no, response.question[0]), None, result_2, 0.3)
    rh1.compare(rh2, -1, True, True)

if __name__ == "__main__":
    main()
