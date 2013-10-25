About ResolverCompare
=====================

This project contains python code that issues DNS queries 
to resolvers and compares the resulting DNS responses.

The comparison can either note the number of equal and unequal
resource records in the answer, or can compare the results
side by side, showing the differences like diff. 


Prerequisites
=============

dnspython is a prerequisite. You must have the very latest
dnspython installed. Note that dnspython version 1.11.0 has
multiple releases and only the latest fixes a bug that 
ResolverCompare expresses.  In dns/resolver.py, line 881
should be: 

    if rcode != dns.rcode.SERVFAIL or not self.retry_servfail:
    
The bug is that this line is missing "self." in earlier releases.
