Version 0.1.2
=============
Released: 2013-01-13 02:32:24 +0100

 * Update lispd a bit. Not finished by far, but better now :-)
 * Fix wrong checks in LISPMapReferralRecord
 * Fix bug in MapReferral packet building
 * Disable some bad checks in the code. To be fixed later...
 * Process rsvd1, rsvd2 and flags fields in LCAF addresses. LCAFInstanceAddress needs rsvd2 for the IID-mask-len
 * Add a get_udp() method to the ECM class
 * Add get_lisp_message(), get_lisp_data_packet() and get_lisp_control_packet() methods to the UDPMessage class
 * Add is_fragmented() method to IP packets
 * Merge branch 'master' of https://github.com/steffann/pylisp
 * Do not include editor backup files in git...
 * fixed doctest for ECM parsing
 * fixed doctest for ECM parsing
 * Add start of lispd and a basic settings module
 * Add a get_final_payload() method to IPv4 to match IPv6
 * Twisted doesn't support IPv6 properly, so stop using it
 * Automatically decode ECM payloads
 * add placeholder for a LISPd
 * automatic changelog generation added
