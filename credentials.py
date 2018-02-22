

UCSC_LDAP_SERVER = ''
UCSC_LDAP_DN = ''
UCSC_LDAP_FIELDS = ''
UCSC_LDAP_BIND_DN = ""

SOE_LDAP_SERVER = ''
SOE_LDAP_DN = ''
SOE_LDAP_FIELDS = ""

# How long to wait before performing the next LDAP query or bind
# Probably not an issue for small batches, larger batches we may want to consider being nicer
# to the ldap server. I have run a 0.1 delay against 5000 lines without issue or complaint from IDM.
LDAP_ACTION_DELAY = 0.1