#Enter column names of database
tablename = 'compromised_processed'
id_field = 'id' #Integer, primary_key
username_field = 'username'
password_field = 'password' #String(255)
domain_field = 'domain' #String(255)
date_added = 'date_added' #TIMESTAMPTZ
dump_name = 'dump_name' #String(255)
date_dump = 'date_dump' #TIMESTAMPTZ

dialect = 'postgres'
sqluser = ''
sqlpass = ''
sqlserver = 'localhost'
sqldatabase = 'phoenixdb'

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
