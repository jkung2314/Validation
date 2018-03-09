#Output settings, note: settings are strings
type = None #Set to 'xlsx' if xlsx file, else keep as 'None'
dataonly = None #Set to true if you only want to add to database, and not send to LDAP
dateadded = None #Date of dump.
dumpname = None #Name of password dump.
showonlyindatabase = None #Set value to 'false' to print values not found in database and 'true' to print values found in database.
matchpassword = None #If your file does not contain a password set this to 'false'.
username = None #Username without domain. Only uid field will be searched for a direct match.
uservalue = None #Searches for string as exact uid or substring in primary/alternate email.
file = 'compromise_list.txt' #A file containing one username per line. uid direct match search only.
noemailformat = None #Set value to true if usernames do not contain @ symbol or domain.
showonlyindir = None #Set value to true to hide output lines for users not in the directory.
ucscldap = None #Use the UCSC ldap server. This is the default.
soeldap = None #Use the SOE ldap server.

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
