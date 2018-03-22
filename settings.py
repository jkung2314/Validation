#Output settings, note: settings are strings
fileType = None #Set to 'xlsx' if xlsx file, else keep as 'None'
dataOnly = None #Set to true if you only want to add to database, and not send to LDAP
dateAdded = None #Date of dump.
dumpName = None #Name of password dump.
showData = None #Set value to 'false' to print values not found in database and 'true' to print values found in database.
matchPassword = None #If your file does not contain a password set this to 'false'.
fileName = None #A file containing one username per line. uid direct match search only.
noEmailFormat = None #Set value to true if usernames do not contain @ symbol or domain.
showOnlyInDir = None #Set value to true to hide output lines for users not in the directory.

#Enter column names of database
tablename = 'compromised_processed' #CHANGE TO CORRESPONDING TABLENAME
id_field = 'id' #DO NOT CHANGE
username_field = 'username' #DO NOT CHANGE
password_field = 'password' #DO NOT CHANGE
domain_field = 'domain' #DO NOT CHANGE
date_added = 'date_added' #DO NOT CHANGE
dump_name = 'dump_name' #DO NOT CHANGE
date_dump = 'date_dump' #DO NOT CHANGE

dialect = 'postgres'
sqluser = ''
sqlpass = ''
sqlserver = 'localhost'
sqldatabase = 'phoenixdb'

LDAP_SEARCH_STRING = '' # Example: '( |(uid={0})(mail=*{0}*) )'
LDAP_UID_SEARCH_STRING = '' # Example: '(uid={0})'
LDAP_SERVER = ''
LDAP_DN = ''
LDAP_FIELDS = ''
LDAP_BIND_DN = ""

# How long to wait before performing the next LDAP query or bind
# Probably not an issue for small batches, larger batches we may want to consider being nicer
# to the ldap server. I have run a 0.1 delay against 5000 lines without issue or complaint from IDM.
LDAP_ACTION_DELAY = 0.1
