"""
    Code adapted from Brian Hall <brian@ucsc.edu>

    Jonathan Kung <jhkung@ucsc.edu>
    University of California, Santa Cruz Information Security Team
"""
import ldapServer
import argparse
from datetime import datetime
import time
import psycopg2 as p

start = int(time.time())
current_time = datetime.now()

#start connection
try:
    con = p.connect ("dbname = 'phoenixdb' host = 'localhost'")
except:
    print "Unable to connect to database."

cur = con.cursor()

#Reset id key in rtbh to correct value
cur.execute("SELECT setval('compromised_processed_id_seq', (SELECT MAX(id) FROM compromised_processed)+1);")
con.commit()

parser = argparse.ArgumentParser(description='Process args')
parser.add_argument('-dataonly', help="Set to true if you only want to add to database, and not send to LDAP")
parser.add_argument('-dateadded', help="Date of dump.")
parser.add_argument('-dumpname', help="Name of password dump.")
parser.add_argument('-showonlyindatabase', help="Set value to 'false' to print values not found in database and 'true' to print values found in database.")
parser.add_argument('-username', help="Username without domain. Only uid field will be searched for a direct match.")
parser.add_argument('-uservalue', help="Searches for string as exact uid or substring in primary/alternate email.")
parser.add_argument('-file', help="A file containing one username per line. uid direct match search only.")
parser.add_argument('-noemailformat', help="Set value to true if usernames do not contain @ symbol or domain.")
parser.add_argument('-showonlyindir', help="Set value to true to hide output lines for users not in the directory.")
parser.add_argument('-ucscldap', help="Use the UCSC ldap server. This is the default.")
parser.add_argument('-soeldap', help="User the SOE ldap server.")
args = parser.parse_args()

showData = args.showonlyindatabase
dataOnly = args.dataonly
dateAdded = args.dateadded
dumpName = args.dumpname
noEmailFormat = args.noemailformat
username = args.username
uservalue = args.uservalue
fName = args.file
showOnlyInDir = args.showonlyindir
ucscLdap = args.ucscldap
soeLdap = args.soeldap

ldapObj = ldapServer.ldapServer() #New ldap object

# Default to UCSC ldap server
if ucscLdap is None and soeLdap is None:
    ldapObj.setUCSCServer()
elif soeLdap is not None:  # Use SOE ldap server if it's available
    ldapObj.setSOEServer()
elif soeLdap is not None and ucscLdap is not None: # maybe later we'll query both if not found in one or the other.
    print "Error: Both UCSC and SOE ldap servers selected. Right now this script can only do one at a time."
#ldapObj.connect()

def Bind(username, password, user):
    result = ldapObj.bind(username, password)

    if result == "*** Valid credentials ***" and showOnlyInDir == "true":
        print "Result: {0}, user: {1}, password: {2},rowdata: {3}".format(result, username, password, user)
    else:
        print "Result: {0}, user: {1}, password: {2},rowdata: {3}".format(result, username, password, user)

def Fldap(username, user, password):
    result = ldapObj.uid_search(username)

    if len(result) < 1:
        if showOnlyInDir != "true":
            print "{0} is not in campus LDAP\n".format(username)
    else:
        print [result[0][0], username, user]
        Bind(username, password, user)

    # sleep for a little bit to avoid hammering the ldap
    time.sleep(0.1)

def Uldap(username):
    result = ldapObj.uid_search(username)

    if len(result) < 1:
        if showOnlyInDir != "true":
            print "{0} is not in campus LDAP".format(username)
    else:
        print result

#Check if in Postgres database
def inDatabase(username, password, showData):
    sql = "SELECT * FROM compromised_processed WHERE username = %s"
    data = (username,)
    cur.execute(sql, data)
    row = cur.fetchall()
    if row == []:
        return False
    else:
        if password == None:
            return True
        else:
            sql = "SELECT * FROM compromised_processed WHERE username = %s AND password = %s"
            data = (username, password)
            cur.execute(sql, data)
            data = cur.fetchall()
            if data == []:
                return False
            elif showData == "true":
                print data
            return True

def done():
    con.commit()
    con.close()

    end = int(time.time())
    print "Finished in " + str(end - start) + " seconds"
    exit(1)

#Insert into Postgres database
def insert(username, password, domain, current_time, dumpName, dateAdded):
        sql = "INSERT INTO compromised_processed (username, password, domain, date_added, date_dump, dump_name) VALUES (%s, %s, %s, %s, %s, %s)"
        data = (username, password, domain, current_time, dumpName, dateAdded)
        cur.execute(sql, data)

lineCount = 0
if fName is not None:
    try:
        userList = open(fName).read().strip().rsplit('\n')
    except IOError as e:
        print e

    for user in userList:
        lineCount = lineCount + 1
        if noEmailFormat != "true":
            if str(user).find("@") > 0:
                username = user[0:str(user).find("@")]
                password = user.split(":")
                domain = user.split("@")
                domain = domain[1].split(":")
                domain = domain[0]
                try:
                    password = password[1]
                except IndexError:
                    print ("(email:password) formatted incorrectly in line " + str(lineCount) + ", username: " + username)
                    continue
                if inDatabase(username, password, showData) == False:
                    insert(username, password, domain, current_time, dumpName, dateAdded)
                    if showData == "false":
                        print (username + " NOT in database, sending to LDAP...")
                    if dataOnly is None:
                        #Fldap(username, user, password)
                        continue
                else:
                    if showData == "true":
                        print (username + " LOCATED in database, ignoring...")
    done()

if username is not None:
    if noEmailFormat != "true":
        if str(username).find("@") > 0:
            username = username[0:str(username).find("@")]
            print username
            password = None #or NULL?
            if inDatabase(username, password, showData) == False:
                domain = None #or NULL?
                insert(username, password, domain, current_time, dumpName, dateAdded)
                if showData == "false":
                    print (username + " NOT in database, sending to LDAP...")
                if dataOnly is None:
                    Uldap(username)
            else:
                if showData == "true":
                    print (username + " LOCATED in database, ignoring...")
    done()
