"""
    Code adapted from Brian Hall <brian@ucsc.edu>

    Jonathan Kung <jhkung@ucsc.edu>
    University of California, Santa Cruz Information Security Team
"""
import ldapServer
import argparse
import time
import psycopg2 as p

start = int(time.time())

#start connection
try:
    con = p.connect ("dbname = 'phoenixdb' host = 'localhost'")
except:
    print "Unable to connect to database."

cur = con.cursor()

cur.execute("DELETE FROM compromised_processed WHERE id > 0")
con.commit()

#Reset id key in rtbh to correct value
cur.execute("SELECT setval('compromised_processed_id_seq', (SELECT MAX(id) FROM compromised_processed)+1);")
con.commit()

parser = argparse.ArgumentParser(description='Process args')
parser.add_argument('-dumpname', help="Name of password dump.")
parser.add_argument('-dateadded', help="Date of dump.")
parser.add_argument('-username', help="Username without domain. Only uid field will be searched for a direct match.")
parser.add_argument('-uservalue', help="Searches for string as exact uid or substring in primary/alternate email.")
parser.add_argument('-file', help="A file containing one username per line. uid direct match search only.")
parser.add_argument('-noemailformat', help="Set value to true if usernames do not contain @ symbol or domain.")
parser.add_argument('-showonlyindir', help="Set value to true to hide output lines for users not in the directory.")
parser.add_argument('-ucscldap', help="Use the UCSC ldap server. This is the default.")
parser.add_argument('-soeldap', help="User the SOE ldap server.")
args = parser.parse_args()

dumpName = args.dumpname
dateAdded = args.dateadded
noEmailFormat = args.noemailformat
username = args.username
uservalue = args.uservalue
fName = args.file
showOnlyInDir = args.showonlyindir
ucscLdap = args.ucscldap
soeLdap = args.soeldap

lineCount = 0
#ldapObj = ldapServer.ldapServer()
if fName is not None and dumpName is None and dateAdded is None:
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
                sql = "SELECT * FROM compromised_processed WHERE username = %s"
                data = (username,)
                cur.execute(sql, data)
                row = cur.fetchall()
                if row == []:
                    sql = "INSERT INTO compromised_processed (username, password, domain) VALUES (%s, %s, %s)"
                    data = (username, password, domain)
                    cur.execute(sql, data)
con.commit()
con.close()

end = int(time.time())
print "Finished in " + str(end - start) + " seconds"
