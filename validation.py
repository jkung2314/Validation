"""
    Code adapted from Brian Hall <brian@ucsc.edu>

    Jonathan Kung <jhkung@ucsc.edu>
    University of California, Santa Cruz Infrastructure Security Team
"""
import credentials
import ldapServer
from datetime import datetime
import time
import xlrd
import psycopg2 as p
from DB import compromisedDB
import progressbar

start = int(time.time())
current_time = datetime.now()

database = compromisedDB()
#start connection
try:
    database.connect()
except:
    print "Unable to connect to database."

fileFormat = credentials.type
dataOnly = credentials.dataonly
dateAdded = credentials.dateadded
dumpName = credentials.dumpname
showData = credentials.showonlyindatabase
matchPassword = credentials.matchpassword
username = credentials.username
uservalue = credentials.uservalue
fName = credentials.file
noEmailFormat = credentials.noemailformat
showOnlyInDir = credentials.showonlyindir
ucscLdap = credentials.ucscldap
soeLdap = credentials.soeldap

ldapObj = ldapServer.ldapServer() #New ldap object

# Default to UCSC ldap server
if ucscLdap is None and soeLdap is None:
    ldapObj.setUCSCServer()
elif soeLdap is not None:  # Use SOE ldap server if it's available
    ldapObj.setSOEServer()
elif soeLdap is not None and ucscLdap is not None: # maybe later we'll query both if not found in one or the other.
    print "Error: Both UCSC and SOE ldap servers selected. Right now this script can only do one at a time."
ldapObj.connect()

#Function for Binding
def Bind(username, password, user):
    result = ldapObj.bind(username, password)

    if result == "*** Valid credentials ***" and showOnlyInDir == "true":
        print "Result: {0}, user: {1}, password: {2},rowdata: {3}".format(result, username, password, user)
    else:
        print "Result: {0}, user: {1}, password: {2},rowdata: {3}".format(result, username, password, user)

#LDAP function for email:password format
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

#LDAP function for username only format
def Uldap(username):
    result = ldapObj.uid_search(username)

    if len(result) < 1:
        if showOnlyInDir != "true":
            print "{0} is not in campus LDAP".format(username)
    else:
        print result

#Check if in Postgres database
def inDatabase(username, password, showData):
    row = database.searchUsername(username)
    if row[0] == 0:
        return False
    else:
        if password == None:
            return True
        else:
            data = database.searchUsernamePassword(username, password)
            if data[0] == 0:
                return False
            elif showData == "true":
                print str(data[1]) + "\n"
            return True

#finish
def done():
    database.close() #commit and close

    end = int(time.time())
    print "Finished in " + str(end - start) + " seconds"
    exit(1)

#If -file given
lineCount = 0
errorList = []
if fName is not None:
    if fileFormat == "xlsx":
        try:
            workbook = xlrd.open_workbook(fName)
            sheet = workbook.sheet_by_index(0)
            userList = []
            for row in range(sheet.nrows):
                userList.append(sheet.cell_value(row, 0))
        except IOError as e:
            print e
    else:
        try:
            userList = open(fName).read().strip().rsplit('\n')
        except IOError as e:
            print e
    with progressbar.ProgressBar(max_value=len(userList)) as progress:
        for user in userList:
            lineCount = lineCount + 1
            if noEmailFormat != "true":
                if str(user).find("@") > 0:
                    username = user[0:str(user).find("@")]
                    if ":" in str(user):
                        password = user.split(":")
                        password = password[1]
                        domain = user.split("@")
                        domain = domain[1].split(":")
                        domain = domain[0]
                    elif matchPassword == "false":
                        password = None
                    else:
                        errorList.append("(email:password) formatted incorrectly in line " + str(lineCount) + ", username: " + username)
                        continue
                    if inDatabase(username, password, showData) == False:
                        database.insert(username, password, domain, current_time, dumpName, dateAdded)
                        if showData == "false":
                            print (username + " NOT in database, sending to LDAP...")
                        if dataOnly is None:
                            if password != None:
                                continue
                                #Fldap(username, user, password)
                            else:
                                continue
                                #Uldap(username)
                    else:
                        if showData == "true":
                            print (username + " LOCATED in database, ignoring...")
            progress.update(lineCount)
    if errorList is not None:
        for error in errorList:
            print error
    done()

#If -username given
if username is not None:
    if noEmailFormat != "true":
        if str(username).find("@") > 0:
            username = username[0:str(username).find("@")]
            print username
            password = None
            if inDatabase(username, password, showData) == False:
                domain = None
                database.insert(username, password, domain, current_time, dumpName, dateAdded)
                if showData == "false":
                    print (username + " NOT in database, sending to LDAP...")
                if dataOnly is None:
                    Uldap(username)
            else:
                if showData == "true":
                    print (username + " LOCATED in database, ignoring...")
    done()
