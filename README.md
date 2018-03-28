# Compromised Credentials Validation

An all-in-one automated program that processes and validates the authenticity of potentially compromised accounts.

### Key Features
* Determines whether **username:password** combination has previously been processed
* .txt and .xlsx file support
* Support for multiple databases for data storage utilizing SQLAlchemy:

```
    Firebird
    Microsoft SQL Server
    MySQL
    Oracle
    PostgreSQL
    SQLite
    Sybase
```
* Ability to load in previously processed compromised account data
* Standard LDAP validation process

**NOTE: For program to function correctly, these conditions must be met:** 

1. Each line in text file must be in this **exact** format:

```
user@domain:password
    or 
user@domain
```

2. Database to store credentials must contain these **exact** column names:

```
  id (integer, pkey) #auto-increment
  username (string)  
  password (string)  
  domain (string)  
  date_added (string)  
  dump_name (string)  
  date_dump (string) 
```

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.  

Begin by navigating to your Python environment.  
Current release only supports Python 2.7 . Support for Python 3 may be available in the future.

```
~ cd to desired directory
~ git clone https://github.com/jkung2314/Validation
```

### Setup

To install required libraries:

```
~ cd /Validation
~ pip install -r requirements.txt
```

Configure the settings.py file

```
Fields to be edited, NOTE: ALL FIELDS ARE STRINGS
  Database:
    tablename = '' #name of table in database
    dialect = '' #Supports 'firebird', 'mssql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'sybase'
    sqluser = '' #username
    sqlpass = '' #password
    sqlserver = '' #host:port
    sqldatabase = '' #database name
  
  LDAP Server:
    LDAP_SEARCH_STRING = '' #Fields to search if user exists in LDAP; Example: '( |(uid={0})(mail=*{0}*) )'
    LDAP_UID_SEARCH_STRING = '' #Fields to search if user exists in LDAP Example: '(uid={0})'
    LDAP_SERVER = '' #LDAP Server 
    LDAP_DN = '' #LDAP DN
    LDAP_FIELDS = [''] #LDAP fields to search 
    LDAP_BIND_DN = "" #LDAP BIND DN 
  
  Runtime:
    showData = None #Change to 'false' to print all rows not found in database or 'true' to print all rows 
      found in database, else: keep as 'None' to print nothing each iteration except for results of binds.  
    showOnlyInDir = None #Set value to 'true' to hide output lines for users not in the LDAP,
      else: keep as 'None'
    fileType = None #Change to 'xlsx' if .xlsx file, else: keep as 'None'
    fileName = '' #Name of file if in same folder, or path to file
    dateAdded = None #Insert date of dump, else: keep as 'None', 
      #database dependent
    dumpName = None #Insert name of password dump, else: keep as 'None'
    
  Special Cases:
    1. If text file contains usernames only WITH a domain:
         matchPassword = 'false'
    2. If text file contains usernames only WITHOUT a domain:
         noEmailFormat = 'true'
         matchPassword = 'false'
    3. To load in data to database only:
         dataOnly = 'true'
```

## Running the program

If processing file:

```
python validation.py
```

If processing individual email to determine validity of username:

```
python validation.py -u [email]
```
