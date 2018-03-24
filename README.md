# Compromised Credentials Validation

An all in one program that manages and validates the authenticity of potentially compromised accounts. 

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.  

Begin by navigating to your Python environment.  
Current release only supports Python 2.7 . Support for Python 3 may be available in the future.

```
~ cd to desired directory
~ git clone ...path to be determined
```

### Setup

To install required libraries:

```
~ cd to /Validation
~ pip install -r requirements.txt
```

Configure the settings.py file

```
Database setup:
  dialect = '' #Supports 'firebird', 'mssql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'sybase'
  sqluser = '' #username
  sqlpass = '' #password
  sqlserver = '' #host:port
  sqldatabase = '' #database name
```

## Running the program

If processing file:

```
python validation.py
```

If processing individual email:password combination:

```
python validation.py -u [email] -p [password]
```
