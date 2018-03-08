# For connecting
from sqlalchemy import create_engine

# For schema/mapped class
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Sequence

# For session management
from sqlalchemy.orm import sessionmaker

import credentials

__Base = declarative_base()

tablename = credentials.tablename

# Database table mapping class
class Compromised(__Base):
    __tablename__ = tablename

    id = Column(Integer, primary_key=True)
    username = Column(String)
    password = Column(String)
    domain = Column(String)
    date_added = Column(String)
    dump_name = Column(String)
    date_dump = Column(String)

    def __repr__(self):
        return "username='{0}', password='{1}', domain='{2}, '"\
               "date_added='{3}', dump_name='{4}', date_dump='{5}'".format(self.username,
                self.password, self.domain, self.date_added, self.dump_name,
                self.date_dump)

# Class for handling database transactions
class compromisedDB():
    # global session
    __session = None
    __engine = None

    def connect(self):
        # Set up connection string for postgres DB
        # connString = 'dialect+driver://username:password@host:port/database'
        connString = '{0}://{1}:{2}@{3}/{4}'.format(credentials.dialect, credentials.sqluser, credentials.sqlpass,
                                               credentials.sqlserver, credentials.sqldatabase)

        self.__engine = create_engine(connString)

        # Create the session, store in global
        Session = sessionmaker(bind=self.__engine)
        self.__session = Session()

    def searchUsername(self, username):
        # query for an exact match on username only
        q = self.__session.query(Compromised).filter(Compromised.username == username)
        return q.count(), q.all()

    def searchUsernamePassword(self, username, password):
        # query for an exact match on username + password
        q = self.__session.query(Compromised).filter(Compromised.username == username,
                                                     Compromised.password == password)
        return q.count(), q.all()

    # add a row with these values
    def insert(self, username, password, domain, date_added, dump_name, date_dump):
        row = Compromised(username=username, password=password, domain=domain,
                date_added=date_added, dump_name=dump_name, date_dump=date_dump)
        self.__session.add(row)

    def close(self):
        self.__session.commit()
        self.__session = None
        self.__engine = None
