"""
Brian Hall
UCSC
Updated: 3/23/2017

Handles ldap interactions and methods to set UCSC ldap server or others.
Maybe we should move the ldap strings out into a credentials file?

"""
import ldap
import credentials


class ldapServer:
    _LDAP_SERVER = ''
    _LDAP_DN = ''
    _LDAP_FIELDS = []
    _connection = None

    def __init__(self, LDAP_SERVER="", LDAP_DN="", LDAP_FIELDS=""):
        _LDAP_SERVER = LDAP_SERVER
        _LDAP_DN = LDAP_DN
        _LDAP_FIELDS = LDAP_FIELDS

    def setUCSCServer(self):
        self._LDAP_SERVER = credentials.UCSC_LDAP_SERVER
        self._LDAP_DN = credentials.UCSC_LDAP_DN
        self._LDAP_FIELDS = credentials.UCSC_LDAP_FIELDS

    def setSOEServer(self):
        self._LDAP_SERVER = credentials.SOE_LDAP_SERVER
        self._LDAP_DN = credentials.SOE_LDAP_DN
        self._LDAP_FIELDS = credentials.SOE_LDAP_FIELDS

    def connect(self):
        self._connection = ldap.initialize(self._LDAP_SERVER)


    def search(self, uservalue):
        if self._connection is None:
            self.connect()

        results = self._connection.search_s(self._LDAP_DN, ldap.SCOPE_SUBTREE, '(|(uid={0})(mail=*{0}*)(ucscPersonPubAlternateMail=*{0}*))'.format(uservalue), self._LDAP_FIELDS )
        return results

    def uid_search(self, username):
        if self._connection is None:
            self.connect()

        results = self._connection.search_s(self._LDAP_DN, ldap.SCOPE_SUBTREE, '(uid={0})'.format(username), self._LDAP_FIELDS )
        return results

    def bind(self, username, password):
        try:
            if self._connection is None:
                self.connect()
            #self._connection.set_option(ldap.OPT_REFERRALS,0) # stops referrals, usually only needed for AD.
            self._connection.simple_bind_s(credentials.UCSC_LDAP_BIND_DN.format(username), password)
            self._connection.unbind()
            self._connection = None
            return '*** Valid credentials ***'
        except ldap.INVALID_CREDENTIALS as e:
            return 'Invalid credentials - {0}'.format(e)
        except Exception as e:
            return 'Exception: {0}'.format(e)
