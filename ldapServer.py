"""
Brian Hall
UCSC

Handles ldap interactions and methods.
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

    def connect(self):
        self._LDAP_SERVER = credentials.LDAP_SERVER
        self._LDAP_DN = credentials.LDAP_DN
        self._LDAP_FIELDS = credentials.LDAP_FIELDS
        self._connection = ldap.initialize(self._LDAP_SERVER)


    def search(self, uservalue):
        if self._connection is None:
            self.connect()

        results = self._connection.search_s(self._LDAP_DN, ldap.SCOPE_SUBTREE, credentials.LDAP_SEARCH_STRING.format(uservalue), self._LDAP_FIELDS )
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
            self._connection.simple_bind_s(credentials.LDAP_BIND_DN.format(username), password)
            self._connection.unbind()
            self._connection = None
            return '*** Valid credentials ***'
        except ldap.INVALID_CREDENTIALS as e:
            return 'Invalid credentials - {0}'.format(e)
        except Exception as e:
            return 'Exception: {0}'.format(e)
