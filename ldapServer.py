import ldap
import settings

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
        self._LDAP_SERVER = settings.LDAP_SERVER
        self._LDAP_DN = settings.LDAP_DN
        self._LDAP_FIELDS = settings.LDAP_FIELDS
        self._connection = ldap.initialize(self._LDAP_SERVER)


    def search(self, uservalue):
        if self._connection is None:
            self.connect()

        results = self._connection.search_s(self._LDAP_DN, ldap.SCOPE_SUBTREE, settings.LDAP_SEARCH_STRING.format(uservalue), self._LDAP_FIELDS )
        return results

    def uid_search(self, username):
        if self._connection is None:
            self.connect()

        results = self._connection.search_s(self._LDAP_DN, ldap.SCOPE_SUBTREE, settings.LDAP_UID_SEARCH_STRING.format(username), self._LDAP_FIELDS )
        return results

    def bind(self, username, password):
        try:
            if self._connection is None:
                self.connect()
            self._connection.simple_bind_s(settings.LDAP_BIND_DN.format(username), password)
            self._connection.unbind()
            self._connection = None
            return True
        except ldap.INVALID_CREDENTIALS as e:
            return False
