#             LDAP_SERVER = 'ldap://128.114.119.108:389',
#             LDAP_DN = 'ou=people,dc=ucsc,dc=edu',
#             LDAP_FIELDS = ['cn', 'uid', 'mail']
#
#             LDAP_SERVER = 'directory.soe.ucsc.edu',
#             LDAP_DN = 'ou=People,dc=soe,dc=ucsc,dc=edu',
#             LDAP_FIELDS = ['cn', 'uid', 'mail']

import ldap


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
        self._LDAP_SERVER = 'ldap://ldap-blue.prd.idm.aws.ucsc.edu:389'
        self._LDAP_DN = 'ou=people,dc=ucsc,dc=edu'
        self._LDAP_FIELDS = ['cn', 'uid', 'mail', 'ucscPersonPubAlternateMail', 'proxyAddress']

    def setSOEServer(self):
        self._LDAP_SERVER = 'ldap://directory.soe.ucsc.edu:389'
        self._LDAP_DN = 'ou=People,dc=soe,dc=ucsc,dc=edu'
        self._LDAP_FIELDS = ['cn', 'uid', 'mail', 'soeStatus']

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
