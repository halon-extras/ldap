all: ldap

ldap:
	g++ -I../smtpd -I/opt/halon/include/ -I/usr/local/include/ -fPIC -shared ldap.cpp -lldap -o ldap.so
