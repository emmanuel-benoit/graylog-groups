package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

type (
	// LDAP connection encapsulation. This includes the connection itself, as well as a logger
	// that includes fields related to the LDAP server and a copy of the initial configuration.
	ldapConn struct {
		conn      *ldap.Conn
		log       *logrus.Entry
		cfg       ldapConfig
		usernames map[string]string
		counter   uint
	}

	// LDAP group members
	ldapGroupMembers map[string][]string
)

// Establish a connection to the LDAP server
func getLdapConnection(cfg ldapConfig) *ldapConn {
	dest := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	log := log.WithFields(logrus.Fields{
		"ldap_server": dest,
		"ldap_tls":    cfg.TLS,
	})
	log.Trace("Establishing LDAP connection")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSNoVerify,
	}
	if cfg.TLS != "no" && cfg.CaChain != "" {
		log := log.WithField("cachain", cfg.CaChain)
		data, err := ioutil.ReadFile(cfg.CaChain)
		if err != nil {
			log.WithField("error", err).Fatal("Failed to read CA certificate chain")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			log.Fatal("Could not add CA certificates")
		}
		tlsConfig.RootCAs = pool
	}

	var err error
	var lc *ldap.Conn
	if cfg.TLS == "yes" {
		lc, err = ldap.DialTLS("tcp", dest, tlsConfig)
	} else {
		lc, err = ldap.Dial("tcp", dest)
	}
	if err != nil {
		log.WithField("error", err).Fatal("Failed to connect to the LDAP server")
	}

	if cfg.TLS == "starttls" {
		err = lc.StartTLS(tlsConfig)
		if err != nil {
			lc.Close()
			log.WithField("error", err).Fatal("StartTLS failed")
		}
	}

	if cfg.BindUser != "" {
		log = log.WithField("ldap_user", cfg.BindUser)
		err := lc.Bind(cfg.BindUser, cfg.BindPassword)
		if err != nil {
			lc.Close()
			log.WithField("error", err).Fatal("Could not bind")
		}
	}
	log.Debug("LDAP connection established")
	return &ldapConn{
		conn:      lc,
		log:       log,
		cfg:       cfg,
		usernames: make(map[string]string),
	}
}

// Run a LDAP query to obtain a single object.
func (conn *ldapConn) query(dn string, attrs []string) (bool, *ldap.Entry) {
	log := conn.log.WithFields(logrus.Fields{
		"dn":         dn,
		"attributes": attrs,
	})
	log.Trace("Accessing DN")
	conn.counter++
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", attrs, nil)
	res, err := conn.conn.Search(req)
	if err != nil {
		ldapError, ok := err.(*ldap.Error)
		if ok && ldapError.ResultCode == ldap.LDAPResultNoSuchObject {
			log.Trace("DN not found")
			return false, nil
		}
		log.WithField("error", err).Fatal("LDAP query failed")
	}
	if len(res.Entries) > 1 {
		log.WithField("results", len(res.Entries)).
			Warning("LDAP search returned more than 1 record")
		return false, nil
	}
	log.Trace("Obtained LDAP object")
	return true, res.Entries[0]
}

// Close a LDAP connection
func (conn *ldapConn) close() {
	conn.log.WithField("queries", conn.counter).Debug("Closing LDAP connection")
	conn.conn.Close()
}

// Read a username from a LDAP record based on a DN.
func (conn *ldapConn) readUsername(dn string) (bool, string) {
	log := conn.log.WithField("dn", dn)
	log.Debug("LDAP username lookup")
	ok, res := conn.query(dn, []string{conn.cfg.UsernameAttr})
	if !ok {
		return false, ""
	}
	values := res.GetAttributeValues(conn.cfg.UsernameAttr)
	if len(values) != 1 {
		log.WithField("count", len(values)).
			Warning("Attribute does not have 1 value exactly.")
		return false, ""
	}
	log.WithField("username", values[0]).Trace("Mapped DN to username")
	return true, values[0]
}

// Extract an username from something that may be an username or a DN.
func (conn *ldapConn) usernameFromMember(member string) (bool, string) {
	eqPos := strings.Index(member, "=")
	if eqPos == -1 {
		return true, member
	}
	if conn.cfg.UsernameAttr != "" {
		return conn.readUsername(member)
	}
	commaPos := strings.Index(member, ",")
	if commaPos == -1 {
		return true, member[eqPos+1:]
	}
	if eqPos > commaPos {
		log.WithField("member", member).Warning("Couldn't extract user name")
		return false, ""
	}
	return true, member[eqPos+1 : commaPos]
}

// Read a username from the cache. If the username is not cached, extract it or request it from
// the LDAP.
func (conn *ldapConn) getUsername(member string) (bool, string) {
	name, ok := conn.usernames[member]
	if ok {
		return true, name
	}
	ok, name = conn.usernameFromMember(member)
	if ok {
		conn.usernames[member] = name
	}
	return ok, name
}

// Read the list of members from a LDAP group
func (conn *ldapConn) getGroupMembers(group string) (members []string) {
	log := conn.log.WithField("group", group)
	log.Trace("Obtaining group members")
	ok, entry := conn.query(group, conn.cfg.MemberFields)
	if !ok {
		return
	}
	for _, attr := range conn.cfg.MemberFields {
		values := entry.GetAttributeValues(attr)
		if len(values) == 0 {
			continue
		}
		for _, value := range values {
			ok, name := conn.getUsername(value)
			if ok {
				members = append(members, name)
			}
		}
		break
	}
	log.WithField("members", members).Info("Obtained group members")
	return
}

// Read the list of group members from the LDAP server for all groups in the mapping section.
func readLdapGroups(cfg configuration) ldapGroupMembers {
	conn := getLdapConnection(cfg.LDAP)
	defer conn.close()
	groups := make(ldapGroupMembers)
	for group := range cfg.Mapping {
		groups[group] = conn.getGroupMembers(group)
	}
	return groups
}
