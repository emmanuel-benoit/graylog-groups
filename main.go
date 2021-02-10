package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-ldap/ldap"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type (
	// This structure contains all values that may be set from the command line.
	cliFlags struct {
		// The path to the configuration file.
		cfgFile string
		// The name of the instance, to be used in logs.
		instance string
		// The log level.
		logLevel string
	}

	// LDAP connection encapsulation, including a logger.
	ldapConn struct {
		conn *ldap.Conn
		log  *logrus.Entry
	}

	/*                    *
	 * CONFIGURATION DATA *
	 *                    */

	// LDAP server configuration
	LdapConfig struct {
		Host         string
		Port         uint16
		Tls          string
		TlsNoVerify  bool     `yaml:"tls_skip_verify"`
		CaChain      string   `yaml:"cachain"`
		BindUser     string   `yaml:"bind_user"`
		BindPassword string   `yaml:"bind_password"`
		MemberFields []string `yaml:"member_fields"`
		UsernameAttr string   `yaml:"username_attribute"`
	}

	// Graylog server configuration
	GraylogConfig struct {
		ApiBase        string `yaml:"api_base"`
		Username       string
		Password       string
		DeleteAccounts bool `yaml:"delete_accounts"`
	}

	// A Graylog object on which privileges are defined
	GraylogObject struct {
		Type  string
		Id    string
		Level string
	}

	// A mapping from a LDAP group to a set of privileges
	GroupPrivileges struct {
		Roles      []string
		Privileges []GraylogObject
	}

	// All group mappings
	GroupMapping map[string]GroupPrivileges

	// The whole configuration
	Configuration struct {
		Ldap    LdapConfig
		Graylog GraylogConfig
		Mapping GroupMapping
	}

	/*             *
	 * SERVER DATA *
	 *             */

	// A Graylog user
	GraylogUser struct {
		Username string
		Roles    []string
	}

	// The response obtained when querying the Graylog server for a list of users.
	GlUsers struct {
		Users []struct {
			GraylogUser
			External bool
		}
	}

	// LDAP group members
	GroupMembers map[string][]string
)

var (
	// Privilege levels
	privLevels = map[string]int{
		"read":  0,
		"write": 1,
	}
	// Privilege level string representation
	privStr = []string{"read", "write"}
	// Graylog items on which privileges may be set
	graylogItems = map[string]bool{
		"dashboard": true,
		"stream":    true,
	}
	// Grayog privilege string templates
	graylogPriv = map[string][]string{
		"dashboard:read":  {"dashboards:read:%s", "view:read:%s"},
		"dashboard:write": {"dashboards:read:%s", "dashboards:edit:%s", "view:read:%s", "view:edit:%s"},
		"stream:read":     {"streams:read:%s"},
		"stream:write":    {"streams:read:%s", "streams:edit:%s", "streams:changestate:%s"},
	}
	// The logging context.
	log *logrus.Entry
)

// Check group/privilege mapping configuration
func checkPrivMapping(cfg GroupMapping, log *logrus.Entry) {
	for group, info := range cfg {
		log := log.WithField("group", group)
		for index, priv := range info.Privileges {
			log := log.WithField("entry", index)
			if !graylogItems[priv.Type] {
				log.WithField("item", priv.Type).
					Fatal("Invalid Graylog item")
			}
			if _, ok := privLevels[priv.Level]; !ok {
				log.WithField("level", priv.Type).
					Fatal("Invalid privilege level")
			}
		}
	}
}

// Load and check the configuration file
func loadConfiguration(flags cliFlags) (configuration Configuration) {
	log := log.WithField("config", flags.cfgFile)
	log.Trace("Loading configuration")
	cfgData, err := ioutil.ReadFile(flags.cfgFile)
	if err != nil {
		log.WithField("error", err).Fatal("Could not load configuration")
	}

	configuration = Configuration{
		Ldap: LdapConfig{
			Port: 389,
			Tls:  "no",
		},
	}
	err = yaml.Unmarshal(cfgData, &configuration)
	if err != nil {
		log.WithField("error", err).Fatal("Could not parse configuration")
	}

	checkPrivMapping(configuration.Mapping, log)
	return
}

// Execute a Graylog API request, returning the status code and the body
func executeApiCall(cfg GraylogConfig, method string, path string, data io.Reader) (status int, body []byte) {
	log := log.WithFields(logrus.Fields{
		"base":     cfg.ApiBase,
		"username": cfg.Username,
		"method":   method,
		"path":     path,
	})
	log.Trace("Executing Graylog API call")
	client := &http.Client{}
	request, err := http.NewRequest(method, fmt.Sprintf("%s/%s", cfg.ApiBase, path), data)
	if err != nil {
		log.WithField("error", err).Fatal("Could not create HTTP request")
	}
	request.SetBasicAuth(cfg.Username, cfg.Password)
	if data != nil {
		request.Header.Add("Content-Type", "application/json")
	}
	request.Header.Add("X-Requested-By", "graylog-groups")
	response, err := client.Do(request)
	if err != nil {
		log.WithField("error", err).Fatal("Could not execute HTTP request")
	}
	defer response.Body.Close()
	status = response.StatusCode
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.WithField("error", err).Fatal("Could not read Graylog response")
	}
	log.WithField("status", status).Trace("Executed Graylog API call")
	return
}

// Get the list of Graylog users that have been imported from LDAP
func getGraylogUsers(configuration GraylogConfig) (users []GraylogUser) {
	log.Trace("Getting users from the Graylog API")
	status, body := executeApiCall(configuration, "GET", "users", nil)
	if status != 200 {
		log.WithField("status", status).Fatal("Could not read users")
	}

	data := GlUsers{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.WithField("error", err).Fatal("Could not parse Graylog's user list")
	}

	users = make([]GraylogUser, 0)
	for _, item := range data.Users {
		if item.External {
			users = append(users, item.GraylogUser)
		}
	}
	log.WithField("users", len(users)).Info("Obtained users from the Graylog API")
	return
}

// Establish a connection to the LDAP server
func getLdapConnection(cfg LdapConfig) (conn ldapConn) {
	dest := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	log := log.WithFields(logrus.Fields{
		"ldap_server": dest,
		"ldap_tls":    cfg.Tls,
	})
	log.Trace("Establishing LDAP connection")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TlsNoVerify,
	}
	if cfg.Tls != "no" && cfg.CaChain != "" {
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
	if cfg.Tls == "yes" {
		lc, err = ldap.DialTLS("tcp", dest, tlsConfig)
	} else {
		lc, err = ldap.Dial("tcp", dest)
	}
	conn = ldapConn{
		conn: lc,
		log:  log,
	}
	if err != nil {
		conn.log.WithField("error", err).Fatal("Failed to connect to the LDAP server")
	}

	if cfg.Tls == "starttls" {
		err = lc.StartTLS(tlsConfig)
		if err != nil {
			lc.Close()
			conn.log.WithField("error", err).Fatal("StartTLS failed")
		}
	}

	if cfg.BindUser != "" {
		conn.log = conn.log.WithField("ldap_user", cfg.BindUser)
		err := lc.Bind(cfg.BindUser, cfg.BindPassword)
		if err != nil {
			conn.close()
			conn.log.WithField("error", err).Fatal("Could not bind")
		}
	}
	log.Debug("LDAP connection established")
	return
}

// Run a LDAP query to obtain a single object.
func (conn ldapConn) query(dn string, attrs []string) (bool, *ldap.Entry) {
	log := conn.log.WithFields(logrus.Fields{
		"dn":         dn,
		"attributes": attrs,
	})
	log.Trace("Accessing DN")
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
func (conn ldapConn) close() {
	conn.log.Trace("Closing LDAP connection")
	conn.conn.Close()
}

// Read a username from a LDAP record based on a DN.
func readUsernameFromLdap(dn string, conn ldapConn, attr string) (bool, string) {
	log := conn.log.WithFields(logrus.Fields{
		"dn":        dn,
		"attribute": attr,
	})
	log.Trace("Converting DN to username")
	ok, res := conn.query(dn, []string{attr})
	if !ok {
		return false, ""
	}
	values := res.GetAttributeValues(attr)
	if len(values) != 1 {
		log.WithField("count", len(values)).
			Warning("Attribute does not have 1 value exactly.")
		return false, ""
	}
	log.WithField("username", values[0]).Trace("Mapped DN to username")
	return true, values[0]
}

// Extract an username from something that may be an username or a DN.
func usernameFromMember(member string, conn ldapConn, config LdapConfig) (bool, string) {
	eqPos := strings.Index(member, "=")
	if eqPos == -1 {
		return true, member
	}
	if config.UsernameAttr != "" {
		return readUsernameFromLdap(member, conn, config.UsernameAttr)
	}
	commaPos := strings.Index(member, ",")
	if commaPos == -1 {
		return true, member[eqPos+1:]
	}
	if eqPos > commaPos {
		log.Printf("couldn't extract user name from %s", member)
		return false, ""
	}
	return true, member[eqPos+1 : commaPos]
}

// Read the list of members from a LDAP group
func getGroupMembers(group string, conn ldapConn, config LdapConfig) (members []string) {
	log := conn.log.WithField("group", group)
	log.Trace("Obtaining group members")
	ok, entry := conn.query(group, config.MemberFields)
	if !ok {
		return
	}
	for _, attr := range config.MemberFields {
		values := entry.GetAttributeValues(attr)
		if len(values) == 0 {
			continue
		}
		for _, value := range values {
			ok, name := usernameFromMember(value, conn, config)
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
func readLdapGroups(configuration Configuration) (groups GroupMembers) {
	conn := getLdapConnection(configuration.Ldap)
	defer conn.close()

	groups = make(GroupMembers)
	for group := range configuration.Mapping {
		groups[group] = getGroupMembers(group, conn, configuration.Ldap)
	}
	return
}

// List groups an user is a member of.
func getUserGroups(user string, membership GroupMembers) (groups []string) {
	groups = make([]string, 0)
	for group, members := range membership {
		for _, member := range members {
			if member == user {
				groups = append(groups, group)
				break
			}
		}
	}
	return
}

// Compute roles that should apply to an user
func computeRoles(mapping GroupMapping, membership []string) (roles []string) {
	rset := make(map[string]bool)
	for _, group := range membership {
		for _, role := range mapping[group].Roles {
			rset[role] = true
		}
	}

	roles = make([]string, len(rset))
	i := 0
	for group := range rset {
		roles[i] = group
		i++
	}
	return
}

// Compute privileges on Graylog objects that should be granted to an user
func computePrivileges(mapping GroupMapping, membership []string) (privileges []string) {
	type privInfo struct {
		otp, oid string
		priv     int
	}
	rset := make(map[string]privInfo)
	for _, group := range membership {
		for _, priv := range mapping[group].Privileges {
			key := fmt.Sprintf("%s:%s", priv.Type, priv.Id)
			record, ok := rset[key]
			level := privLevels[priv.Level]
			if ok && level <= record.priv {
				continue
			}
			if !ok {
				record.otp = priv.Type
				record.oid = priv.Id
			}
			record.priv = level
			rset[key] = record
		}
	}

	privileges = make([]string, 0)
	for _, record := range rset {
		key := fmt.Sprintf("%s:%s", record.otp, privStr[record.priv])
		for _, p := range graylogPriv[key] {
			pval := fmt.Sprintf(p, record.oid)
			privileges = append(privileges, pval)
		}
	}
	return
}

// Delete a Graylog user account
func deleteAccount(cfg GraylogConfig, user string) {
	log := log.WithField("user", user)
	log.Warning("Deleting Graylog account")
	code, body := executeApiCall(cfg, "DELETE", fmt.Sprintf("/users/%s", user), nil)
	if code != 204 {
		log.WithFields(logrus.Fields{
			"status": code,
			"body":   string(body),
		}).Fatal("Could not delete user")
	}
}

// Returns the strings that are in a but not in b.
func getDifference(a []string, b []string) (diff []string) {
	diff = make([]string, 0)
	for _, sa := range a {
		found := false
		for _, sb := range b {
			if sa == sb {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, sa)
		}
	}
	return
}

// Set an account's roles and grant it access to Graylog objects
func setUserPrivileges(cfg GraylogConfig, user GraylogUser, roles []string, privileges []string) {
	type perms struct {
		Permissions []string `json:"permissions"`
	}
	p := perms{Permissions: privileges}
	data, err := json.Marshal(p)
	if err != nil {
		log.Fatalf("unable to generate permissions JSON for %s: %v", user, err)
	}

	code, body := executeApiCall(cfg, "PUT", fmt.Sprintf("users/%s/permissions", user.Username), bytes.NewBuffer(data))
	if code != 204 {
		log.Fatalf("could not set permissions for %s: code %d, body '%s'", user.Username, code, string(body))
	}

	placeholder := bytes.NewBuffer([]byte("{}"))
	for _, role := range getDifference(roles, user.Roles) {
		ep := fmt.Sprintf("roles/%s/members/%s", role, user.Username)
		code, body := executeApiCall(cfg, "PUT", ep, placeholder)
		if code != 204 {
			log.Fatalf("could not add role %s to %s: code %d, body '%s'", role, user.Username, code, string(body))
		}
	}
	for _, role := range getDifference(user.Roles, roles) {
		ep := fmt.Sprintf("roles/%s/members/%s", role, user.Username)
		code, body := executeApiCall(cfg, "DELETE", ep, nil)
		if code != 204 {
			log.Fatalf("could not remove role %s from %s: code %d, body '%s'", role, user.Username, code, string(body))
		}
	}
}

// Apply privilege mappings to the external Graylog users
func applyMapping(cfg Configuration, users []GraylogUser, groups GroupMembers) {
	for _, user := range users {
		membership := getUserGroups(user.Username, groups)
		roles := computeRoles(cfg.Mapping, membership)
		privileges := computePrivileges(cfg.Mapping, membership)
		if cfg.Graylog.DeleteAccounts && len(roles) == 0 && len(privileges) == 0 {
			deleteAccount(cfg.Graylog, user.Username)
		} else {
			setUserPrivileges(cfg.Graylog, user, roles, privileges)
		}
	}
}

// Parse command line options.
func parseCommandLine() cliFlags {
	flags := cliFlags{}
	flag.StringVar(&flags.cfgFile, "c", "graylog-groups.yml", "Configuration file.")
	flag.StringVar(&flags.instance, "i", "", "Instance identifier.")
	flag.StringVar(&flags.logLevel, "L", "", "Log level for the logrus library.")
	flag.Parse()
	return flags
}

// Initialize the logging context.
func getLoggingContext(instance string) *logrus.Entry {
	logFields := logrus.Fields{
		"application": "graylog",
		"component":   "graylog-groups",
	}
	if instance != "" {
		logFields["instance"] = instance
	}
	return logrus.WithFields(logFields)
}

// Configure the log level
func configureLogLevel(cliLevel string) {
	var lvl logrus.Level
	if cliLevel == "" {
		lvl = logrus.InfoLevel
	} else {
		var err error
		lvl, err = logrus.ParseLevel(cliLevel)
		if err != nil {
			log.WithFields(logrus.Fields{
				"level": cliLevel,
			}).Warning("Invalid log level on command line")
			lvl = logrus.InfoLevel
		}
	}
	log.Logger.SetLevel(lvl)
}

// Configure the logging library based on the various command line flags.
func configureLogging(flags cliFlags) {
	log = getLoggingContext(flags.instance)
	configureLogLevel(flags.logLevel)
}

func main() {
	flags := parseCommandLine()
	configureLogging(flags)
	log.Debug("Starting synchronization")
	configuration := loadConfiguration(flags)
	glUsers := getGraylogUsers(configuration.Graylog)
	groups := readLdapGroups(configuration)
	applyMapping(configuration, glUsers, groups)
}
