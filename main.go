package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-ldap/ldap"
	"gopkg.in/yaml.v2"
)

type (
	/*                    *
	 * CONFIGURATION DATA *
	 *                    */

	// LDAP server configuration
	LdapConfig struct {
		Host           string
		Port           uint16
		Tls            string
		TlsNoVerify    bool `yaml:"tls_skip_verify"`
		TlsAllowCnOnly bool `yaml:"tls_allow_cn_only"`
		CaChain        string
		BindUser       string   `yaml:"bind_user"`
		BindPassword   string   `yaml:"bind_password"`
		MemberFields   []string `yaml:"member_fields"`
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
)

// Load and check the configuration file
func loadConfiguration() (configuration Configuration) {
	var cfgFile string
	if len(os.Args) < 2 {
		cfgFile = "graylog-groups.yml"
	} else {
		cfgFile = os.Args[1]
	}
	cfgData, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		log.Fatalf("could not load configuration: %v", err)
	}

	configuration = Configuration{
		Ldap: LdapConfig{
			Port: 389,
			Tls:  "no",
		},
	}
	err = yaml.Unmarshal(cfgData, &configuration)
	if err != nil {
		log.Fatalf("could not parse configuration: %v", err)
	}

	for _, info := range configuration.Mapping {
		for _, priv := range info.Privileges {
			if !graylogItems[priv.Type] {
				log.Fatalf("invalid Graylog item %s", priv.Type)
			}
			if _, ok := privLevels[priv.Level]; !ok {
				log.Fatalf("invalid privilege level %s", priv.Level)
			}
		}
	}

	return
}

// Execute a Graylog API request, returning the status code and the body
func executeApiCall(cfg GraylogConfig, method string, path string, data io.Reader) (status int, body []byte) {
	client := &http.Client{}
	request, err := http.NewRequest(method, fmt.Sprintf("%s/%s", cfg.ApiBase, path), data)
	if err != nil {
		log.Fatalf("could not create HTTP request: %v", err)
	}
	request.SetBasicAuth(cfg.Username, cfg.Password)
	if data != nil {
		request.Header.Add("Content-Type", "application/json")
	}
	request.Header.Add("X-Requested-By", "graylog-groups")
	response, err := client.Do(request)
	if err != nil {
		log.Fatalf("could not execute %s %s request on Graylog at %s: %v", method, path, cfg.ApiBase, err)
	}
	defer response.Body.Close()
	status = response.StatusCode
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("could not read Graylog response: %v", err)
	}
	return
}

// Get the list of Graylog users that have been imported from LDAP
func getGraylogUsers(configuration GraylogConfig) (users []GraylogUser) {
	status, body := executeApiCall(configuration, "GET", "users", nil)
	if status != 200 {
		log.Fatalf("could not read users: status code %v", status)
	}

	data := GlUsers{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Fatalf("could not parse Graylog's user response: %v", err)
	}

	users = make([]GraylogUser, 0)
	for _, item := range data.Users {
		if item.External {
			users = append(users, item.GraylogUser)
		}
	}
	return
}

// Extract an username from something that may be an username or a DN.
func usernameFromMember(member string) string {
	eqPos := strings.Index(member, "=")
	if eqPos == -1 {
		return member
	}
	commaPos := strings.Index(member, ",")
	if commaPos == -1 {
		return member[eqPos+1:]
	}
	if eqPos > commaPos {
		log.Fatalf("couldn't extract user name from %s", member)
	}
	return member[eqPos+1 : commaPos]
}

// Establish a connection to the LDAP server
func getLdapConnection(cfg LdapConfig) (conn *ldap.Conn) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TlsNoVerify,
	}
	if cfg.Tls != "no" && cfg.CaChain != "" {
		data, err := ioutil.ReadFile(cfg.CaChain)
		if err != nil {
			log.Fatalf("failed to read CA certificate chain from %s", cfg.CaChain)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			log.Fatalf("could not add CA certificates from %s", cfg.CaChain)
		}
		tlsConfig.RootCAs = pool
	}

	var err error
	dest := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	if cfg.Tls == "yes" {
		conn, err = ldap.DialTLS("tcp", dest, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", dest)
	}
	if err != nil {
		log.Fatalf("failed to connect to LDAP server %s: %v", cfg.Host, err)
	}

	if cfg.Tls == "starttls" {
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			conn.Close()
			log.Fatalf("LDAP server %s, StartTLS failed: %v", cfg.Host, err)
		}
	}
	return
}

// Read the list of members from a LDAP group
func getGroupMembers(group string, conn *ldap.Conn, fields []string) (members []string) {
	req := ldap.NewSearchRequest(group, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", fields, nil)
	res, err := conn.Search(req)
	if err != nil {
		log.Fatalf("LDAP search for %s: %v", group, err)
	}

	for _, entry := range res.Entries {
		for _, attr := range fields {
			values := entry.GetAttributeValues(attr)
			if len(values) == 0 {
				continue
			}
			members = make([]string, len(values))
			for i, value := range values {
				members[i] = usernameFromMember(value)
			}
			break
		}
	}
	return
}

// Read the list of group members from the LDAP server for all groups in the mapping section.
func readLdapGroups(configuration Configuration) (groups GroupMembers) {
	conn := getLdapConnection(configuration.Ldap)
	defer conn.Close()

	if configuration.Ldap.BindUser != "" {
		err := conn.Bind(configuration.Ldap.BindUser, configuration.Ldap.BindPassword)
		if err != nil {
			log.Fatalf("LDAP server %s, could not bind: %v", configuration.Ldap.Host, err)
		}
	}

	groups = make(GroupMembers)
	for group := range configuration.Mapping {
		groups[group] = getGroupMembers(group, conn, configuration.Ldap.MemberFields)
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
	log.Printf("DELETING ACCOUNT %s", user)
	code, body := executeApiCall(cfg, "DELETE", fmt.Sprintf("/users/%s", user), nil)
	if code != 204 {
		log.Fatalf("could not delete user %s: code %d, body '%s'", user, code, string(body))
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

func main() {
	configuration := loadConfiguration()
	glUsers := getGraylogUsers(configuration.Graylog)
	groups := readLdapGroups(configuration)
	applyMapping(configuration, glUsers, groups)
}
