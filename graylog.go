package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/sirupsen/logrus"
)

type (
	// A Graylog user and associated roles
	graylogUser struct {
		Username string
		Roles    []string
	}

	// The response obtained when querying the Graylog server for a list of users.
	graylogUsers struct {
		Users []struct {
			graylogUser
			External bool
		}
	}
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

// Execute a Graylog API request, returning the status code and the body
func executeAPICall(cfg graylogConfig, method string, path string, data io.Reader) (status int, body []byte) {
	log := log.WithFields(logrus.Fields{
		"base":     cfg.APIBase,
		"username": cfg.Username,
		"method":   method,
		"path":     path,
	})
	log.Trace("Executing Graylog API call")
	client := &http.Client{}
	request, err := http.NewRequest(method, fmt.Sprintf("%s/%s", cfg.APIBase, path), data)
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
func getGraylogUsers(configuration graylogConfig) (users []graylogUser) {
	log.Trace("Getting users from the Graylog API")
	status, body := executeAPICall(configuration, "GET", "users", nil)
	if status != 200 {
		log.WithField("status", status).Fatal("Could not read users")
	}

	data := graylogUsers{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.WithField("error", err).Fatal("Could not parse Graylog's user list")
	}

	users = make([]graylogUser, 0)
	for _, item := range data.Users {
		if item.External {
			users = append(users, item.graylogUser)
		}
	}
	log.WithField("users", len(users)).Info("Obtained users from the Graylog API")
	return
}

// List groups an user is a member of.
func getUserGroups(user string, membership ldapGroupMembers) (groups []string) {
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
func computeRoles(mapping groupMapping, membership []string) (roles []string) {
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
func computePrivileges(mapping groupMapping, membership []string) (privileges []string) {
	type privInfo struct {
		otp, oid string
		priv     int
	}
	rset := make(map[string]privInfo)
	for _, group := range membership {
		for _, priv := range mapping[group].Privileges {
			key := fmt.Sprintf("%s:%s", priv.Type, priv.ID)
			record, ok := rset[key]
			level := privLevels[priv.Level]
			if ok && level <= record.priv {
				continue
			}
			if !ok {
				record.otp = priv.Type
				record.oid = priv.ID
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
func deleteAccount(cfg graylogConfig, user string) {
	log := log.WithField("user", user)
	log.Warning("Deleting Graylog account")
	code, body := executeAPICall(cfg, "DELETE", fmt.Sprintf("/users/%s", user), nil)
	if code != 204 {
		log.WithFields(logrus.Fields{
			"status": code,
			"body":   string(body),
		}).Error("Could not delete user")
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
func setUserPrivileges(cfg graylogConfig, user graylogUser, roles []string, privileges []string) {
	log := log.WithField("user", user.Username)

	type perms struct {
		Permissions []string `json:"permissions"`
	}
	p := perms{Permissions: privileges}
	data, err := json.Marshal(p)
	if err != nil {
		log.WithField("error", err).Fatal("Unable to generate permissions JSON")
	}
	log.WithField("privileges", privileges).Info("Setting permissions")
	code, body := executeAPICall(cfg, "PUT",
		fmt.Sprintf("users/%s/permissions", user.Username),
		bytes.NewBuffer(data))
	if code != 204 {
		log.WithFields(logrus.Fields{
			"status": code,
			"body":   string(body),
		}).Error("Could not set permissions")
	}

	placeholder := bytes.NewBuffer([]byte("{}"))
	for _, role := range getDifference(roles, user.Roles) {
		ep := fmt.Sprintf("roles/%s/members/%s", role, user.Username)
		log.WithField("role", role).Info("Adding role")
		code, body := executeAPICall(cfg, "PUT", ep, placeholder)
		if code != 204 {
			log.WithFields(logrus.Fields{
				"status": code,
				"body":   string(body),
				"role":   role,
			}).Error("Could not add role")
		}
	}
	for _, role := range getDifference(user.Roles, roles) {
		ep := fmt.Sprintf("roles/%s/members/%s", role, user.Username)
		log.WithField("role", role).Info("Removing role")
		code, body := executeAPICall(cfg, "DELETE", ep, nil)
		if code != 204 {
			log.WithFields(logrus.Fields{
				"status": code,
				"body":   string(body),
				"role":   role,
			}).Error("Could not remove role")
		}
	}
}

// Apply privilege mappings to the external Graylog users
func applyMapping(cfg configuration, users []graylogUser, groups ldapGroupMembers) {
	for _, user := range users {
		log := log.WithField("user", user.Username)
		membership := getUserGroups(user.Username, groups)
		log.WithField("groups", membership).Trace("Computed group membership")
		roles := computeRoles(cfg.Mapping, membership)
		log.WithField("roles", roles).Trace("Computed roles")
		privileges := computePrivileges(cfg.Mapping, membership)
		log.WithField("privileges", privileges).Trace("Computed privileges")
		if cfg.Graylog.DeleteAccounts && len(roles) == 0 && len(privileges) == 0 {
			deleteAccount(cfg.Graylog, user.Username)
		} else {
			setUserPrivileges(cfg.Graylog, user, roles, privileges)
		}
	}
}
