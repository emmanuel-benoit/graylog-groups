package main

import (
	"io/ioutil"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type (
	/*                    *
	 * CONFIGURATION DATA *
	 *                    */

	// LDAP server configuration
	ldapConfig struct {
		Host         string   `yaml:"host"`
		Port         uint16   `yaml:"port"`
		TLS          string   `yaml:"tls"`
		TLSNoVerify  bool     `yaml:"tls_skip_verify"`
		CaChain      string   `yaml:"cachain"`
		BindUser     string   `yaml:"bind_user"`
		BindPassword string   `yaml:"bind_password"`
		MemberFields []string `yaml:"member_fields"`
		UsernameAttr string   `yaml:"username_attribute"`
	}

	// Graylog server configuration
	graylogConfig struct {
		APIBase        string `yaml:"api_base"`
		Username       string
		Password       string
		DeleteAccounts bool `yaml:"delete_accounts"`
	}

	// A Graylog object on which privileges are defined
	graylogObject struct {
		Type  string `yaml:"type"`
		ID    string `yaml:"id"`
		Level string `yaml:"level"`
	}

	// A mapping from a LDAP group to a set of privileges
	groupPrivileges struct {
		Roles      []string
		Privileges []graylogObject
	}

	// All group mappings
	groupMapping map[string]groupPrivileges

	// The whole configuration
	configuration struct {
		LDAP    ldapConfig
		Graylog graylogConfig
		Mapping groupMapping
	}
)

// Check group/privilege mapping configuration
func checkPrivMapping(cfg groupMapping, log *logrus.Entry) {
	for group, info := range cfg {
		log := log.WithField("group", group)
		for index, priv := range info.Privileges {
			log := log.WithField("entry", index)
			if !graylogItems[priv.Type] {
				log.WithField("item", priv.Type).
					Fatal("Invalid Graylog item")
			}
			if _, ok := privLevels[priv.Level]; !ok {
				log.WithField("level", priv.Level).
					Fatal("Invalid privilege level")
			}
		}
	}
}

// Load and check the configuration file
func loadConfiguration(flags cliFlags) (cfg configuration) {
	log := log.WithField("config", flags.cfgFile)
	log.Trace("Loading configuration")
	cfgData, err := ioutil.ReadFile(flags.cfgFile)
	if err != nil {
		log.WithField("error", err).Fatal("Could not load configuration")
	}

	cfg = configuration{
		LDAP: ldapConfig{
			Port: 389,
			TLS:  "no",
		},
	}
	err = yaml.Unmarshal(cfgData, &cfg)
	if err != nil {
		log.WithField("error", err).Fatal("Could not parse configuration")
	}

	checkPrivMapping(cfg.Mapping, log)
	return
}
