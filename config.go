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
				log.WithField("level", priv.Level).
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
