package main

import (
	"flag"
	"github.com/sirupsen/logrus"
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
)

var (
	// The logging context.
	log *logrus.Entry
)

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
func toLogLevel(cliLevel string) logrus.Level {
	if cliLevel == "" {
		return logrus.InfoLevel
	}
	lvl, err := logrus.ParseLevel(cliLevel)
	if err == nil {
		return lvl
	}
	log.WithField("level", cliLevel).Warning("Invalid log level on command line")
	return logrus.InfoLevel
}

// Configure the logging library based on the various command line flags.
func configureLogging(flags cliFlags) {
	log = getLoggingContext(flags.instance)
	log.Logger.SetLevel(toLogLevel(flags.logLevel))
}

func main() {
	flags := parseCommandLine()
	configureLogging(flags)
	configuration := loadConfiguration(flags)
	glUsers := getGraylogUsers(configuration.Graylog)
	groups := readLdapGroups(configuration)
	applyMapping(configuration, glUsers, groups)
}
