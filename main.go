package main

import (
	"io/ioutil"
	"os"

	lrh_gl "github.com/gemnasium/logrus-graylog-hook/v3"
	"github.com/karrick/golf"
	"github.com/sirupsen/logrus"
	lrh_wr "github.com/sirupsen/logrus/hooks/writer"
)

type (
	// This structure contains all values that may be set from the command line.
	cliFlags struct {
		// The path to the configuration file.
		cfgFile string
		// The name of the instance, to be used in logs.
		instance string
		// Quiet mode. Will disable logging to stderr.
		quiet bool
		// The log level.
		logLevel string
		// A file to write logs into.
		logFile string
		// Graylog server to send logs to (using GELF/UDP). Format is <hostname>:<port>.
		logGraylog string
	}
)

var (
	// The logging context.
	log *logrus.Entry
)

// Parse command line options.
func parseCommandLine() cliFlags {
	var help bool
	flags := cliFlags{}

	golf.StringVarP(&flags.cfgFile, 'c', "config", "./graylog-groups.yml", "Set the configuration file.")
	golf.StringVarP(&flags.logFile, 'f', "log-file", "", "Log file.")
	golf.StringVarP(&flags.logGraylog, 'g', "log-graylog", "", "Log to Graylog server (format: <host>:<port>).")
	golf.BoolVarP(&help, 'h', "help", false, "Display command line help and exit.")
	golf.StringVarP(&flags.instance, 'i', "instance", "", "Specify an instance identifier.")
	golf.StringVarP(&flags.logLevel, 'L', "log-level", "info", "Log level to use.")
	golf.BoolVarP(&flags.quiet, 'q', "quiet", false, "Quiet mode; prevents logging to stderr.")

	golf.Parse()
	if help {
		golf.Usage()
		os.Exit(0)
	}
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

// Add a file writer hook to the logging library.
func configureLogFile(path string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.Logger.AddHook(&lrh_wr.Hook{
			Writer:    file,
			LogLevels: logrus.AllLevels,
		})
	} else {
		log.WithFields(logrus.Fields{
			"error": err,
			"file":  path,
		}).Error("Could not open log file")
	}
}

// Configure the logging library based on the various command line flags.
func configureLogging(flags cliFlags) {
	log = getLoggingContext(flags.instance)
	log.Logger.SetFormatter(&logrus.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	log.Logger.SetLevel(toLogLevel(flags.logLevel))
	if flags.logFile != "" {
		configureLogFile(flags.logFile)
	}
	if flags.logGraylog != "" {
		log.Logger.AddHook(lrh_gl.NewGraylogHook(flags.logGraylog, nil))
	}
	if flags.quiet {
		log.Logger.SetOutput(ioutil.Discard)
	}
}

func main() {
	flags := parseCommandLine()
	configureLogging(flags)
	configuration := loadConfiguration(flags)
	glUsers := getGraylogUsers(configuration.Graylog)
	groups := readLdapGroups(configuration)
	applyMapping(configuration, glUsers, groups)
}
