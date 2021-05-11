graylog-groups
===============

A program that controls Graylog roles and privileges over objects using LDAP
groups.

**Note** My apologies, this is my first actual program in Go, so it must be a
terrible example of worst practices. Sorry.

Why?
-----

The community edition of [Graylog](https://graylog.org) had the ability to use
LDAP group in order to control user access to the various objects (searches,
streams and dashboards).

In a somewhat ethically questionable move this capability was removed in version
4.0 and replaced with an enterprise-only feature called teams.

This program is meant to emulate the pre-4.0 LDAP group functionality.

How?
-----

This program is meant to be executed on a regular basis through e.g. `cron`. It
will read its configuration file, and from there :

* get the list of users on the Graylog side,
* read the list of members for all LDAP groups that have a mapping defined in
  the configuration file,
* compute the roles and object privileges to grant for each Graylog user,
* optionally delete users that no longer have any privileges according to the
  mapping and LDAP group membership,
* set the users' permissions on the various Graylog objects,
* add or remove Graylog roles from user accounts.

It should be noted that permissions set by this tool to not appear anywhere on
the Graylog 4 UI. They can be queried back using the API, using the
`/user/{login}` endpoint.

Installing
-----------

- Download and build the program :
```
git clone https://github.com/tseeker/graylog-groups
cd graylog-groups
go build
```
- Copy the resulting binary to whatever box will run it.
- Create a configuration file based in the example from
  `graylog-groups.yml.example`.
- Set up a cron job or whatever it is you use to schedule tasks to run the
  synchronization binary on a regular basis.

Usage
------

The program accepts the following command line arguments :

* `-h` / `--help`: displays usage information then exits.
* `-q` / `--quiet`: quiet mode. This will disable logging to `stderr`.
* `-c <file>` / `--config <file>`: specifies the configuration file. If this
  option is not present, the program will try to load a file named
  `graylog-groups.yml` from the current working directory.
* `-i <name>` / `--instance <name>`: specifies an instance name that will be
  added to logs as a field named `instance`.
* `-L <level>` / `--level <level>`: specifies the log level. It must be one of
  the following: `trace`, `debug`, `info` (the default), `warn`, `error`,
  `fatal`, `panic`.
* `-f <file>` / `--log-file <file>`: appends logs to the specified file.
* `-g <host>:<port>` / `--log-graylog <host>:<port>`: sends logs to the
  specified Graylog server using GELF over UDP.

To Do
------

* Add TLS options (skip checks / specify CA) for the Graylog API.
* Read object ownership using `grn_permissions` to preserve privileges on users'
  own objects
* Support granting ownership on objects
* Use goroutines ? Maybe.
* Custom log file/terminal output
