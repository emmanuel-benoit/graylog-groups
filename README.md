graylog-groups
===============

A program that controls Graylog roles and privileges over objects using LDAP
groups.

**Note** My apologies, this is my first actual program in Go, so it must be a
terrible example of worst practices. Sorry.

Why?
-----

The community edition of [Graylog](https://graylog.org) had the ability to use
LDAP group in order to control user access to the various objects (streams and
dashboards).

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

To Do
------

* Proper logging, work in progress:
  * Sending logs to... well, Graylog... through CLI switches.
* Document command line flags.
* Add TLS options (skip checks / specify CA) for the Graylog API.
* Read object ownership using `grn_permissions` to preserve privileges on users'
  own objects
* Support granting ownership on objects
* Use goroutines ? Maybe.
