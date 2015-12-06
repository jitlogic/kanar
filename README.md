# kanar-core

Kanar is a non-reference CAS protocol implementation. Kanar is implemented as a framework and 
leiningen template rather than final server code as it needs to be customized anyway and some 
initial customization can be performed by template itself.

## Building from source

Kanar binaries are not (yet) available in clojars.org repository, so you need fetch to compile them manually:

```
cd /tmp
git clone https://github.com/jitlogic/kanar.git
cd kanar
for D in kanar-core kanar-ldap kanar-hazelcast lein-template ; do cd $D ; lein jar ; lein install ; cd .. ; done
```

This step will be obsolete as soon as first versions of kanar will be posted on clojars.


## Creating and compiling SSO server from template

In order to create new SSO server project, issue the following command:

```
$ cd /tmp
$ lein new kanar myserver
```

It will create simple SSO server source tree that will be configured to use local file as user database.

In order to use LDAP to authenticate, use `--with-ldapauth` option:

```
$ lein new kanar myserver -- --with-ldapauth
```

In order to use Hazelcast to have distributed ticket registry use `--with-hazelcast` option.

Created project can (and should) be modified and adjusted to individual needs, yet it can be compiled and
installed from get go:

```
$ cd myserver
$ lein uberjar
Compiling myserver.views
Compiling myserver.app
Created /tmp/myserver/target/myserver-0.1.0-SNAPSHOT.jar
Created /tmp/myserver/target/myserver-0.1.0-SNAPSHOT-standalone.jar
```

## Installing SSO server binary

Compiled server binary can be found in `target/` directory. Sample config files and startup scripts can
are located in `conf/` directory:

* `kanar.conf` - main configuration file;

* `services.conf` - services database;

* `users.conf` - users database;

* `kanar.sh` - sample startup script;

Additionally user can create `jvm.conf` script and place `JAVA_HOME` and `JAVA_OPTS` inside.

Create directory for server instance and copy appropriate files there:

```
$ mkdir /opt/kanar /opt/kanar/logs
$ cp /tmp/myserver/target/myserver-0.1.0-SNAPSHOT-standalone.jar /opt/kanar/kanar.jar
$ cp /tmp/myserver/conf/{kanar.sh,kanar.conf,services.conf,users.conf} /opt/kanar
```

Optionally, edit config files and create `jvm.conf` file:

```
$ echo "JAVA_HOME=/opt/jdk8" > /opt/kanar/jvm.conf
```

Start server:

```
$ cd /opt/kanar
$ ./kanar.sh start
```

Note that by default server listens on non-SSL port and TGC cookies require TLS. You need either to 
use TLS-terminating proxy or enable HTTPS in `kanar.conf`.

## Documentation

See [Kanar documentation](http://kanar.io/) for more information.

## License

Copyright © 2015 Rafal Lewczuk <rafal.lewczuk@jitlogic.com>

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
