Client for ClamAV Daemon
========================

Client for ClamAV Daemon, supporting TCP and unix domain sockets as transport.
Only requiring JDK 17+ as runtime.

Usage
-----

```java
// Initialize client with unix domain socket path or alternatively with
// host and port
ClamdClient client = new ClamdClient("/var/run/clamav/clamd.ctl");

// Scan data from stream
try (FileInputStream fis = new FileInputStream("<path_to_file>")) {
    System.out.println(client.scanStream(fis));
}

// Scan data from byte array
System.out.println(client.scanStream(data));
```

Testing
-------

The integation tests assume:

- that clamd is listening on port 3310 on host localhost
- that clamd is listening on unix domain socket `/tmp/clamd.ctl`
- that that clamd rejects streams with more than 5MB
- that the clamd log is written to `/tmp/clamd.log`

For local execution a docker container can be used. Both invocations are run
from the root of the checked out code.

Building the container:

```bash
docker buildx build --tag clamd-client-build src/test/docker
```

Running integration tests:

```bash
docker run \
    --user `id --user` \
    --volume .:/clamd-client \
    --volume $HOME/.m2:/home/ubuntu/.m2 \
    clamd-client-build \
    /clamd-client/src/test/docker/runtest.sh
```