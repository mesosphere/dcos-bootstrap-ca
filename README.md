# [DC/OS](https://docs.mesosphere.com/1.13/overview/what-is-dcos/) certificate bootstrap (dcos-bootstrap-ca)
This program is part of the DC/OS installation toolchain. Specifically,
`dcos-bootstrap-ca` provides PKI (Public Key Infrastructure) bootstrapping,
secure, automated certificate signing, and security artifact 
transcoding. **This program is not intended to be used outside of the
context of a DC/OS installation.**

## Standalone container

It is possible to build this project as a standalone container that can be
used for CI testing purposes without need to run DC/OS installer bootstrap
node.

To build a container run:

```sh
make standalone
```

To push a container run:

```sh
make standalone-push
```
