## Yog

An opinionated docker-and-ssh-centric declarative system management tool.

Some features:
* Like puppet or ansible but a lot smaller and focused on docker.
* "agentless" in the same sense that ansible is, in that it (ab)uses ssh to do lots of its functionality.
* (ab)uses ssh as a poor-person's Envoy - it prefers to tunnel traffic over ssh even if it could otherwise just hit the port directly.