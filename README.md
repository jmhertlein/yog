# Yog

## Overview

An opinionated docker-and-ssh-centric declarative system management tool.

`pip3 install yog`

Features:
* Like puppet or ansible but a lot smaller and focused on docker, files, and cron
* agentless - runs entirely on top of ssh
* entirely defers auth(z/n) to ssh and the remote system's user permissions

Command summary:

* `yog`: Applies configurations to hosts. e.g. `yog myhost.mytld` applies the config from `./domains/mytld/myhost.yml`.
* `yog-repo`: Manages a docker repository. `yog-repo push` uses the contents of `./yog-repo.conf` to build an image and push it to the configured registry with the configured name and tag.

## Usage

Yog uses YML files that it calls "necronomicons" for configuration of hosts. It's organized hierarchically so
that a necronomicon for "mytld" will be applied to all hosts under that TLD.

Let's learn by example:

Suppose we have a folder, that can be named whatever we want, at `~/projects/my-config`. This is the root of a 
git repo, and is also the root of our yog configuration. Make this your current working dir, or pass `--root-dir`.

`$ cd ~/projects/my-config`

```text
.
├── domains
│      ├── com
│      │      └── example
│      │          └── myhost.yml
│      └── com.yml
└── files
    ├── example.txt
    ├── hello_world.html
    └── helloworld-nginx.conf

4 directories, 5 files
```

Files that can be sent to hosts are stored under `files`.

Host configurations - necronomicons - are stored under `domains`.

If we want to apply `myhost.yml`, we run:

`yog myhost.example.com`

Example output:
```text
$ yog myhost.example.com
[2022-12-26 11:01:52,514] [INFO]: [myhost.example.com]
[2022-12-26 11:01:59,121] [INFO]: [myhost.example.com][files]: OK [hello_world.html]
[2022-12-26 11:01:59,274] [INFO]: [myhost.example.com][files]: OK [helloworld-nginx.conf]
[2022-12-26 11:02:07,117] [INFO]: [myhost.example.com][docker]: OK registry@sha256:8be26f81ffea54106bae012c6f349df70f4d5e7e2ec01b143c46e2c03b9e551d
```

### Necronomicon format

Let's look at a necronomicon.

```yml
files:
  - src: hello_world.html
    dest: /srv/hello_world/hello_world.html
    root: yes
  - src: helloworld-nginx.conf
    dest: /etc/nginx/conf.d/helloworld.conf
    root: yes
    hupcmd: sudo systemctl restart nginx


docker:
  - image: registry
    name: my-registry
    fingerprint: sha256:8be26f81ffea54106bae012c6f349df70f4d5e7e2ec01b143c46e2c03b9e551d
    volumes:
      images: /var/lib/registry
    ports:
      5000: 5000
    env:
      REGISTRY_STORAGE_DELETE_ENABLED: true
```

#### Files

Files are checked for equality via hash-comparison. I've found this a useful way to manage:

* cron files in /etc/cron.d/
* Root certificates to put in the system trust store[1]
* random config files

Attributes:

* `src`: the source. This is a _relative_ path rooted at the `files` directory in the hierarchy. You can use intermediate dirs.
* `dest`: the destination filepath on the managed host. This is an absolute path.
* `root`: whether to `sudo` to root for the file put. This mainly picks who owns the file + can access files, but this might have other useful properties for your use case. If set to `no`, the put operation is run as your ssh user. 
* `hupcmd`: a command to run after the file is placed. A common thing in ye olde days was to send SIGHUP to a process which would handle it by reloading the config. Commonly nowadays you might be using `hupcmd: sudo systemctl reload nginx`

[1] This is one of those things where I feel like you probably shouldn't manage root certs like this but I have yet to regret it? It's not a cryptographic secret, so.

#### Docker containers

Docker containers are compared on all specified attributes and won't unnecessarily restart containers. 

Attributes: 

* `image`: the docker repository name. e.g. `itzg/minecraft-server` or `dockerrepo.local:5000/mything`
* `name`: the container name.
* `fingerprint`: sha digest of the desired version. Tags are bad news bears so we don't support them. This is called fingerprint instead of digest because I didn't know they were called digests when I first coded this and then never changed it once I did.
* `volumes`: volumes to attach. see below.
* `ports`: ports to open. see below.
* `env`: environment variables to set.

##### Volumes

For volumes, the key is the volume name and the value is the mount point.

For bind mounts, the key is the host path and the value is the container path.

##### Ports

The key is the host addr/port, and the value is the dest container port. Examples:

```yml
192.168.1.103:53/tcp: 53/tcp
192.168.1.103:53/udp: 53/udp
127.0.0.1:53/tcp: 53/tcp
127.0.0.1:53/udp: 53/udp
33200: 33200
8080: 3000 # host port 8080 maps to container port 3000
```