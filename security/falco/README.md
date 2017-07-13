# Lab: Falco IDS

> **Difficulty**: Medium

> **Time**: Approximately 40 minutes

Sysdig Falco is an open source, behavioral activity monitor designed to detect anomalous activity. Suitable for deploying intrusion detection over any generic Linux host, it is particularly useful for Docker hosting nodes, since it supports container-specific context like **container.id** or **namespaces** for its rules. 

In this lab you will learn the basics of Sysdig Falco and how to use it with Docker to detect anomalous container behavior.

You will experiment with the following security threats as part of this lab.

- [Container running an interactive shell](#shell)
- [Unauthorized process](#process)
- [Unauthorized port open](#port)
- [Unauthorized remote host connection](#remote)
- [Write to non user-data directory](#write)
- [Running system administration binaries](#sysadm)
- [Process tries to access unauthorized device](#device)

You will play both the attacker and defender (sysadmin) roles, verifying that the intrusion attempt has
been detected by Sysdig Falco.

# Prerequisites

You will need all of the following to complete this lab:

- A Linux-based Docker Host.
- Some disposable containers to simulate the attacks.

To generate this lab `Ubuntu 16.04.2 LTS` and `Docker 17.06.0-ce` were used. Any current version of the Linux kernel
and Docker should suffice.

# Falco installation and configuration

Sysdig Falco can be installed as a regular package from the repositories of popular distributions like Ubuntu or RHEL, but
there is also a convenient scripted install:

   ```
   $ curl -s https://s3.amazonaws.com/download.draios.com/stable/install-falco | sudo bash
   Detecting operating system
   Detecting operating system
   Installing Sysdig public key
   OK
   Installing falco repository
   Installing kernel headers
   Installing falco

   ...
   

   falco-probe:
   Running module version sanity check.
    - Original module
      - No original module exists within this kernel
    - Installation
      - Installing to /lib/modules/4.4.0-83-generic/updates/dkms/

   depmod....

   DKMS: install completed.
   ```
   
You have probably noticed that the installer will pull the kernel headers, build and install a kernel module. This module is in charge of collecting Linux syscalls and other low-level events to the user-level tool, using this mechanism you don't need to modify or instrument the monitorized containers in any way.

Start the falco service

   ```
   # systemctl start falco
   ```

And check that the module is correctly loaded

   ```
   # lsmod | grep falco

     falco_probe           442368  1
   ```

There are also two configuration files that you will need to modify: `/etc/falco.yaml` and `/etc/falco_rules.yaml`.
As you can guess, *falco.yaml* covers the daemon configuration and *falco_rules.yaml* the threat detection patters.

By default, Falco only logs to *syslog*, let's edit it to enable file output, this way the exercises will be easier to follow.


Edit the *falco.yaml* file and modify the `file_output` section:
   ```
   file_output:
     enabled: true
     filename: /var/log/falco_events.txt
   ```
If you have not already, clone the lab and `cd` into the lab's `examplefiles` directory.

   ```
   $ git clone https://github.com/docker/labs.git
   $ cd labs/security/falco/examplefiles
   ```

There you will find the complete `falco.yaml` file and a (solution) `falco_rules.yaml` file.

Reload the Falco daemon every time that you change the configuration files

   ```
   # systemctl restart falco
   ```

# <a name="shell"></a> Container running an interactive shell

Let's start with an easy one, detecting an attacker running an interactive shell in any of our containers. This alert is included
in the default rule set. Let's trigger it first and then you can dissect the rule itself.

Run any container on your Docker host, for example `nginx`:
   ```
   # docker run -d -P --name example1 nginx
 
   # docker ps
   CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                   NAMES
   604aa46610dd        nginx               "nginx -g 'daemon ..."   2 minutes ago       Up 2 minutes        0.0.0.0:32771->80/tcp   example1
   ```

Now spawn an interactive shell 

   ```
   # docker exec -it example1 bash
   ```

Tailing the `/var/log/falco_events.txt` you will be able to read:

   ```
   17:13:24.357351845: Notice A shell was spawned in a container with an attached terminal (user=root example1 (id=604aa46610dd) shell=bash parent=<NA> cmdline=bash  terminal=34816)
   ```

This is the specific `/etc/falco_rules.yaml` rule that fired

   ```
   - rule: Terminal shell in container
     desc: A shell was spawned by a program in a container with an attached terminal.
     condition: >
       spawned_process and container
       and shell_procs and proc.tty != 0
     output: "A shell was spawned in a container with an attached terminal (user=%user.name %container.info shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty)"
     priority: NOTICE
     tags: [container, shell]
   ```

This is a rather complex rule, don't worry if you don't fully understand it at this moment.

Notice that you can define and use macros to make your rules more readable and powerful. For example the `and container` condition above corresponds to the macro

   ```
   - macro: container
     condition: container.id != host
   ```

This is, any container id that doesn't match the hosting node (any actual container).

You can also classify different threat priorities [DEBUG, INFO, NOTICE, WARNING, ERROR...]

Note as well that the output can be completed with the context variables provided by Falco like `%proc.name` or `%container.info`.

For the next exercise, you will create your own custom rule from scratch.

# <a name="process"></a> Unauthorized process

Docker and microservices design patterns instruct us to minimize the number of processes per container. Apart from the architectural benefits, this
could be a huge advantage to security, because it restricts what should and should not be running on a particular container. 

You know that your `nginx`containers should only be executing the `nginx` process (or a reduced set of processes in more realistic scenarios). Anything else
should rise an alarm.

Let's write the following rule into `/etc/falco_rules.yaml`

   ```
   #Our nginx containers for example1 should only be running the 'nginx' process
   - rule: Unauthorized process on nginx containers
     desc: There is a process in our nginx container that is not described in the template
     condition: spawned_process and container and container.image startswith nginx and `
     output: Unauthorized process (%proc.cmdline) running in (%container.id)
     priority: WARNING
   ```

You have the `rule` name and `desc` for the human reader.
The firing condition requires:
 - `spawned_process` (default macro) 
 - `container` (you don't want to fire this for the host)
 - `container.image startswith nginx` (so you can have separate authorized process lists for separate containers) 
 - `not proc.name in (nginx)` (you can write a comma separated list with the expected processes)

You already know how `output` and `priority` works.

Again, restart Falco, create the nginx container.

   ```
   # systemctl restart falco
   # docker run -d -P --name example2 nginx
   ```

spawn a shell in the `example2` container and just run anything like `ls`

Tailing the `/var/log/falco_events.txt` you will be able to read:

   ```
   18:38:36.911250971: Notice A shell was spawned in a container with an attached terminal (user=root example1 (id=604aa46610dd) shell=bash parent=<NA> cmdline=bash  terminal=34816)
   18:38:43.364877988: Warning Unauthorized process (ls ) running in (604aa46610dd)
   ```

Success! The first notice entry, you were already expecting by the rule in the exercise above, second entry shows that Falco has recognized an alien process and is firing a warning.


procps
kill -s HUP `cat /var/run/nginx.pid`

# Conclusions & Further reading

Output to program, notification



