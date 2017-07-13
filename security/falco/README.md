# Lab: Falco IDS

> **Difficulty**: Medium

> **Time**: Approximately 25 minutes

Sysdig Falco 

Sysdig Falco is an open source, behavioral activity monitor designed to detect anomalous activity. Suitable for deploying intrusion detection over any generic Linux host, it is particularly useful for Docker hosting nodes, since it supports container-specific context like **container.id** or **namespaces** for its rules. 

In this lab you will learn the basics of Sysdig Falco and how to use it with Docker to detect anomalous container behavior.

You will experiment with the following security warnings as part of this lab.

- [Container running a shell](#shell)
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

#Falco installation and configuration

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

And check that the module correctly loaded

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
     filename: ./falco_events.txt
   ```
If you have not already, clone the lab and `cd` into the lab's `examplefiles` directory.

   ```
   $ git clone https://github.com/docker/labs.git
   $ cd labs/security/falco/examplefiles
   ```



