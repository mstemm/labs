# Lab: Falco IDS

> **Difficulty**: Medium

> **Time**: Approximately 40 minutes

Sysdig Falco is an open source, behavioral monitor designed to detect anomalous activity. Suitable for deploying intrusion detection targeting any generic Linux host, it is particularly useful for Docker hosting nodes since it supports container-specific context like **container.id** or **namespaces** for its rules. 

In this lab you will learn the basics of Sysdig Falco and how to use it along with Docker to detect anomalous container behavior.

You will simulate the following security threats as part of this lab:

- [Container running an interactive shell](#shell)
- [Unauthorized process](#process)
- [Unauthorized port open](#port)
- [Write to non user-data directory](#write)
- [Process attempts to read sensitive information after startup](#sensitive)


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
   
You have probably noticed that the installer will pull the kernel headers, build and install a kernel module. This module is in charge of collecting Linux syscalls and other low-level events that will be exposed to the user-level tool, using this mechanism you don't need to modify or instrument the monitored containers in any way.

Other option is to install Falco as a container itself!

   ```
   docker pull sysdig/falco
   docker run -i -t --name falco --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro sysdig/falco
   ```

This privileged container will build and inject the kernel module, assuming that Linux kernel headers are installed and available under `lib/modules`.
If you choose the scripted install, the Falco configuration and service reloads will be executed from the Docker host, if you prefer the Docker container method, you will need to login and launch from there.

Start the Falco service

   ```
   # systemctl start falco
   ```

And check that the module is correctly loaded

   ```
   # lsmod | grep falco

     falco_probe           442368  1
   ```

There are also two configuration files that you will need to modify: `/etc/falco.yaml` and `/etc/falco_rules.yaml`.
As you can guess, *falco.yaml* covers the daemon configuration and *falco_rules.yaml* the threat detection patterns.

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

Reload the Falco daemon every time that you modify the configuration files

   ```
   # systemctl restart falco
   ```

# <a name="shell"></a> Container running an interactive shell

Let's start with an easy one, detecting an attacker running an interactive shell in any of your containers. This alert is included
in the default rule set. Let's trigger it first and then you can study the rule itself.

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

Tailing the `/var/log/falco_events.txt` file you will be able to read:

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

This is a rather complex rule, don't worry if you don't fully understand every section at this moment.

Notice that you can define and use macros to make your rules more readable and powerful. For example the `and container` condition above corresponds to the macro

   ```
   - macro: container
     condition: container.id != host
   ```

This is, any container id that doesn't match the hosting node (any actual container).

You can also classify different threat priorities [DEBUG, INFO, NOTICE, WARNING, ERROR...]

Note as well that the output message will be much more useful including the context variables provided by Falco like `%proc.name` or `%container.info`.

For the next exercise, you will create your own custom rule from scratch.

# <a name="process"></a> Unauthorized process

Docker and microservices design patterns recommend minimizing the number of processes per container. Apart from the architectural benefits, this
could be a huge advantage to security, because it completely restricts what should and should not be running on a particular container. 

You know that your `nginx`containers should only be executing the `nginx` process (or a reduced set of processes in more complex scenarios). Anything else
should fire an alarm.

Let's write the following rule into `/etc/falco_rules.yaml`

   ```
   #Our nginx containers for example1 should only be running the 'nginx' process
   - rule: Unauthorized process on nginx containers
     desc: There is a process running in the nginx container that is not described in the template
     condition: spawned_process and container and container.image startswith nginx and not proc.name in (nginx)
     output: Unauthorized process (%proc.cmdline) running in (%container.id)
     priority: WARNING
   ```

You need to provide the `rule` name and `desc` entries for the human reader.
The firing condition requires:
 - `spawned_process` (default macro) 
 - `container` (you don't want to fire this for the host)
 - `container.image startswith nginx` (so you can have separate authorized process lists for each container image) 
 - `not proc.name in (nginx)` (you can write a comma separated list with the expected processes)

You already know how `output` and `priority` works.

Again, restart Falco and create the nginx container.

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

Success! The first notice entry, you were already expecting by the rule in the exercise above, second entry shows that Falco has recognized an unexpected process and is firing a warning.

You should probably comment out this rule before proceeding to the next exercises to get a cleaner output.

# <a name="port"></a> Unauthorized port

Similar to the previous exercise, if your container is opening a port that does not correlate to its service template, that's probably
something that should be checked.

this time, you can create a macro that contains your expected port numbers, so the rules you create later are shorter and easier to read:

   ```
   - macro: nginx_ports
     condition: fd.sport=80 or fd.sport=443 or fd.sport=8080

   ```

Now, write a rule that uses the macro

   ```
   - rule: Unauthorized port
     desc: Unauthorized port open on nginx container
     condition: inbound and container and container.image startswith nginx and not nginx_ports
     output: Unauthorized port (%fd.name) running in (%container.info)
     priority: WARNING
   ```

Let's reload Falco and create a disposable nginx container

   ```
   # systemctl restart falco
   # docker run -d -P --name example3 nginx
   ```

By default, the container exposes port 80, so you should receive no warning.

You can now spawn a shell into the container and install a text editor (remember to comment out the rule in example2 or this will generate a lot of noise).

   ```
   # docker exec -it example3 bash
   # apt update
   # apt install vim   # or your favorite text editor
   ```

Edit the nginx configuration file

   ```
   # vim /etc/nginx/conf.d/default.conf
   
   ```

you will see the directive `listen 80`, change it to a non authorized port, `listen 85` for example. Save the file and exit.

Reload the nginx service

   ```
   # service nginx reload
   ```

If you tail the `/var/log/falco_events.txt` you will see two interesting entries:

   ```
   19:50:33.663139720: Error File below /etc opened for writing (user=root command=vim /etc/nginx/conf.d/default.conf file=/etc/nginx/conf.d/default.conf)
   19:50:51.031989661: Warning Unauthorized port (0.0.0.0:85) running in (example3 (id=6227a98c2d0b))
   ```

First one corresponds to a default Falco rule, usually you don't want a process to write in `/etc/`, second one is the custom rule you just created.


# <a name="write"></a> Write to non user-data directory

One of the key concepts using Docker is "immutability", usually, running containers are not supposed to be updated and the user data directories are
perfectly delimited. Let's use this design principle as a security indicator.

First, let's define a macro with the write-allowed directories:

   ```
   - macro: user_data_dir
     condition: evt.arg[1] startswith /userdata or evt.arg[1] startswith /var/log/nginx
   ```

You may want to include `/var/log/nginx` to avoid firing an alarm when nginx updates its logs.

And the rule for this exercise:

   ```
   - rule: Write to non user_data dir
     desc: attempt to write to directories that should be immutable
     condition: open_write and container and not user_data_dir
     output: "Writing to non user_data dir (user=%user.name command=%proc.cmdline file=%fd.name)"
     priority: ERROR

   ```

Let's take a look at the `open_write` macro:

   ```
   - macro: open_write
   condition: (evt.type=open or evt.type=openat) and evt.is_open_write=true and fd.typechar='f'
   ```

Just as a reminder that at its core, Falco performs a live capture of system calls like `open` or `openat`.

Now, you can spawn a new container and try this rule:

   ```
   # systemctl restart falco
   # docker run -d -P --name example4 nginx
   # docker exec -it example4 bash
   # mkdir /userdata
   # touch /userdata/foo   # Shouldn't trigger this rule
   # touch /usr/foo 
   ```

Again, two relevant log lines:

   ```
   21:15:01.998703651: Error Writing to non user_data dir (user=root command=bash  file=/dev/tty)
   21:15:58.476945006: Error Writing to non user_data dir (user=root command=touch /usr/foo file=/usr/foo)
   ```

Your shell wrote to `/dev/tty`, and the non allowed file write to `/usr`.

# <a name="sensitive"></a> Process attempts to read sensitive information after startup

This is a rule already included in the default rule set, you will just adjust it to your use case.

This is the original rule

   ```
   - rule: Read sensitive file trusted after startup
     desc: an attempt to read any sensitive file (e.g. files containing user/password/authentication information) by a trusted program after startup. Trusted programs might read these files at startup to load initial state, but not afterwards.
     condition: sensitive_files and open_read and server_procs and not proc_is_new and proc.name!="sshd"
     output: "Sensitive file opened for reading by trusted program after startup (user=%user.name command=%proc.cmdline file=%fd.name)"
     priority: WARNING
    tags: [filesystem]
   ```

You haven't used the `tags` key before on your custom rules. Using tags you can
arbitrarily group sets of rules and run Falco with the `-T <tag>` to disable a set
of rules, or `-t <tag>` to *only* run the rules from the selected tag.

Let's focus on two of the macros from the former rule

`sensitive_files`

   ```
   - macro: sensitive_files
     condition: fd.name startswith /etc and (fd.name in (/etc/shadow, /etc/sudoers, /etc/pam.conf) or fd.directory in (/etc/sudoers.d, /etc/pam.d)) 
   ```

These are the files or directories that you consider sensitive. You can add

   ```
   or fd.name startswith /dev
   ```
   
In case the malicious software / users try to read from raw devices.

`server_procs`

   ```
   - macro: server_procs
    condition: proc.name in (http_server_binaries, db_server_binaries, docker_binaries, sshd)
   ```

These are the binaries considered safe that should always be allowed to read sensitive files and directories. Note that
you can include macros to define new macros.

You can now reload Falco and create a new disposable nginx container

   ```
   # systemctl restart falco
   # docker run -d -P --name example5 nginx
   # docker exec -it example5 bash
   # cat /etc/shadow
   ```

Checking the log, you can read the lines

   ```
   21:41:32.181638659: Warning Sensitive file opened for reading by non-trusted program (user=root name=cat command=cat /etc/shadow file=/etc/shadow)
   ```

# Conclusions & Further reading

In this lab you learned the basic of Sysdig Falco and its application in the Docker-based deployments.
Starting off from kernel system calls, events and Linux namespace context metadata, you can configure the relevant
alerts without ever having to modify or instrument the Docker images, preserving their immutable and encapsulated
design.

You have used simple file output in order to focus on the rule syntax during this lab, but you can 
also [configure a custom program output](https://github.com/draios/falco/wiki/Falco-Alerts#program-output)
to get proper notifications.

Further reading:

- [Sysdig Falco documentation](https://github.com/draios/falco/wiki)
- Blogpost [SELinux, Seccomp, Sysdig Falco, and you: A technical discussion](https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/)
- Demo video [Sysdig Falco - Man in the middle attack detection](https://www.youtube.com/watch?v=Hf8PxSJOMfw)
- [Public slack channel](https://slack.sysdig.com/), join channel #falco 
