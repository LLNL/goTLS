rpm packaging
=============

This directory contains the spec file required to generate an rpm package from
the gotls source repo.

## Configure

In order for go modules to download during a mockbuild, you may have to enable
systemd container access within the mock container:

```
cat ~/.mock/user.cfg
config_opts['rpmbuild_networking'] = True
```

## Build

First we need to place an archive containing the source alongside the
gencsr.spec file. The preferred method is to download an archive from a source
control repository. However, the archive must decompress into a top-level
folder following this naming convention:
gotls-0.1.0/

To manually create the archive from a git working folder:
```
tar --exclude-vcs --exclude-vcs-ignores --exclude='rpm/gotls-*' --exclude='todo' --dereference -czf gotls-0.1.0.tar.gz gotls-0.1.0/
```

Once the archive is in place, build the package for the desired operating
system version:
```
$ mv gotls-0.1.0.tar.gz gotls-0.1.0/rpm/
$ cd gotls-0.1.0/rpm/
$ fedpkg --release f29 mockbuild
```

