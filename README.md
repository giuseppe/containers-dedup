containers-dedup
===========
PoC experimental tool for containers storage data deduplication.  It uses
the FIDEDUPERANGE ioctl for telling the file system to deduplicate
blocks with the same data.

Usage:
=======================================================

It requires reflinks support in the underlying file system.  You can
setup a XFS file system to play with and use it as storage for
containers:

```console
# truncate --size=20G xfs
# mkfs.xfs -m reflink=1 xfs 
# mount -o loop xfs /var/lib/containers/storage
```

To run the deduplication:

```console
$ ./autogen.sh
$ ./configure
$ make
$ sudo ./dedup /var/lib/containers/storage/{overlay,overlay-layers,overlay-images,libpod}
```
