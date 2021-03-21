Postfix FS Exporter
===================

This exporter collects filesystem and /proc postfix statistics.
It counts number of files and their total size in each queue directory.
Also it counts postfix processes and parses master.cf to know what is maximum
number of these processes.

See `postfix-fs-exporter -help` for list of available configuration options.
