# Loghub samples

Excerpts of real system logs from [Loghub](https://github.com/logpai/loghub), used by
`LoghubSamplesParseTest` to check the parsers against lines no one wrote for them.

Each file is a contiguous slice of the dataset's `<Name>/<Name>_2k.log`, with the CRLF line
endings of the originals converted to LF. The lines themselves are unchanged.

| File | Lines of `_2k.log` | Shape | Expected |
| --- | --- | --- | --- |
| `Linux.log` | 501-1000 | BSD syslog, `/var/log/messages` | every line parses as syslog |
| `OpenSSH.log` | 1-500 | BSD syslog, `sshd` auth log | every line parses as syslog |
| `Mac.log` | 1-500 | BSD syslog, macOS `system.log` | every line parses as syslog |
| `Apache.log` | 1-50 | Apache **error** log | no parser accepts a line |
| `BGL.log` | 1-50 | Blue Gene/L RAS log | no parser accepts a line |
| `HDFS.log` | 1-50 | Hadoop log4j | no parser accepts a line |
| `OpenStack.log` | 1-50 | OpenStack, file-name prefixed | no parser accepts a line |
| `Proxifier.log` | 1-50 | Proxifier | no parser accepts a line |
| `Thunderbird.log` | 1-50 | syslog behind a Thunderbird prefix | no parser accepts a line |

The second group is there on purpose: a parser that accepts a line it does not understand files
it under the wrong fields, which is worse than leaving it to the plain-text fallback.

## Licence

The Loghub datasets are freely available for research or academic work. For any usage or
distribution, refer to the loghub repository URL, https://github.com/logpai/loghub, and cite:

> Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. *Loghub: A Large Collection of
> System Log Datasets for AI-driven Log Analytics.* IEEE International Symposium on Software
> Reliability Engineering (ISSRE), 2023.
