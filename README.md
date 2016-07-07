# Exercise from BT #

## Description ##

Attached is a log file, it has 1,000 entries in it. The format of the entries of the log file differ depending on the event type:
1.  CVE event: Date, Time, Severity, Event ID, Hostname, Protocol, CVE ID.
2.  Access event: Date, Time, Severity Event ID, Source Address, Destination Address, User.
 
With this file do the following:
1.  Write a python script that reads the log file and writes it into an sqlite database table.
2.  Verify that all entries are in the sqlite database.
3.  Tell us how many critical CVE issues are there?

Please send to us:
1.  Git repository containing the Python code.
2.  The resulting sqlite database.

## Example ##

```
2016-05-27 22:01:46.403912 high 7564 host778.example.com TCP CVE-2015-6778
2016-05-27 22:08:20.403929 high 9081 247.134.158.200 79.87.184.11 bryan
```

## Answers ##

Total number of critical CVEs: 133
