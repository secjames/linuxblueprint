# linuxblueprint

linuxblueprint.sh

Authors: James McNabb, Eric Wold

This script "blueprints" a linux system and gathers information for system vetting needs and generates a report of in the current working directory. An overview of report secitons can be found below.

Report Sections:
1.  Host Name
2.  Computer Information
3.  Hardware Information
4.  Banners
5.  Host File
6.  DNS IInformation
7.  User Information
8.  Goups Information
9.  Home Directories
10. Installed Software
11. Services and Statuses
12. Open Ports
13. Cron Jobs
14. Firewall Setup
15. SSH Setup
16. Webserver Information
17. SSL Information
18. Samba/SMB Informaiton
19. App Armor/SeLinux Informaiton
20. Syslog Information
21. Fail2Ban Information
22. SNMP Information

Usage: sudo ./linuxblueprint.sh

Report Name: YYmmddHHMMSS-{Hostname}-Blueprint.txt