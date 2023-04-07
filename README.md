# Lab 5 : CEG 3400 Intro to Cyber Security

## Name: Jason Byrum

### Task 1: Snort ICMP

Paste your snort log ICMP packet here (paste all data from a single ping packet).

```bash 
sudo u2spewfoo /var/log/snort/snort.log
(Event)
        sensor id: 0    event id: 4     event second: 1680715857        event microsecond: 62149
        sig id: 1000001 gen id: 1       revision: 1      classification: 0
        priority: 0     ip source: 10.0.0.25    ip destination: 54.174.113.99
        src port: 8     dest port: 0    protocol: 1     impact_flag: 0  blocked: 0
        mpls label: 0   vland id: 0     policy id: 0    appid:

Packet
        sensor id: 0    event id: 4     event second: 1680715857
        packet second: 1680715857       packet microsecond: 62149
        linktype: 1     packet_length: 98
[    0] 16 39 E0 55 71 E9 16 14 23 4D 92 97 08 00 45 00  .9.Uq...#M....E.
[   16] 00 54 D3 CD 40 00 40 01 B4 B1 0A 00 00 19 36 AE  .T..@.@.......6.
[   32] 71 63 08 00 0A 21 00 01 00 04 51 B0 2D 64 00 00  qc...!....Q.-d..
[   48] 00 00 AF F2 00 00 00 00 00 00 10 11 12 13 14 15  ................
[   64] 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25  .......... !"#$%
[   80] 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35  &'()*+,-./012345
[   96] 36 37                                            67



```

* What does the rule action `alert` do?
  *  The alert action is something that is put in place to look for a certain something. In our example when it finds a ICMP packet it will let you know. You can also use the alert command to search for something you want to find or something that should not be somewhere.
* In this scenario, why might we ***NOT*** want to use the `reject` or `drop` 
  rule actions?  Be sure to understand the scenario by reading task 1 instructions
  and be verbose in your answer!
  * You would not want to use the reject or drop actions becasue we are tring to capture the incoming ICMP packets coming into our honeypot and using these commands would drop or reject them and we would not be able to capture them to get their IP. 

---

### Task 2: Custom rules 

List all three of your new rules in `/etc/snort/rules/local.rules` here:

```bash
ubuntu@ip-10-0-0-25:/$ cat /etc/snort/rules/local.rules
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any -> any any (msg:"ICMP Packet found"; sid:1000001; rev:1;)
alert tcp any any -> any 80 (msg:"Outgoing traffic to www.gizoogle.net"; content:"Host\: www.gizoogle.net"; sid:1000002; rev:1;)
alert tcp any any -> any 80 (msg:"Outgoing traffic to www.lingscars.com"; content:"Host\: www.lingscars.com"; sid:1000003; rev:1;)
alert tcp any any -> any 80 (msg:"Outgoing traffic to twitter.com"; content:"Host\: twitter.com"; sid:1000004; rev:1;)
alert tcp any 80 -> any any (msg:"Incoming traffic from www.gizoogle.net"; content:"Host\: www.gizoogle.net"; sid:1000005; rev:1;)
alert tcp any 80 -> any any (msg:"Incoming traffic from www.lingscars.com"; content:"Host\: www.lingscars.com"; sid:1000006; rev:1;)
alert tcp any 80 -> any any (msg:"Incoming traffic from twitter.com"; content:"Host\: twitter.com"; sid:1000007; rev:1;)

```

* What is a zero-day attack?
  * A zero-day attack is an attack on a network or software that the developer or manager is unaware of. They call it a zero-day attack because the manager or developer does not know about the hole in their code or network to get a patch out in time, therefore they have zero days to prepare for it.

* Can Snort catch zero-day network attacks?  If not, why not?  If yes, how?
  * Yes, Snort can catch zero-day network attacks. Snort can look out for suspicious incoming traffic and get the jump the incoming threat from a vulnerability before it has time to act.
* What commands/process did you use to test your rules?  Be verbose!
  * First I had to add the rules to the local.rules, then I had to restart. Next I used the command curl -H "Host: www.gizoogle.net" 54.174.113.99. This command uses my virtual IP to ping the website that I had flagged by the alert command. Then I printed the readable file to task2.logs. 

* Provide the snort logs for your tests in a separate file `task2.logs`

---

### Task 3: EC (30 points)

* What rule did you choose?
  * I choose chat.rules  
Explain all parts of the rule and what they do including:
* Rule headers including IP, protocol, port, and direction
  * IP- This rule uses two variables for an external and internal network addresses. It does not specify a certain IP address.
  Protocol- This rule scans for TCP traffic.
  Port- This rule looks for traffic on any port specified.
  Direction- This rule looks for traffic going from any external IP address to any IP address on a network.
* Active rules and options including content, offset, and all relevent options to make the rule work
    * Alert- Will generate an alert if it matches the specification.
      * Traffic- It needs to know what type of traffic to monitor such as TCP.
      * Source and Destination- Needs the source and destination addresses and ports for the traffic to match. 
      * Message- It needs to have a message to display to the user.
      * Flow- This option limits the rule to only look at traffic that has already established a connection to the server.
      * Content- Needs to have specific content specified that the rule can look for in the packet.
      * Offset- This specifies the position in the packet where the content should start being searched.
      * Depth- This specifies the maximum length of the packet to search for the content.
      * Reference- This provides a reference to the CVE vulnerability that this rule is designed to detect.
      * Classtype- This specifies the classification type of the alert.
      * Sid- This is the unique ID number of the rule.
      * Rev- This is the revision number of the rule.
* Your words on what the rule is trying to detect.
  * This rules file has rules that aim to detect many instant messaging traffic for the large messaging companies such as many popular messanger websites and services. A user of these rules can set an alert to search for certain parts of a packet that may be of interest such as certain strings of data.


