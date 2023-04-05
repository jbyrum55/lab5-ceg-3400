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
cat /etc/snort/rules/local.rules

```

* What is a zero-day attack?
* Can Snort catch zero-day network attacks?  If not, why not?  If yes, how?
* What commands/process did you use to test your rules?  Be verbose!
* Provide the snort logs for your tests in a separate file `task2.logs`

---

### Task 3: EC (30 points)

* What rule did you choose?

```bash

```

* Describe the rule in detail (I purposely left formatting help out, be creative and make good use of markdown)!
* Describe what the rule is intended to detect and why someone might want this rule active.


