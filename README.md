# Lab 5 : CEG 3400 Intro to Cyber Security

## Name:

### Task 1: Snort ICMP

Paste your snort log ICMP packet here (paste all data from a single ping packet).

```bash 
sudo u2spewfoo /var/log/snort/snort.log

```

* What does the rule action `alert` do?
* In this scenario, why might we ***NOT*** want to use the `reject` or `drop` 
  rule actions?  Be sure to understand the scenario by reading task 1 instructions
  and be verbose in your answer!

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


