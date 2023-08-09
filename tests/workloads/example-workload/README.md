<!-- Space: CCOE -->
<!-- Parent: Security -->
<!-- Parent: Workload Firewall Rules -->
<!-- Title: example-workload firewall rules -->
<!-- Label: AWS -->
<!-- Label: CCOE -->
<!-- Label: NetworkFirewall -->
<!-- Label: Suppression -->

# example-workload Firewall Rules


The example-workload workload has the following accounts:

**Account Name** | **Account ID**
-----------------|---------------
binxio-example-workload-development | 111122223333
binxio-example-workload-testing | 222233334444
binxio-example-workload-acceptance | 333344445555
binxio-example-workload-production | 444455556666



## binxio-example-workload-development

The binxio-example-workload-development has the following suppressions registered:



### My Rule name

My rule destination

#### Sources

**CIDR** | **Description**
---------|----------------
192.168.0.0/21 | My Source


#### Destinations

**Endpoint** | **CIDR** | **Protocol** | **Port** | **Description**
-------------|----------|--------------|----------|-----------------
xebia.com | None | TLS  | 443 | My destination


#### Rules

Based on the above defined sources and destination the following firewall rules are required:

```
pass tls 192.168.0.0/21 any -> any 443 (tls.sni; content:"xebia.com"; nocase; startswith; endswith; msg:"binxio-example-workload-development | My Rule name"; sid:0; rev:1;)

```




## binxio-example-workload-testing



## binxio-example-workload-acceptance



## binxio-example-workload-production


