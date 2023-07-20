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

**CIDR** | **Region** | **Description**
---------|------------|----------------
192.168.0.0/21 | eu-west-1 | My Source


#### Destinations

**Endpoint** | **CIDR** | **Region** | **Protocol** | **Port** | **Description**
-------------|----------|------------|--------------|----------|-----------------
xebia.com | 192.168.8.0/21 | eu-central-1 | TLS  | 443 | My destination


#### Rules

Based on the above defined sources and destination the following firewall rules are required:

```
pass tls 192.168.0.0/21 any -> 192.168.8.0/21 443 (tls.sni; tls.version:"1.2,1.3"; content:"xebia.com"; nocase; startswith; endswith; msg:"binxio-example-workload-development | My Rule name"; rev:"1"; sid:"XXX")

```




## binxio-example-workload-testing



## binxio-example-workload-acceptance



## binxio-example-workload-production


