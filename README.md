# AWS Security VPC with Check Point CloudGuard Network Security using GWLB

## Architecture

![Architecture](./img/aws-security-vpc-chkp-gwlb.svg)

## Contents

- build infarstructure: 50-aws-tgw-chkp-vpc

- implement Check Point policy: 51-tf-aws-policy

## Flow

* open in Github Workspace

* follow [50-aws-tgw-chkp-vpc/NOTES.md](./50-aws-tgw-chkp-vpc/NOTES.md) to build ingrastructure

```shell
cd /workspaces/tf-aws-security-vpc-gwlb/50-aws-tgw-chkp-vpc/
code NOTES.md
```

* use [51-tf-aws-policy/NOTES.md](./51-tf-aws-policy/NOTES.md) to implement Check Point policy in provided CP Security Management server