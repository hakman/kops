# Images

As of Kubernetes 1.27 the default images used by kOps are the **[official Ubuntu 22.04](#ubuntu-2204-jammy)** images.

You can choose a different image for an instance group by editing it with `kops edit ig nodes`.

For AWS, you should set the `image` field in one of the following formats:

* `ami-abcdef` - specifies an image by id directly (image id is precise, but ids vary by region)
* `<owner>/<name>` specifies an image by its owner's account ID  and name properties
* `<alias>/<name>` specifies an image by its [owner's alias](#owner-aliases) and name properties
* `ssm:<ssm_parameter>` specifies an image through an SSM parameter (kOps 1.25.3+)

```yaml
image: ami-00579fbb15b954340
image: 099720109477/ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200423
image: ubuntu/ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200423
image: ssm:/aws/service/canonical/ubuntu/server/20.04/stable/current/amd64/hvm/ebs-gp2/ami-id
```

## Security Updates

As of kOps 1.35, automated security updates are disabled by default to minimize the risk that node updates disrupt the cluster. Instead, we recommend updating instance group images on a regular cadence.
To enable automatic security updates for Debian, Flatcar, or Ubuntu, edit the cluster or instance group configuration to include:

```yaml
spec:
  updatePolicy: automatic
```

## Distros Support Matrix

The following table provides the support status for various distros with regards to kOps version:

| Distro                                  | Experimental | Stable | Deprecated | Removed |
|-----------------------------------------|-------------:|-------:|-----------:|--------:|
| [Amazon Linux 2](#amazon-linux-2)       |         1.10 |   1.18 |          - |       - |
| [Amazon Linux 2023](#amazon-linux-2023) |         1.27 |      - |          - |       - |
| CentOS 7                                |            - |    1.5 |       1.21 |    1.23 |
| CentOS 8                                |         1.15 |      - |       1.21 |    1.23 |
| CoreOS                                  |          1.6 |    1.9 |       1.17 |    1.18 |
| Debian 8                                |            - |    1.5 |       1.17 |    1.18 |
| Debian 9                                |          1.8 |   1.10 |       1.21 |    1.23 |
| [Debian 10](#debian-10-buster)          |         1.13 |   1.17 |          - |       - |
| [Debian 11](#debian-11-bullseye)        |       1.21.1 |      - |          - |       - |
| [Debian 12](#debian-12-bookworm)        |       1.26.3 |      - |          - |       - |
| [Flatcar](#flatcar)                     |       1.15.1 |   1.17 |          - |       - |
| Kope.io                                 |            - |      - |       1.18 |    1.23 |
| RHEL 7                                  |            - |    1.5 |       1.21 |    1.23 |
| [RHEL 8](#rhel-8)                       |         1.15 |   1.18 |          - |       - |
| [RHEL 9](#rhel-9)                       |         1.27 |      - |          - |       - |
| [Rocky 8](#rocky-8)                     |       1.23.2 |   1.24 |          - |       - |
| [Rocky 9](#rocky-9)                     |         1.30 |      - |          - |       - |
| Ubuntu 16.04                            |          1.5 |   1.10 |       1.17 |    1.20 |
| Ubuntu 18.04                            |         1.10 |   1.16 |       1.26 |    1.28 |
| [Ubuntu 20.04](#ubuntu-2004-focal)      |       1.16.2 |   1.18 |          - |       - |
| [Ubuntu 22.04](#ubuntu-2204-jammy)      |         1.23 |   1.24 |          - |       - |
| [Ubuntu 24.04](#ubuntu-2404-noble)      |         1.29 |   1.31 |          - |       - |

## Supported Distros

### Amazon Linux 2

Amazon Linux 2 has variants using Kernel versions 4.14 and 5.10. Be sure to use the 5.10 images as specified in the image filter below. More information is available in the [AWS Documentation](https://aws.amazon.com/amazon-linux-2/faqs/).

For kOps versions 1.16 and 1.17, the only supported Docker version is `18.06.3`. Newer versions of Docker cannot be installed due to missing dependencies for `container-selinux`. This issue is fixed in kOps **1.18**.

Available images can be listed using:

```bash
aws ec2 describe-images --region us-east-1 --output table \
  --filters "Name=owner-alias,Values=amazon" \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=amzn2-ami-kernel-5.10-hvm-2*-*-gp2"
```

### Amazon Linux 2023

Amazon Linux 2023 uses Kernel version 6.1. More information is available in the [AWS Documentation](https://aws.amazon.com/linux/amazon-linux-2023/faqs/). Only the standard AMI is supported, the [minimal AMI](https://docs.aws.amazon.com/linux/al2023/ug/AMI-minimal-and-standard-differences.html) is not supported.

Available images can be listed using:

```bash
aws ec2 describe-images --region us-east-1 --output table \
  --filters "Name=owner-alias,Values=amazon" \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=al2023-ami-2*-kernel-6.1-*"
```

### Debian 10 (Buster)

Debian 10 is based on Kernel version **4.19** which fixes some of the bugs present in Debian 9 and effects are less visible.

One notable change is the addition of `iptables` NFT, which is by default. This is not yet supported by most CNI plugins and seems to be [slower](https://youtu.be/KHMnC3kj3Js?t=771) than the legacy version. It is recommended to switch to `iptables` legacy by using the following script in `additionalUserData` for each instance group:

```yaml
additionalUserData:
  - name: busterfix.sh
    type: text/x-shellscript
    content: |
      #!/bin/sh
      update-alternatives --set iptables /usr/sbin/iptables-legacy
      update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
      update-alternatives --set arptables /usr/sbin/arptables-legacy
      update-alternatives --set ebtables /usr/sbin/ebtables-legacy
```

Available images can be listed using:

```bash
# Amazon Web Services (AWS)
aws ec2 describe-images --region us-east-1 --output table \
  --owners 136693071363 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=debian-10-*-*"

# Google Cloud Platform (GCP)
gcloud compute images list --filter debian-10-buster-v

# Microsoft Azure
az vm image list --all --output table \
  --publisher Debian --offer debian-10 --sku 10-gen2
```

### Debian 11 (Bullseye)

Debian 11 is based on Kernel version **5.10** which has no known major Kernel bugs and fully supports all Cilium features.

Available images can be listed using:

```bash
# Amazon Web Services (AWS)
aws ec2 describe-images --region us-east-1 --output table \
  --owners 136693071363 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=debian-11-*-*"

# Google Cloud Platform (GCP)
gcloud compute images list --filter debian-11-bullseye-v

# Microsoft Azure
az vm image list --all --output table \
  --publisher Debian --offer debian-11 --sku 11-gen2
```

### Debian 12 (Bookworm)

Debian 12 is based on Kernel version **6.1** which has no known major Kernel bugs and fully supports all Cilium features.

Available images can be listed using:

```bash
# Amazon Web Services (AWS)
aws ec2 describe-images --region us-east-1 --output table \
  --owners 136693071363 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=debian-12-*-*"
```

### Flatcar

Flatcar is a friendly fork of CoreOS and as such, compatible with it.

Available images can be listed using:

```bash
aws ec2 describe-images --region us-east-1 --output table \
  --owners 075585003325 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=Flatcar-stable-*-hvm"
```

### RHEL 8

RHEL 8 is based on Kernel version **4.18** which fixes some of the bugs present in RHEL/CentOS 7 and effects are less visible.

One notable change is the addition of `iptables` NFT, which is the only iptables backend available. This may not be supported by some CNI plugins and should be used with care.

Available images can be listed using:

```bash
aws ec2 describe-images --region us-east-1 --output table \
  --owners 309956199498 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=RHEL-8.*"
```

### RHEL 9

RHEL 9 is based on Kernel version **5.15** which fixes all the known major Kernel bugs.

Available images can be listed using:

```bash
aws ec2 describe-images --region us-east-1 --output table \
  --owners 309956199498 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=RHEL-9.*"
```

### Rocky 8

Rocky Linux is a community enterprise Operating System designed to be 100% bug-for-bug compatible with [RHEL 8](#rhel-8).

Available images can be listed using:

```bash
aws ec2 describe-images --region us-east-1 --output table \
  --owners 792107900819 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=Rocky-8-ec2-8.*.*"
```

### Rocky 9

Rocky Linux 9 is based on Kernel version **5.14**.

Available images can be listed using:

```bash
aws ec2 describe-images --region us-east-1 --output table \
  --owners 792107900819 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=Rocky-9-EC2-Base-9.*.*"
```


### Ubuntu 20.04 (Focal)

Ubuntu 20.04 is based on Kernel version **5.4** which fixes all the known major Kernel bugs.

Available images can be listed using:

```bash
# Amazon Web Services (AWS)
aws ec2 describe-images --region us-east-1 --output table \
  --owners 099720109477 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-focal-20.04-*-*"
  
# Google Cloud Platform (GCP)
gcloud compute images list --filter ubuntu-2004-focal-v

# Microsoft Azure
az vm image list --all --output table \
  --publisher Canonical --offer 0001-com-ubuntu-server-focal --sku 20_04-lts-gen2
```

### Ubuntu 22.04 (Jammy)

Ubuntu 22.04 is based on Kernel version **5.15** which fixes all the known major Kernel bugs.

Available images can be listed using:

```bash
# Amazon Web Services (AWS)
aws ec2 describe-images --region us-east-1 --output table \
  --owners 099720109477 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*-*"

# Google Cloud Platform (GCP)
gcloud compute images list --filter ubuntu-2204-jammy-v

# Microsoft Azure
az vm image list --all --output table \
  --publisher Canonical --offer 0001-com-ubuntu-server-jammy --sku 22_04-lts-gen2
```

### Ubuntu 24.04 (Noble)

Support for Ubuntu 24.04 is based on Kernel version **6.8**.

Available images can be listed using:

```bash
# Amazon Web Services (AWS)
aws ec2 describe-images --region us-east-1 --output table \
  --owners 099720109477 \
  --query "sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]" \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-*-*"
```

## Owner aliases

kOps supports owner aliases for the official accounts of supported distros:

* `amazon` => `137112412989`
* `debian10` => `136693071363`
* `debian11` => `136693071363`
* `flatcar` => `075585003325`
* `redhat` => `309956199498`
* `ubuntu` => `099720109477`
