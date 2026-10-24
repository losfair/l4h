# EC2 boot and ENA tests

`tests/build-ec2.sh` builds a UEFI integration-test image;
`tools/ec2-image.py` imports it as a private, ENA-enabled x86-64 AMI;
`tests/ec2-test.py` launches it, records its serial output, and terminates
the instance. The importer uses the EBS direct API, so it needs neither
an S3 bucket nor a VM Import/Export service role.

On 2026-10-24, the complete test passed on `c6i.xlarge`: eight checks,
zero failures, including the optional jumbo/TCP peer checks. See the
[recorded result](results/ec2-c6i-2026-10-24.txt). All temporary AWS
resources from that run were removed; the image can be rebuilt and
imported with the commands below.

Use the repository's normal x86-64 build dependencies and Linux source
tree described in the [manual](../docs/manual/l4h-manual.tex). The AWS
identity needs EC2 launch/image/snapshot permissions and EBS direct API
permissions. Configure an existing AWS CLI profile or sign in first.

All build scratch files stay under `build/ec2/work`:

```sh
mkdir -p build/ec2/work
export TMPDIR="$PWD/build/ec2/work"
python3 -m venv build/ec2/venv
build/ec2/venv/bin/pip install 'boto3[crt]'
tests/build-ec2.sh
build/ec2/venv/bin/python tools/ec2-image.py build/ec2/l4h.raw \
    --region us-west-2 --name l4h-ec2-test-UNIQUE \
    --state build/ec2/image.json
build/ec2/venv/bin/python tests/ec2-test.py AMI_ID \
    --region us-west-2 --subnet SUBNET_ID --security-group SG_ID \
    --out build/ec2/boot-UNIQUE
```

Both Python tools accept `--profile`. Use a public subnet with a route to
an internet gateway and outbound DNS/HTTP access for the internet test.
The runner assigns a public IP; it needs no inbound SSH rule. Its default
machine is `c6i.xlarge` (4 vCPUs, 8 GiB), with UEFI and IMDSv2. l4h does
not need nested virtualization. Secure Boot must be disabled.

The boot test checks DHCP, IMDSv2, DNS and internet HTTP, the full guest
self-test on all four CPUs, 64 MiB of NVMe EBS write/readback, and four
concurrent small guests followed by destruction. The runner attaches a
fresh, disposable 1 GiB EBS volume as host disk 1 for the destructive
disk test; host disk 0 is the boot disk. Do not run this test initramfs on
an instance with existing data disks.

For jumbo frames and a checked 32 MiB TCP download, prepare a Linux peer
in the same subnet, set its interface MTU to 9001, and serve `payload`
and `payload.sha256` on TCP 8000. For example, in a directory on that peer:

```sh
dd if=/dev/urandom of=payload bs=1M count=32
sha256sum payload > payload.sha256
python3 -m http.server 8000 --bind PEER_PRIVATE_IP
```

Allow ICMP and TCP 8000 between the instances' security groups, and build
with `L4H_EC2_PEER=PEER_PRIVATE_IP tests/build-ec2.sh`. Without this setting,
the two peer-dependent checks are skipped. The separate
[VFIO test](ena-vfio/README.md) exercises both ENA TX queue placements,
packet contents, checksums, segmentation, index wraparound and MSI-X.

Resource IDs and results are saved in the requested JSON state files;
the boot directory also contains `serial.log`. A new state/output path is
required for every run so a previous resource record is not overwritten.
The runner terminates its instance on success or failure, including its
boot/data volumes and ENI. `--keep` retains it for debugging. Termination
uses `SkipOsShutdown` because l4h does not yet handle EC2's ACPI shutdown
request. The AMI and snapshot are retained; remove them when finished:

```sh
aws ec2 deregister-image --region us-west-2 --image-id AMI_ID
aws ec2 delete-snapshot --region us-west-2 --snapshot-id SNAPSHOT_ID
```

The built AMI contains an automated test dom0, which waits after reporting
the result. For a normal dom0, build its initramfs and configuration with
`tools/mkimage.sh -i INITRD -c CONFIG OUT.raw`, then use the same importer.
dom0's uplink vNIC inherits the ENI's MAC and can acquire its address with
DHCP. Put other guests on internal switches and route/NAT through dom0.
