#!/usr/bin/env python3
"""Boot an l4h test AMI, collect serial results, and terminate the instance.

Build with tests/build-ec2.sh and import with tools/ec2-image.py first.
The AMI and its snapshot are retained. The supplied security group must
allow traffic to any configured test peer. A fresh, disposable 1 GiB EBS
data volume is attached for the destructive disk test.
"""
import argparse
import datetime
import json
from pathlib import Path
import time

import boto3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--region', required=True)
    parser.add_argument('--subnet', required=True)
    parser.add_argument('--security-group', required=True)
    parser.add_argument('--instance-type', default='c6i.xlarge')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=1200)
    parser.add_argument('--profile')
    parser.add_argument('--keep', action='store_true', help='retain the instance for debugging')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    ec2 = boto3.Session(profile_name=args.profile, region_name=args.region).client('ec2')
    name = 'l4h-boot-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    tags = [{'Key': 'Name', 'Value': name}, {'Key': 'Purpose', 'Value': 'l4h-ec2'}]
    instance = ec2.run_instances(
        ImageId=args.image, InstanceType=args.instance_type, MinCount=1, MaxCount=1,
        NetworkInterfaces=[{'DeviceIndex': 0, 'SubnetId': args.subnet,
                            'Groups': [args.security_group], 'AssociatePublicIpAddress': True,
                            'DeleteOnTermination': True}],
        BlockDeviceMappings=[{'DeviceName': '/dev/sdf', 'Ebs': {
            'VolumeSize': 1, 'VolumeType': 'gp3', 'DeleteOnTermination': True}}],
        MetadataOptions={'HttpTokens': 'required', 'HttpEndpoint': 'enabled'},
        TagSpecifications=[{'ResourceType': kind, 'Tags': tags} for kind in ('instance', 'volume')]
    )['Instances'][0]
    iid = instance['InstanceId']
    state = {'region': args.region, 'image': args.image, 'instance': iid, 'name': name}
    state_file = args.out / 'resources.json'
    state_file.write_text(json.dumps(state, indent=2) + '\n')
    print('Booting', iid, flush=True)
    passed = False
    previous = ''
    try:
        ec2.get_waiter('instance_running').wait(InstanceIds=[iid])
        instance = ec2.describe_instances(InstanceIds=[iid])['Reservations'][0]['Instances'][0]
        state['volumes'] = [m['Ebs']['VolumeId'] for m in instance['BlockDeviceMappings']]
        state['network_interfaces'] = [n['NetworkInterfaceId'] for n in instance['NetworkInterfaces']]
        state['public_ip'] = instance.get('PublicIpAddress')
        state_file.write_text(json.dumps(state, indent=2) + '\n')
        end = time.monotonic() + args.timeout
        while time.monotonic() < end:
            response = ec2.get_console_output(InstanceId=iid, Latest=True)
            # Botocore decodes EC2's base64 console field in its response handler.
            output = response.get('Output', '').replace('\r', '')
            if output:
                (args.out / 'serial.log').write_text(output)
            if output != previous:
                for line in output.splitlines():
                    if line not in previous and any(s in line for s in ('EC2TEST:', 'panic', 'PANIC', 'ENA ', 'Booting all')):
                        print(line, flush=True)
                previous = output
            if 'EC2TEST: PASS\n' in output:
                passed = True
                break
            if 'EC2TEST: FAIL\n' in output or 'PANIC:' in output or 'panicked at' in output:
                break
            time.sleep(10)
        state['passed'] = passed
    finally:
        if args.keep:
            print('Retained', iid, flush=True)
        else:
            # The test is finished and all data disks are disposable. l4h
            # does not yet handle EC2's ACPI power-button shutdown request.
            ec2.terminate_instances(InstanceIds=[iid], SkipOsShutdown=True)
            ec2.get_waiter('instance_terminated').wait(InstanceIds=[iid])
            state['terminated'] = True
            print('Terminated', iid, flush=True)
        state_file.write_text(json.dumps(state, indent=2) + '\n')
    print('Serial log:', args.out / 'serial.log', flush=True)
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
