#!/usr/bin/env python3
"""Import a raw tools/mkimage.sh image as a private UEFI/ENA EC2 AMI.

Requires boto3 (boto3[crt] for AWS CLI login profiles), EBS direct API and
EC2 image permissions. No S3 bucket or VM Import/Export role is needed.
Resource IDs are saved as soon as they exist; keep the state file until
the AMI is deregistered and its backing snapshot has been deleted.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path

import boto3
from botocore.config import Config

BLOCK = 512 * 1024
GIB = 1024 ** 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('disk', type=Path)
    parser.add_argument('--region', required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--profile')
    args = parser.parse_args()
    size = args.disk.stat().st_size
    if not size or size % GIB:
        parser.error('raw image size must be a positive whole number of GiB')
    with args.disk.open('rb') as disk:
        header = disk.read(1024)
        disk.seek(-512, os.SEEK_END)
        backup = disk.read(8)
    if header[510:512] != b'\x55\xaa' or header[512:520] != b'EFI PART' or backup != b'EFI PART':
        parser.error('expected a complete GPT disk image from tools/mkimage.sh')
    args.state.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite the only record of resources from a previous import.
    with args.state.open('x') as f:
        json.dump({'region': args.region, 'name': args.name}, f)
    state = {'region': args.region, 'name': args.name, 'disk': str(args.disk.resolve())}

    def save():
        args.state.write_text(json.dumps(state, indent=2) + '\n')

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    config = Config(retries={'mode': 'standard', 'max_attempts': 8})
    ebs = session.client('ebs', config=config)
    ec2 = session.client('ec2', config=config)
    tags = [{'Key': 'Name', 'Value': args.name}, {'Key': 'Purpose', 'Value': 'l4h-ec2'}]
    snap = ebs.start_snapshot(VolumeSize=size // GIB, Description=args.name, Tags=tags)
    state['snapshot'] = snap['SnapshotId']
    save()
    print('Uploading', state['snapshot'], flush=True)
    with args.disk.open('rb') as disk:
        indices = []
        digest = hashlib.sha256()
        for index in range(size // BLOCK):
            block = disk.read(BLOCK)
            if len(block) != BLOCK:
                raise RuntimeError('image changed size while reading')
            digest.update(block)
            if block.strip(b'\0'):
                indices.append(index)
        state['sha256'] = digest.hexdigest()
        state['blocks'] = len(indices)
        save()

        def upload(index):
            block = os.pread(disk.fileno(), BLOCK, index * BLOCK)
            if len(block) != BLOCK:
                raise RuntimeError('image changed size while uploading')
            checksum = base64.b64encode(hashlib.sha256(block).digest()).decode()
            result = ebs.put_snapshot_block(
                SnapshotId=state['snapshot'], BlockIndex=index, BlockData=block,
                DataLength=BLOCK, Checksum=checksum, ChecksumAlgorithm='SHA256')
            if result['Checksum'] != checksum:
                raise RuntimeError('snapshot block checksum mismatch')

        with ThreadPoolExecutor(max_workers=4) as pool:
            for done, _ in enumerate(pool.map(upload, indices), 1):
                if done % 32 == 0 or done == len(indices):
                    print(f'Uploaded {done}/{len(indices)} nonzero blocks', flush=True)
    ebs.complete_snapshot(SnapshotId=state['snapshot'], ChangedBlocksCount=len(indices))
    print('Waiting for snapshot completion', flush=True)
    ec2.get_waiter('snapshot_completed').wait(
        SnapshotIds=[state['snapshot']], WaiterConfig={'Delay': 10, 'MaxAttempts': 120})
    result = ec2.register_image(
        Name=args.name, Description='l4h UEFI boot image', Architecture='x86_64',
        VirtualizationType='hvm', RootDeviceName='/dev/sda1', BootMode='uefi',
        EnaSupport=True, ImdsSupport='v2.0',
        BlockDeviceMappings=[{'DeviceName': '/dev/sda1', 'Ebs': {
            'SnapshotId': state['snapshot'], 'VolumeType': 'gp3', 'DeleteOnTermination': True}}],
        TagSpecifications=[{'ResourceType': 'image', 'Tags': tags}])
    state['image'] = result['ImageId']
    save()
    ec2.get_waiter('image_available').wait(ImageIds=[state['image']])
    print(json.dumps(state, indent=2), flush=True)


if __name__ == '__main__':
    main()
