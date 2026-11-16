#!/usr/bin/env python3
"""Fork lifecycle controls and diagnostic kernel entry profiles; all artifacts stay in build/."""
import argparse
import csv
import importlib.util
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('smp',ROOT/'tests/run-smpbench.py')
smp=importlib.util.module_from_spec(spec)
spec.loader.exec_module(smp)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--variants',default='sel4,fl4,serial')
    p.add_argument('--kernel',action='append',default=[],help='NAME=ELF overrides/adds a kernel variant')
    p.add_argument('--force',action='append',default=[],help='NAME=MASK selects diagnostic serial admission: copy=1, delete=2, map=4, all=8')
    p.add_argument('--profile',type=int,choices=[0,1],default=1)
    p.add_argument('--vcpus',type=smp.cpu_list,default=[1,2,4])
    p.add_argument('--workers',type=int,help='Fixed worker count instead of one per vCPU')
    p.add_argument('--modes',default='0,1,2',help='0=fork, 1=vfork, 2=clone_vm')
    p.add_argument('--count',type=int,default=2000)
    p.add_argument('--runs',type=int,default=3)
    p.add_argument('--nice',type=int,help='Runner/QEMU nice value; negative values use sudo -n renice if needed')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    nice=smp.configure_nice(a.nice)
    a.output=a.output.resolve()
    a.output.mkdir(parents=True,exist_ok=False)
    scratch=ROOT/'build/scratch'
    scratch.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,TMPDIR=str(scratch))
    kernels={'sel4':ROOT/'build/sel4/bin/kernel.elf',
             'fl4':ROOT/'build/sel4-fl4/bin/kernel.elf',
             'serial':ROOT/'build/kernel-fl4-latest-serial/kernel/kernel.elf',
             'profile':ROOT/'build/kernel-fl4-fork-profile/kernel/kernel.elf'}
    for item in a.kernel:
        name,path=item.split('=',1)
        kernels[name]=Path(path).resolve()
    variants=a.variants.split(',')
    forces={name:int(mask,0) for name,mask in (x.split('=',1) for x in a.force)}
    modes=[int(m) for m in a.modes.split(',')]
    assert all(1<=n<=6 for n in a.vcpus) and all(0<=m<=2 for m in modes) and a.runs>0 and a.count>0
    if a.workers: assert 1<=a.workers<=min(a.vcpus)
    inputs=a.output/'images'
    inputs.mkdir()
    for name in ['initrd.cpio.gz','forkbench']:
        shutil.copy2(ROOT/'build/forkbench'/name,inputs/name)
    shutil.copy2(ROOT/'build/smpbench/images/linux.elf',inputs/'linux.elf')
    metadata={'args':{k:str(v) if isinstance(v,Path) else v for k,v in vars(a).items()},
              'fl4_revision':(ROOT/'build/sel4-fl4/fl4-revision').read_text().strip(),
              'uname':smp.run(['uname','-a']),'nice':nice,'scheduler':smp.scheduler_context(),
              'kernels':{},'sha256':{p.name:smp.digest(p) for p in inputs.iterdir()}}
    for variant in variants:
        dest=inputs/variant
        dest.mkdir()
        backend='sel4' if variant=='sel4' else 'fl4'
        shutil.copy2(ROOT/'build/smpbench/images'/backend/'root.elf',dest/'root.elf')
        smp.run(['objcopy','-O','elf32-i386',str(kernels[variant]),str(dest/'kernel32.elf')],env=env)
        metadata['kernels'][variant]={'path':str(kernels[variant]),'sha256':smp.digest(kernels[variant])}
    for name in ['forkbench.c','init-forkbench']:
        shutil.copy2(ROOT/'tests/guest'/name,a.output/name)
    shutil.copy2(__file__,a.output/'run-forkbench.py')
    (a.output/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    rows=[]
    for rep in range(1,a.runs+1):
        order=variants if rep%2 else list(reversed(variants))
        for n in a.vcpus:
            for mode in modes:
                for variant in order:
                    print(f'Fork run {rep}/{a.runs}: {variant}, {n} vCPUs, mode {mode}',flush=True)
                    dest=a.output/f'r{rep:02d}-{variant}-{n}cpu-m{mode}'
                    dest.mkdir()
                    conf=dest/'l4h.conf'
                    conf.write_text(f'dom0_vcpus={n}\ndom0_mem_mb=512\nwatchdog_secs=0\n'
                                    f'dom0_cmdline=console=hvc0 FORKBENCH_COUNT={a.count} FORKBENCH_MODE={mode} '
                                    f'FORKBENCH_WORKERS={a.workers or n} FORKBENCH_FORCE={forces.get(variant,0)} FORKBENCH_PROFILE={a.profile}\n')
                    image=dest/'root-dom0.elf'
                    smp.run([str(ROOT/'tools/add-modules.py'),str(inputs/variant/'root.elf'),str(image),
                             f'guest-kernel={inputs/"linux.elf"}',f'dom0-initrd={inputs/"initrd.cpio.gz"}',
                             f'l4h-config={conf}'],env=env,log=dest/'modules.log')
                    sock=ROOT/'build/forkbench-qmp.sock'
                    sock.unlink(missing_ok=True)
                    command=['taskset','-c','0,1','qemu-system-x86_64','-enable-kvm',
                             '-cpu','host,-vmx,-svm,+invtsc','-smp','6,sockets=1,cores=6,threads=1',
                             '-m','4G','-nographic','-serial','mon:stdio','-no-reboot','-nic','none',
                             '-kernel',str(inputs/variant/'kernel32.elf'),'-initrd',str(image),
                             '-S','-qmp',f'unix:{sock},server=on,wait=off']
                    log=dest/'serial.log'
                    info={'command':command,'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
                    qmp=None
                    with log.open('w') as stream:
                        proc=subprocess.Popen(command,env=env,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT)
                        try:
                            qmp=smp.QMP(sock,proc)
                            cpus=sorted(qmp.execute('query-cpus-fast'),key=lambda c:c['cpu-index'])
                            assert len(cpus)==6
                            for cpu,host in zip(cpus,range(2,8)):
                                os.sched_setaffinity(cpu['thread-id'],{host})
                                cpu['host_affinity']=sorted(os.sched_getaffinity(cpu['thread-id']))
                                cpu['host_stats']=smp.thread_stats(cpu['thread-id'])
                                assert cpu['host_affinity']==[host]
                                assert cpu['host_stats']['nice']==nice
                            info['cpu_threads']=cpus
                            qmp.execute('cont')
                            deadline=time.monotonic()+240
                            while proc.poll() is None:
                                content=log.read_text(errors='replace')
                                if 'FORKBENCH: PASS' in content or 'FORKBENCH: FAIL' in content: break
                                if time.monotonic()>deadline: raise TimeoutError(str(log))
                                time.sleep(.1)
                        finally:
                            if proc.poll() is None and 'cpu_threads' in info:
                                info['final_thread_stats']={str(c['thread-id']):smp.thread_stats(c['thread-id']) for c in info['cpu_threads']}
                            if qmp:qmp.close()
                            proc.terminate()
                            try:proc.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                proc.kill();proc.wait()
                            sock.unlink(missing_ok=True)
                            (dest/'run.json').write_text(json.dumps(info,indent=2)+'\n')
                    content=log.read_text(errors='replace')
                    assert 'FORKBENCH: PASS' in content and 'FORKBENCH: FAIL' not in content,str(log)
                    matches=[line for line in content.splitlines() if line.startswith('FORKBENCH: metric=')]
                    assert len(matches)==1,str(log)
                    row=dict(part.split('=',1) for part in matches[0].split()[1:])
                    assert int(row['workers'])==(a.workers or n) and int(row['operations'])==(a.workers or n)*a.count
                    row.update(variant=variant,vcpus=n,repetition=rep)
                    row['value']=float(row['value'])
                    rows.append(row)
                    image.unlink()
                    with (a.output/'raw.csv').open('w') as f:
                        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    summary=[]
    for n in a.vcpus:
        for mode in modes:
            metric=['fork','vfork','clone_vm'][mode]
            for variant in variants:
                selected=[r for r in rows if r['vcpus']==n and r['metric']==metric and r['variant']==variant]
                values=[r['value'] for r in selected]
                entry={'vcpus':n,'metric':metric,'variant':variant,'n':len(values),'median':statistics.median(values),'min':min(values),'max':max(values)}
                for field in ['fork_ticks','wait_ticks']:
                    entry[field+'_per_op']=statistics.median(int(r[field])/int(r['operations']) for r in selected)
                summary.append(entry)
                print(entry,flush=True)
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')

if __name__=='__main__': main()
