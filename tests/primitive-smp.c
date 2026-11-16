// Direct concurrent batches of 64 copy/map/delete operations. Detach and
// clear the leaf table before deleting mapping caps, as L4H teardown does.
// Reuse the root-task bootstrap, checked allocators and UART from the probe.
#define primitivebench_main unused_primitivebench_main
#include "primitivebench.c"
#undef primitivebench_main

struct smp_worker {
    char stack[32768] __attribute__((aligned(16)));
    char tls[4096] __attribute__((aligned(64)));
    char ipc[4096] __attribute__((aligned(4096)));
    seL4_CPtr tcb, sc, space, target, pt, frame[64], copy;
    unsigned long begin, end, copy_ticks, map_ticks, delete_ticks;
};
static struct smp_worker sw[4] __attribute__((aligned(4096)));
static volatile unsigned long ready_mask, done_mask;
static unsigned long worker_count, loop_count;
static int shared_frame;
static seL4_CPtr done_ntfn;

__attribute__((noreturn)) static void smp_client(unsigned long id)
{
    struct smp_worker *w=&sw[id];
    __sel4_ipc_buffer=(seL4_IPCBuffer *)w->ipc;
    __atomic_fetch_or(&ready_mask,1ul<<id,__ATOMIC_RELEASE);
    while(__atomic_load_n(&ready_mask,__ATOMIC_ACQUIRE)!=(1ul<<worker_count)-1)
        __asm__ volatile("pause");
    w->copy_ticks=w->map_ticks=w->delete_ticks=0;
    w->begin=ticks();
    for(unsigned long batch=0;batch<loop_count/64;batch++) {
        for(unsigned long k=0;k<64;k++) {
            unsigned long t=ticks();
            CK(seL4_CNode_Copy(seL4_CapInitThreadCNode,w->copy+k,64,seL4_CapInitThreadCNode,
                              sw[shared_frame ? 0 : id].frame[k],64,seL4_AllRights));
            unsigned long u=ticks();w->copy_ticks+=u-t;t=u;
            CK(seL4_X86_Page_Map(w->copy+k,w->target,0x8000000000ul+k*4096,seL4_ReadWrite,seL4_X86_Default_VMAttributes));
            u=ticks();w->map_ticks+=u-t;
        }
        CK(seL4_X86_PageTable_Unmap(w->pt));
        for(unsigned long k=0;k<64;k++) {
            unsigned long t=ticks();
            CK(seL4_CNode_Delete(seL4_CapInitThreadCNode,w->copy+k,64));
            w->delete_ticks+=ticks()-t;
        }
        CK(seL4_X86_PageTable_Map(w->pt,w->target,0x8000000000ul,seL4_X86_Default_VMAttributes));
    }
    w->end=ticks();
    __atomic_fetch_or(&done_mask,1ul<<id,__ATOMIC_RELEASE);
    seL4_Signal(done_ntfn);
    CK(seL4_TCB_Suspend(w->tcb));
    for(;;)__asm__ volatile("pause");
}

static void smp_metric(const char *operation, unsigned trial, unsigned long elapsed)
{
    char name[80];unsigned n=0;
    while(*operation)name[n++]=*operation++;
    name[n++]='_';name[n++]='0'+worker_count;
    const char *tail=shared_frame ? "cpu_shared" : "cpu_private";
    while(*tail)name[n++]=*tail++;
    name[n]=0;
    report(name,trial,elapsed,loop_count*worker_count);
}

void primitivebench_main(seL4_BootInfo *bootinfo)
{
    bi=bootinfo;
    unsigned long tp=(unsigned long)(tls[0]+sizeof(tls[0])-64);
    *(unsigned long *)tp=tp;
    seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB,tp);
    __sel4_ipc_buffer=bi->ipcBuffer;
    next_slot=bi->empty.start;
    uart=next_slot++;
    seL4_X86_IOPortControl_Issue(seL4_CapIOPortControl,0x3f8,0x3ff,seL4_CapInitThreadCNode,uart,64);
    CK(seL4_TCB_SetFlags(seL4_CapInitThreadTCB,0,1).error);
    unsigned best=0;
    for(seL4_CPtr i=bi->untyped.start;i<bi->untyped.end;i++) {
        seL4_UntypedDesc *d=&bi->untypedList[i-bi->untyped.start];
        if(!d->isDevice && d->sizeBits>best){ut=i;best=d->sizeBits;}
    }
    if(best<22 || bi->numNodes<4)fail("untyped or SMP cores",best);
    done_ntfn=retype(seL4_NotificationObject,0);
    for(unsigned i=0;i<4;i++) {
        struct smp_worker *w=&sw[i];
        w->tcb=retype(seL4_TCBObject,0);
        w->sc=retype(seL4_SchedContextObject,10);
        for(unsigned k=0;k<64;k++)w->frame[k]=retype(seL4_X86_4K,0);
        w->copy=next_slot;next_slot+=64;
        w->space=copy_space();
        w->target=retype(seL4_X64_PML4Object,0);
        CK(seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool,w->target));
        CK(seL4_X86_PDPT_Map(retype(seL4_X86_PDPTObject,0),w->target,0x8000000000ul,seL4_X86_Default_VMAttributes));
        CK(seL4_X86_PageDirectory_Map(retype(seL4_X86_PageDirectoryObject,0),w->target,0x8000000000ul,seL4_X86_Default_VMAttributes));
        w->pt=retype(seL4_X86_PageTableObject,0);
        CK(seL4_X86_PageTable_Map(w->pt,w->target,0x8000000000ul,seL4_X86_Default_VMAttributes));
        seL4_CPtr ipcframe=bi->userImageFrames.start+((unsigned long)w->ipc-(unsigned long)__executable_start)/4096;
        CK(seL4_TCB_Configure(w->tcb,seL4_CapInitThreadCNode,0,w->space,0,(unsigned long)w->ipc,ipcframe));
        CK(seL4_SchedControl_ConfigureFlags(bi->schedcontrol.start+i,w->sc,5000,5000,0,0,0));
        CK(seL4_TCB_SetSchedParams(w->tcb,seL4_CapInitThreadTCB,100,100,w->sc,seL4_CapNull));
        CK(seL4_TCB_SetFlags(w->tcb,0,1).error);
    }
    for(shared_frame=0;shared_frame<=1;shared_frame++)
    for(worker_count=1;worker_count<=4;worker_count*=2)
    for(unsigned trial=0;trial<=5;trial++) {
        ready_mask=done_mask=0;loop_count=trial ? 32768 : 1024;
        for(unsigned i=0;i<worker_count;i++) {
            struct smp_worker *w=&sw[i];
            seL4_UserContext r={0};
            r.rip=(unsigned long)smp_client;r.rsp=(unsigned long)(w->stack+sizeof(w->stack)-8);
            r.rdi=i;r.rflags=0x202;r.fs_base=(unsigned long)(w->tls+sizeof(w->tls)-64);
            *(unsigned long *)r.fs_base=r.fs_base;
            CK(seL4_TCB_WriteRegisters(w->tcb,1,0,20,&r));
        }
        while(__atomic_load_n(&done_mask,__ATOMIC_ACQUIRE)!=(1ul<<worker_count)-1) {
            seL4_Word badge;seL4_Wait(done_ntfn,&badge);
        }
        unsigned long first=~0ul,last=0,copy=0,map=0,del=0;
        for(unsigned i=0;i<worker_count;i++) {
            struct smp_worker *w=&sw[i];
            CK(seL4_TCB_Suspend(w->tcb));
            if(w->begin<first)first=w->begin;
            if(w->end>last)last=w->end;
            copy+=w->copy_ticks;map+=w->map_ticks;del+=w->delete_ticks;
        }
        smp_metric("Cycle",trial,last-first);
        smp_metric("CNodeCopy",trial,copy);
        smp_metric("PageMap",trial,map);
        smp_metric("CNodeDelete",trial,del);
    }
    puts_("PRIMITIVE: PASS\n");
    for(;;)seL4_Yield();
}
