//! virtio-gpu, 2D, one scanout (DESIGN.md §8.6).  A resource's content is
//! its backing, which lies in the guest's I/O pool like every buffer of a
//! virtio-l4h device: the guest's DMA layer copies a buffer there when the
//! driver transfers it to the host, so TRANSFER_TO_HOST_2D has nothing
//! left to copy.  RESOURCE_FLUSH copies the flushed rectangle of the
//! resource on the scanout into the display area (l4h_host::gpu), the one
//! image the host keeps, from which l4h-root serves dom0.  Commands
//! complete at once, in order, fences included.

use core::sync::atomic::{Ordering, fence};

use l4h_rt::host::fixed::ArrayVec;
use l4h_rt::host::gpu::{DisplayHeader, IMAGE_OFFSET, STATE_PAGES, VMM_GPU_STATE_VA, display_pages, image_bytes};

use crate::dev::Backend;
use crate::guest::GuestMem;
use crate::virtq::{Buf, Queue};

const VIRTIO_ID_GPU: u32 = 16;
const QUEUE_SIZE: u32 = 64;
const CONTROLQ: usize = 0;

const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;

const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const RESP_ERR_UNSPEC: u32 = 0x1200;
const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
const RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
const RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
const RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

const FLAG_FENCE: u32 = 1 << 0;
const FLAG_INFO_RING_IDX: u32 = 1 << 1;

const HDR: usize = 24;
const MAX_SCANOUTS: usize = 16;

/// The formats of 4 bytes a pixel (VIRTIO_GPU_FORMAT_*), all there are.
const FORMATS: [u32; 8] = [1, 2, 3, 4, 67, 68, 121, 134];
/// The largest resource: what the largest scanout needs, twice.
const MAX_RESOURCE_BYTES: u64 = 2 * image_bytes(l4h_abi::GPU_MAX_WIDTH, l4h_abi::GPU_MAX_HEIGHT) as u64;

const MAX_RESOURCES: usize = 1024;
const MAX_ENTRIES: usize = 65536;

#[derive(Clone, Copy)]
#[repr(C)]
struct Resource {
    /// 0: free.
    id: u32,
    format: u32,
    width: u32,
    height: u32,
    /// Its backing: entries [first, first + count) (count 0: none).
    first: u32,
    count: u32,
    /// Bytes of backing.
    bytes: u64,
}

/// A piece of backing: `len` bytes at `gpa`, from byte `off` of it.
#[derive(Clone, Copy)]
#[repr(C)]
struct Entry {
    gpa: u64,
    off: u32,
    len: u32,
}

/// In the frames at VMM_GPU_STATE_VA.
#[repr(C)]
struct Tables {
    res: [Resource; MAX_RESOURCES],
    ents: [Entry; MAX_ENTRIES],
    nr_ents: usize,
}
const _: () = assert!(core::mem::size_of::<Tables>() <= STATE_PAGES * 4096);

#[derive(Clone, Copy, Default)]
struct Rect {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

impl Rect {
    fn parse(b: &[u8]) -> Rect {
        Rect { x: le32(b, 0), y: le32(b, 4), w: le32(b, 8), h: le32(b, 12) }
    }

    /// Within a width x height resource?
    fn within(&self, width: u32, height: u32) -> bool {
        self.x as u64 + self.w as u64 <= width as u64 && self.y as u64 + self.h as u64 <= height as u64
    }

    fn intersect(&self, o: &Rect) -> Option<Rect> {
        let x0 = self.x.max(o.x);
        let y0 = self.y.max(o.y);
        let x1 = (self.x as u64 + self.w as u64).min(o.x as u64 + o.w as u64);
        let y1 = (self.y as u64 + self.h as u64).min(o.y as u64 + o.h as u64);
        (x1 > x0 as u64 && y1 > y0 as u64).then(|| Rect { x: x0, y: y0, w: (x1 - x0 as u64) as u32, h: (y1 - y0 as u64) as u32 })
    }
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// A chain's buffers as two byte streams: the request the driver wrote
/// (its readable buffers, in order) and the response (its writable ones).
struct Msg<'a> {
    mem: &'a GuestMem,
    bufs: &'a [Buf],
}

impl Msg<'_> {
    /// Copy request bytes from `off` into `out`; false if there are fewer.
    /// The driver may change them meanwhile: they are read once, here.
    fn read(&self, mut off: usize, out: &mut [u8]) -> bool {
        let mut done = 0;
        for b in self.bufs.iter().filter(|b| !b.write) {
            let len = b.len as usize;
            if off >= len {
                off -= len;
                continue;
            }
            let n = (len - off).min(out.len() - done);
            for i in 0..n {
                out[done + i] = self.mem.read::<u8>(b.gpa + (off + i) as u64);
            }
            done += n;
            off = 0;
            if done == out.len() {
                return true;
            }
        }
        done == out.len()
    }

    /// Write the response; returns the bytes written (all of it, or as
    /// much as the buffers hold).
    fn write(&self, data: &[u8]) -> u32 {
        let mut done = 0;
        for b in self.bufs.iter().filter(|b| b.write) {
            let n = (b.len as usize).min(data.len() - done);
            for i in 0..n {
                self.mem.write::<u8>(b.gpa + i as u64, data[done + i]);
            }
            done += n;
            if done == data.len() {
                break;
            }
        }
        done as u32
    }
}

pub struct Gpu {
    t: &'static mut Tables,
    display: usize,
    width: u32,
    height: u32,
    /// The resource on the scanout and the rectangle of it shown.
    scanout: Option<(u32, Rect)>,
}

impl Gpu {
    /// The display area is `size` bytes at `display_va` (a header, then
    /// the image), for a scanout of `width` x `height`.
    pub fn new(display_va: usize, size: u64, width: u32, height: u32) -> Self {
        assert!(size as usize >= display_pages(width, height) * 4096, "l4h-vmm: GPU display area too small");
        let mut g = Gpu {
            t: unsafe { &mut *(VMM_GPU_STATE_VA as *mut Tables) },
            display: display_va,
            width,
            height,
            scanout: None,
        };
        g.reset();
        g
    }

    fn header(&self) -> &DisplayHeader {
        unsafe { &*(self.display as *const DisplayHeader) }
    }

    /// Begin and end an update of the display area (a seqlock with
    /// l4h-root, which reads it).
    fn begin(&self) {
        let h = self.header();
        h.frame.store(h.frame.load(Ordering::Relaxed) | 1, Ordering::Relaxed);
        fence(Ordering::Release);
    }

    fn end(&self) {
        let h = self.header();
        h.frame.store(h.frame.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
    }

    /// What the display shows: a resource of `format`, whose flushes
    /// paint it, or nothing (black, format 0).
    fn show(&self, format: Option<u32>) {
        self.begin();
        unsafe {
            if format.is_none() {
                core::ptr::write_bytes((self.display + IMAGE_OFFSET) as *mut u8, 0, image_bytes(self.width, self.height));
            }
            let h = self.display as *mut DisplayHeader;
            core::ptr::addr_of_mut!((*h).format).write_volatile(format.unwrap_or(0));
        }
        self.end();
    }

    fn find(&self, id: u32) -> Option<usize> {
        if id == 0 {
            return None;
        }
        self.t.res.iter().position(|r| r.id == id)
    }

    fn detach(&mut self, i: usize) {
        let (first, count) = (self.t.res[i].first as usize, self.t.res[i].count as usize);
        if count != 0 {
            let n = self.t.nr_ents;
            self.t.ents.copy_within(first + count..n, first);
            self.t.nr_ents = n - count;
            for r in self.t.res.iter_mut() {
                if r.count != 0 && r.first as usize > first {
                    r.first -= count as u32;
                }
            }
        }
        let r = &mut self.t.res[i];
        r.first = 0;
        r.count = 0;
        r.bytes = 0;
    }

    /// Copy `out.len()` bytes of resource `i`'s backing from byte `off`.
    fn copy_out(&self, mem: &GuestMem, i: usize, mut off: u64, out: *mut u8, len: usize) {
        let r = &self.t.res[i];
        let ents = &self.t.ents[r.first as usize..(r.first + r.count) as usize];
        // The entry holding `off`: the last that starts at or before it.
        let mut e = ents.partition_point(|e| e.off as u64 <= off).saturating_sub(1);
        let mut done = 0;
        while done < len && e < ents.len() {
            let ent = ents[e];
            let skip = off - ent.off as u64;
            let n = ((ent.len as u64 - skip) as usize).min(len - done);
            let src = mem.bytes(ent.gpa + skip, n);
            unsafe { core::ptr::copy_nonoverlapping(src, out.add(done), n) };
            done += n;
            off += n as u64;
            e += 1;
        }
    }

    /// Put rectangle `fr` of resource `i` (its id is on the scanout) on
    /// the display.
    fn present(&self, mem: &GuestMem, i: usize, fr: &Rect) {
        let Some((_, so)) = self.scanout else { return };
        let shown = Rect { x: so.x, y: so.y, w: so.w.min(self.width), h: so.h.min(self.height) };
        let Some(r) = fr.intersect(&shown) else { return };
        let res = &self.t.res[i];
        if res.count == 0 {
            return;
        }
        self.begin();
        for y in r.y..r.y + r.h {
            let src = (y as u64 * res.width as u64 + r.x as u64) * 4;
            let dst = IMAGE_OFFSET + (((y - so.y) as usize * self.width as usize) + (r.x - so.x) as usize) * 4;
            self.copy_out(mem, i, src, (self.display + dst) as *mut u8, r.w as usize * 4);
        }
        self.end();
    }

    /// Run one command; returns the response type and the bytes after
    /// its header (GET_DISPLAY_INFO).
    fn command(&mut self, mem: &GuestMem, m: &Msg, ty: u32, extra: &mut [u8; MAX_SCANOUTS * 24]) -> (u32, usize) {
        let mut b = [0u8; 64];
        match ty {
            CMD_GET_DISPLAY_INFO => {
                extra.fill(0);
                // pmodes[0]: r = (0, 0, width, height), enabled.
                extra[8..12].copy_from_slice(&self.width.to_le_bytes());
                extra[12..16].copy_from_slice(&self.height.to_le_bytes());
                extra[16..20].copy_from_slice(&1u32.to_le_bytes());
                (RESP_OK_DISPLAY_INFO, extra.len())
            }
            CMD_RESOURCE_CREATE_2D => {
                if !m.read(HDR, &mut b[..16]) {
                    return (RESP_ERR_UNSPEC, 0);
                }
                let (id, format, width, height) = (le32(&b, 0), le32(&b, 4), le32(&b, 8), le32(&b, 12));
                if id == 0 || self.find(id).is_some() {
                    return (RESP_ERR_INVALID_RESOURCE_ID, 0);
                }
                if !FORMATS.contains(&format) || width == 0 || height == 0
                    || width as u64 * height as u64 * 4 > MAX_RESOURCE_BYTES
                {
                    return (RESP_ERR_INVALID_PARAMETER, 0);
                }
                let Some(slot) = self.t.res.iter().position(|r| r.id == 0) else {
                    return (RESP_ERR_OUT_OF_MEMORY, 0);
                };
                self.t.res[slot] = Resource { id, format, width, height, first: 0, count: 0, bytes: 0 };
                (RESP_OK_NODATA, 0)
            }
            CMD_RESOURCE_UNREF => {
                if !m.read(HDR, &mut b[..4]) {
                    return (RESP_ERR_UNSPEC, 0);
                }
                let id = le32(&b, 0);
                let Some(i) = self.find(id) else { return (RESP_ERR_INVALID_RESOURCE_ID, 0) };
                if self.scanout.is_some_and(|(s, _)| s == id) {
                    self.scanout = None;
                    self.show(None);
                }
                self.detach(i);
                self.t.res[i].id = 0;
                (RESP_OK_NODATA, 0)
            }
            CMD_RESOURCE_ATTACH_BACKING => {
                if !m.read(HDR, &mut b[..8]) {
                    return (RESP_ERR_UNSPEC, 0);
                }
                let (id, n) = (le32(&b, 0), le32(&b, 4) as usize);
                let Some(i) = self.find(id) else { return (RESP_ERR_INVALID_RESOURCE_ID, 0) };
                if self.t.res[i].count != 0 || n == 0 {
                    return (RESP_ERR_UNSPEC, 0);
                }
                if n > MAX_ENTRIES - self.t.nr_ents {
                    return (RESP_ERR_OUT_OF_MEMORY, 0);
                }
                let start = self.t.nr_ents;
                let mut at = start;
                let mut total: u64 = 0;
                for k in 0..n {
                    if !m.read(HDR + 8 + 16 * k, &mut b[..12]) {
                        return (RESP_ERR_UNSPEC, 0);
                    }
                    let (gpa, len) = (le64(&b, 0), le32(&b, 8));
                    if len == 0 || !mem.valid(gpa, len as u64) || total + len as u64 > u32::MAX as u64 {
                        return (RESP_ERR_INVALID_PARAMETER, 0);
                    }
                    // Merge pieces that continue the last one.
                    match self.t.ents[start..at].last_mut() {
                        Some(e) if e.gpa + e.len as u64 == gpa => e.len += len,
                        _ => {
                            if at == MAX_ENTRIES {
                                return (RESP_ERR_OUT_OF_MEMORY, 0);
                            }
                            self.t.ents[at] = Entry { gpa, off: total as u32, len };
                            at += 1;
                        }
                    }
                    total += len as u64;
                }
                let r = &mut self.t.res[i];
                if total < r.width as u64 * r.height as u64 * 4 {
                    return (RESP_ERR_INVALID_PARAMETER, 0);
                }
                r.first = start as u32;
                r.count = (at - start) as u32;
                r.bytes = total;
                self.t.nr_ents = at;
                (RESP_OK_NODATA, 0)
            }
            CMD_RESOURCE_DETACH_BACKING => {
                if !m.read(HDR, &mut b[..4]) {
                    return (RESP_ERR_UNSPEC, 0);
                }
                let Some(i) = self.find(le32(&b, 0)) else { return (RESP_ERR_INVALID_RESOURCE_ID, 0) };
                self.detach(i);
                (RESP_OK_NODATA, 0)
            }
            CMD_SET_SCANOUT => {
                if !m.read(HDR, &mut b[..24]) {
                    return (RESP_ERR_UNSPEC, 0);
                }
                let (r, scanout, id) = (Rect::parse(&b), le32(&b, 16), le32(&b, 20));
                if scanout != 0 {
                    return (RESP_ERR_INVALID_SCANOUT_ID, 0);
                }
                if id == 0 {
                    self.scanout = None;
                    self.show(None);
                    return (RESP_OK_NODATA, 0);
                }
                let Some(i) = self.find(id) else { return (RESP_ERR_INVALID_RESOURCE_ID, 0) };
                let res = self.t.res[i];
                if r.w == 0 || r.h == 0 || !r.within(res.width, res.height) {
                    return (RESP_ERR_INVALID_PARAMETER, 0);
                }
                if self.scanout.is_none_or(|(s, _)| s != id) {
                    self.show(Some(res.format));
                }
                self.scanout = Some((id, r));
                (RESP_OK_NODATA, 0)
            }
            CMD_TRANSFER_TO_HOST_2D => {
                if !m.read(HDR, &mut b[..32]) {
                    return (RESP_ERR_UNSPEC, 0);
                }
                let (r, offset) = (Rect::parse(&b), le64(&b, 16));
                let Some(i) = self.find(le32(&b, 24)) else { return (RESP_ERR_INVALID_RESOURCE_ID, 0) };
                let res = self.t.res[i];
                if res.count == 0 || !r.within(res.width, res.height) {
                    return (RESP_ERR_INVALID_PARAMETER, 0);
                }
                // The rectangle is already in the backing; it only has to
                // be there.
                if r.w != 0 && r.h != 0 {
                    let last = (r.h as u64 - 1) * res.width as u64 * 4 + r.w as u64 * 4;
                    if offset.checked_add(last).is_none_or(|end| end > res.bytes) {
                        return (RESP_ERR_INVALID_PARAMETER, 0);
                    }
                }
                (RESP_OK_NODATA, 0)
            }
            CMD_RESOURCE_FLUSH => {
                if !m.read(HDR, &mut b[..20]) {
                    return (RESP_ERR_UNSPEC, 0);
                }
                let (r, id) = (Rect::parse(&b), le32(&b, 16));
                let Some(i) = self.find(id) else { return (RESP_ERR_INVALID_RESOURCE_ID, 0) };
                let res = self.t.res[i];
                if !r.within(res.width, res.height) {
                    return (RESP_ERR_INVALID_PARAMETER, 0);
                }
                if self.scanout.is_some_and(|(s, _)| s == id) {
                    self.present(mem, i, &r);
                }
                (RESP_OK_NODATA, 0)
            }
            _ => (RESP_ERR_UNSPEC, 0),
        }
    }

    /// Handle one chain; returns the bytes written.
    fn handle(&mut self, mem: &GuestMem, q: usize, bufs: &[Buf]) -> u32 {
        let m = Msg { mem, bufs };
        let mut hdr = [0u8; HDR];
        if !m.read(0, &mut hdr) {
            return 0;
        }
        // The cursor queue: there is no cursor plane, and no response.
        if q != CONTROLQ {
            return 0;
        }
        let mut extra = [0u8; MAX_SCANOUTS * 24];
        let (ty, n) = self.command(mem, &m, le32(&hdr, 0), &mut extra);
        let mut resp = [0u8; HDR + MAX_SCANOUTS * 24];
        let flags = le32(&hdr, 4);
        resp[0..4].copy_from_slice(&ty.to_le_bytes());
        if flags & FLAG_FENCE != 0 {
            // The fence is done with the command.
            resp[4..8].copy_from_slice(&(flags & (FLAG_FENCE | FLAG_INFO_RING_IDX)).to_le_bytes());
            resp[8..20].copy_from_slice(&hdr[8..20]);
            if flags & FLAG_INFO_RING_IDX != 0 {
                resp[20] = hdr[20];
            }
        }
        resp[HDR..HDR + n].copy_from_slice(&extra[..n]);
        m.write(&resp[..HDR + n])
    }
}

impl Backend for Gpu {
    fn device_id(&self) -> u32 {
        VIRTIO_ID_GPU
    }

    fn features(&self) -> u64 {
        0
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn queue_max(&self, _q: usize) -> u32 {
        QUEUE_SIZE
    }

    fn init_config(&self, config: &mut [u8]) {
        // events_read, events_clear, num_scanouts, num_capsets.
        config[8..12].copy_from_slice(&1u32.to_le_bytes());
    }

    fn kick(&mut self, mem: &GuestMem, queues: &mut [Queue], q: usize) -> bool {
        let mut any = false;
        let mut bufs = ArrayVec::<Buf, { QUEUE_SIZE as usize }>::new();
        while let Some(head) = queues[q].pop(mem) {
            let n = if queues[q].chain(mem, head, &mut bufs).is_ok() { self.handle(mem, q, &bufs) } else { 0 };
            queues[q].push(mem, head, n);
            any = true;
        }
        any
    }

    fn complete(&mut self, _mem: &GuestMem, _queues: &mut [Queue]) -> bool {
        false
    }

    fn reset(&mut self) {
        for r in self.t.res.iter_mut() {
            *r = Resource { id: 0, format: 0, width: 0, height: 0, first: 0, count: 0, bytes: 0 };
        }
        self.t.nr_ents = 0;
        self.scanout = None;
        self.show(None);
    }
}
