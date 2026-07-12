use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bch_bindgen::accounting::data_type;
use bch_bindgen::c::{
    bch_ioctl_data, bch_ioctl_data__bindgen_ty_1__bindgen_ty_1 as ScrubArgs,
    bch_ioctl_data_event_ret, bch_ioctl_data_progress,
};
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::commands::DeviceNameArgs;
use crate::util::{fmt_bytes_human, fmt_sectors_human};
use crate::wrappers::handle::BcachefsHandle;
use crate::wrappers::ioctl::bch_ioc_w;
use crate::wrappers::sysfs::{fs_get_devices, sysfs_path_from_fd};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigint_handler(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

const BCH_IOCTL_DATA_NR: u32 = 10;
const DATA_PROGRESS_DATA_TYPE_PHYS: u8 = 254;
const DATA_EVENT_RET_ERROR: u8 = 3;
const SCRUB_CHECKPOINT_VERSION: u32 = 2;

/// bch_ioctl_data_event is blocklisted from bindgen (packed+aligned conflict),
/// so we read raw bytes and extract fields manually.
/// Layout: u8 type, u8 ret, u8 pad[6], bch_ioctl_data_progress, padding to 128.
const DATA_EVENT_SIZE: usize = 128;

#[cfg(test)]
unsafe extern "C" {
    fn bch2_scrub_validate_range(
        nr_buckets: u64,
        bucket_size: u64,
        sector_start: u64,
        sector_end: *mut u64,
        extent_bp_shift: libc::c_uint,
    ) -> libc::c_int;
}

#[derive(Serialize, Deserialize)]
struct ScrubCheckpoint {
    version: u32,
    filesystem_uuid: String,
    data_types: u32,
    devices: BTreeMap<u32, ScrubCheckpointDev>,
}

#[derive(Serialize, Deserialize)]
struct ScrubCheckpointDev {
    member_uuid: String,
    offset: u64,
    complete: bool,
}

fn new_checkpoint(filesystem_uuid: &str, data_types: u32) -> ScrubCheckpoint {
    ScrubCheckpoint {
        version: SCRUB_CHECKPOINT_VERSION,
        filesystem_uuid: filesystem_uuid.to_string(),
        data_types,
        devices: BTreeMap::new(),
    }
}

fn validate_checkpoint(
    checkpoint: &ScrubCheckpoint,
    filesystem_uuid: &str,
    data_types: u32,
) -> Result<()> {
    if checkpoint.version != SCRUB_CHECKPOINT_VERSION {
        bail!(
            "unsupported scrub checkpoint version '{}': expected '{}'",
            checkpoint.version,
            SCRUB_CHECKPOINT_VERSION,
        );
    }
    if checkpoint.filesystem_uuid != filesystem_uuid {
        bail!(
            "scrub checkpoint belongs to filesystem '{}', not '{}'",
            checkpoint.filesystem_uuid,
            filesystem_uuid,
        );
    }
    if checkpoint.data_types != data_types {
        bail!(
            "scrub checkpoint data-type mask {:#x} does not match this scrub's {:#x}",
            checkpoint.data_types,
            data_types,
        );
    }
    Ok(())
}

fn load_checkpoint(
    path: Option<&Path>,
    filesystem_uuid: &str,
    data_types: u32,
) -> Result<ScrubCheckpoint> {
    let Some(path) = path else {
        return Ok(new_checkpoint(filesystem_uuid, data_types));
    };

    match std::fs::read(path) {
        Ok(data) => {
            let checkpoint: ScrubCheckpoint = serde_json::from_slice(&data)
                .with_context(|| format!("reading scrub checkpoint '{}'", path.display()))?;
            validate_checkpoint(&checkpoint, filesystem_uuid, data_types)?;
            Ok(checkpoint)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Ok(new_checkpoint(filesystem_uuid, data_types))
        }
        Err(e) => Err(e).with_context(|| format!("opening scrub checkpoint '{}'", path.display())),
    }
}

trait CheckpointIo {
    type File: Write;

    fn open_temporary(&self, path: &Path) -> io::Result<Self::File>;
    fn sync_temporary(&self, file: &Self::File) -> io::Result<()>;
    fn replace(&self, temporary: &Path, path: &Path) -> io::Result<()>;
    fn sync_parent(&self, path: &Path) -> io::Result<()>;
}

struct StdCheckpointIo;

fn checkpoint_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

impl CheckpointIo for StdCheckpointIo {
    type File = std::fs::File;

    fn open_temporary(&self, path: &Path) -> io::Result<Self::File> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    }

    fn sync_temporary(&self, file: &Self::File) -> io::Result<()> {
        file.sync_all()
    }

    fn replace(&self, temporary: &Path, path: &Path) -> io::Result<()> {
        std::fs::rename(temporary, path)
    }

    fn sync_parent(&self, path: &Path) -> io::Result<()> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(checkpoint_parent(path))?
            .sync_all()
    }
}

fn save_checkpoint_with_io<I: CheckpointIo>(
    path: &Path,
    checkpoint: &ScrubCheckpoint,
    io: &I,
) -> Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let data = serde_json::to_vec_pretty(checkpoint)?;
    let mut file = io
        .open_temporary(&tmp)
        .with_context(|| format!("opening scrub checkpoint temporary '{}'", tmp.display()))?;
    file.write_all(&data)
        .with_context(|| format!("writing scrub checkpoint '{}'", tmp.display()))?;
    io.sync_temporary(&file)
        .with_context(|| format!("syncing scrub checkpoint '{}'", tmp.display()))?;
    io.replace(&tmp, path)
        .with_context(|| format!("replacing scrub checkpoint '{}'", path.display()))?;
    io.sync_parent(path).with_context(|| {
        format!(
            "syncing scrub checkpoint directory for '{}'",
            path.display()
        )
    })?;
    Ok(())
}

fn save_checkpoint(path: &Path, checkpoint: &ScrubCheckpoint) -> Result<()> {
    save_checkpoint_with_io(path, checkpoint, &StdCheckpointIo)
}

fn device_member_uuid(sysfs_path: &Path, dev_idx: u32) -> Result<String> {
    let path = sysfs_path.join(format!("dev-{dev_idx}/uuid"));
    let uuid = std::fs::read_to_string(&path)
        .with_context(|| format!("reading bcachefs member UUID '{}'", path.display()))?;
    let uuid = uuid.trim();
    if uuid.is_empty() {
        bail!("bcachefs member UUID '{}' is empty", path.display());
    }
    Ok(uuid.to_string())
}

fn checkpoint_device<'a>(
    checkpoint: &'a mut ScrubCheckpoint,
    dev_idx: u32,
    member_uuid: &str,
) -> Result<&'a mut ScrubCheckpointDev> {
    if let Some(device) = checkpoint.devices.get(&dev_idx) {
        if device.member_uuid != member_uuid {
            bail!(
                "scrub checkpoint device {} belongs to member '{}', not '{}'",
                dev_idx,
                device.member_uuid,
                member_uuid,
            );
        }
    }
    Ok(checkpoint
        .devices
        .entry(dev_idx)
        .or_insert_with(|| ScrubCheckpointDev {
            member_uuid: member_uuid.to_string(),
            offset: 0,
            complete: false,
        }))
}

fn checkpoint_start_sector(
    checkpoint: &mut ScrubCheckpoint,
    dev_idx: u32,
    member_uuid: &str,
) -> Result<Option<u64>> {
    let device = checkpoint_device(checkpoint, dev_idx, member_uuid)?;
    Ok((!device.complete).then_some(device.offset))
}

fn checkpoint_complete(checkpoint: &ScrubCheckpoint) -> bool {
    !checkpoint.devices.is_empty() && checkpoint.devices.values().all(|device| device.complete)
}

fn remove_checkpoint(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing scrub checkpoint '{}'", path.display())),
    }
}

fn physical_cursor_matches(data_type: u8, dev_idx: u32, cursor_dev: u64) -> bool {
    data_type == DATA_PROGRESS_DATA_TYPE_PHYS && cursor_dev == u64::from(dev_idx)
}

fn worker_error(event_ret: u8) -> bool {
    event_ret == DATA_EVENT_RET_ERROR
}

fn read_data_event(fd: &mut std::fs::File) -> io::Result<(u8, u8, bch_ioctl_data_progress)> {
    let mut buf = [0u8; DATA_EVENT_SIZE];
    let n = fd.read(&mut buf)?;
    if n != DATA_EVENT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("short read from progress fd: {} bytes", n),
        ));
    }
    let event_type = buf[0];
    let event_ret = buf[1];
    let p =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().add(8) as *const bch_ioctl_data_progress) };
    Ok((event_type, event_ret, p))
}

fn start_scrub(
    ioctl_fd: i32,
    dev_idx: u32,
    data_types: u32,
    start_sector: u64,
) -> Result<std::fs::File> {
    let mut cmd = bch_ioctl_data {
        op: bch_bindgen::c::bch_data_ops::BCH_DATA_OP_scrub as u16,
        ..Default::default()
    };
    cmd.start_pos.inode = u64::from(dev_idx);
    cmd.start_pos.offset = start_sector;
    // bch_ioctl_data's op-params union is emitted as either a native Rust union or
    // the __BindgenUnionField wrapper, depending on the host libclang's Copy analysis
    // of its blocklisted __u32 members — non-deterministic across build hosts, and
    // the wrapper's helper type isn't nameable here. Both forms share one C layout,
    // so write the scrub params positionally; the asserts pin the layout we rely on.
    const _: () = assert!(std::mem::offset_of!(ScrubArgs, dev) == 0);
    const _: () = assert!(std::mem::offset_of!(ScrubArgs, data_types) == 4);
    unsafe {
        let p = std::ptr::addr_of_mut!(cmd.__bindgen_anon_1) as *mut u32;
        p.write(dev_idx);
        p.add(1).write(data_types);
    }

    let request = bch_ioc_w::<bch_ioctl_data>(BCH_IOCTL_DATA_NR);
    let ret = unsafe { libc::ioctl(ioctl_fd, request, &mut cmd as *mut bch_ioctl_data) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(ret) })
}

struct ScrubDev {
    idx: u32,
    name: String,
    progress_fd: Option<std::fs::File>,
    member_uuid: Option<String>,
    done: u64,
    corrected: u64,
    uncorrected: u64,
    total: u64,
    ret_status: u8,
}

impl ScrubDev {
    fn format_line(&self, rate: u64) -> String {
        let pct = if self.total > 0 {
            format!("{}%", self.done * 100 / self.total)
        } else {
            "0%".to_string()
        };

        let status = if self.progress_fd.is_some() {
            format!("{}/sec", fmt_bytes_human(rate))
        } else if self.ret_status
            == bch_ioctl_data_event_ret::BCH_IOCTL_DATA_EVENT_RET_device_offline as u8
        {
            "offline".to_string()
        } else if worker_error(self.ret_status) {
            "error".to_string()
        } else {
            "complete".to_string()
        };

        format!(
            "{:<16} {:>12} {:>12} {:>12} {:>12} {:>6}  {}",
            self.name,
            fmt_sectors_human(self.done),
            fmt_sectors_human(self.corrected),
            fmt_sectors_human(self.uncorrected),
            fmt_sectors_human(self.total),
            pct,
            status
        )
    }
}

#[derive(Parser, Debug)]
#[command(about = "Verify checksums and correct errors, if possible")]
pub struct Cli {
    /// Check metadata only
    #[arg(short, long)]
    metadata: bool,

    #[command(flatten)]
    device_names: DeviceNameArgs,

    /// Filesystem path or device
    filesystem: String,

    /// Save and resume per-device scrub progress from this JSON file
    #[arg(long, value_name = "PATH")]
    checkpoint_file: Option<PathBuf>,
}

fn scrub(cli: Cli) -> Result<()> {
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }

    let data_types: u32 = if cli.metadata {
        1 << u32::from(data_type::btree)
    } else {
        !0u32
    };

    let handle = BcachefsHandle::open(&cli.filesystem)
        .with_context(|| format!("opening filesystem '{}'", cli.filesystem))?;

    let sysfs_path = sysfs_path_from_fd(handle.sysfs_fd())?;
    let name_mode = cli.device_names.name_mode();
    let devices = fs_get_devices(&sysfs_path, name_mode)?;

    let ioctl_fd = handle.ioctl_fd_raw();
    let dev_idx = handle.dev_idx();
    let filesystem_uuid = uuid::Uuid::from_bytes(handle.uuid())
        .hyphenated()
        .to_string();
    let mut checkpoint =
        load_checkpoint(cli.checkpoint_file.as_deref(), &filesystem_uuid, data_types)?;

    let mut scrub_devs: Vec<ScrubDev> = Vec::new();

    if dev_idx >= 0 {
        let idx = dev_idx as u32;
        let name = devices
            .iter()
            .find(|d| d.idx == idx)
            .map(|d| d.dev.clone())
            .unwrap_or_else(|| format!("dev-{}", dev_idx));

        let member_uuid = cli
            .checkpoint_file
            .as_ref()
            .map(|_| device_member_uuid(&sysfs_path, idx))
            .transpose()?;
        if let Some(start_sector) = member_uuid
            .as_deref()
            .map(|member_uuid| checkpoint_start_sector(&mut checkpoint, idx, member_uuid))
            .transpose()?
            .unwrap_or(Some(0))
        {
            let fd = start_scrub(ioctl_fd, idx, data_types, start_sector)?;
            scrub_devs.push(ScrubDev {
                idx,
                name,
                progress_fd: Some(fd),
                member_uuid,
                done: 0,
                corrected: 0,
                uncorrected: 0,
                total: 0,
                ret_status: 0,
            });
        }
    } else {
        for dev in &devices {
            let member_uuid = cli
                .checkpoint_file
                .as_ref()
                .map(|_| device_member_uuid(&sysfs_path, dev.idx))
                .transpose()?;
            let Some(start_sector) = member_uuid
                .as_deref()
                .map(|member_uuid| checkpoint_start_sector(&mut checkpoint, dev.idx, member_uuid))
                .transpose()?
                .unwrap_or(Some(0))
            else {
                continue;
            };
            let fd = start_scrub(ioctl_fd, dev.idx, data_types, start_sector)?;
            scrub_devs.push(ScrubDev {
                idx: dev.idx,
                name: dev.dev.clone(),
                progress_fd: Some(fd),
                member_uuid,
                done: 0,
                corrected: 0,
                uncorrected: 0,
                total: 0,
                ret_status: 0,
            });
        }
    }

    if scrub_devs.is_empty() {
        if let Some(path) = &cli.checkpoint_file {
            if checkpoint_complete(&checkpoint) {
                remove_checkpoint(path)?;
            }
            println!(
                "Scrub already complete according to checkpoint '{}'",
                path.display()
            );
        } else {
            println!("No devices selected for scrub");
        }
        return Ok(());
    }

    if let Some(path) = &cli.checkpoint_file {
        save_checkpoint(path, &checkpoint)?;
    }

    let dev_names: Vec<&str> = scrub_devs.iter().map(|d| d.name.as_str()).collect();
    println!(
        "Starting scrub on {} devices: {}",
        scrub_devs.len(),
        dev_names.join(" ")
    );

    println!(
        "{:<16} {:>12} {:>12} {:>12} {:>12} {:>6}",
        "device", "checked", "corrected", "uncorrected", "total", ""
    );

    let mut exit_code = 0i32;
    let mut last = Instant::now();
    let mut first = true;
    let live_output = io::stdout().is_terminal();

    loop {
        let now = Instant::now();
        let ns_elapsed = if first {
            0u64
        } else {
            (now - last).as_nanos() as u64
        };

        let mut all_done = true;
        let mut lines: Vec<String> = Vec::new();
        let mut checkpoint_changed = false;

        for dev in &mut scrub_devs {
            let mut rate = 0u64;

            if let Some(ref mut fd) = dev.progress_fd {
                match read_data_event(fd) {
                    Ok((event_type, event_ret, p)) => {
                        // Skip non-progress events
                        if event_type != 0 {
                            all_done = false;
                            lines.push(dev.format_line(0));
                            continue;
                        }

                        if ns_elapsed > 0 {
                            rate = p
                                .sectors_done
                                .wrapping_sub(dev.done)
                                .checked_shl(9)
                                .unwrap_or(0)
                                .saturating_mul(1_000_000_000)
                                .checked_div(ns_elapsed)
                                .unwrap_or(0);
                        }

                        dev.done = p.sectors_done;
                        dev.corrected = p.sectors_error_corrected;
                        dev.uncorrected = p.sectors_error_uncorrected;
                        dev.total = p.sectors_total;

                        if let Some(member_uuid) = dev.member_uuid.as_deref() {
                            if !physical_cursor_matches(p.data_type, dev.idx, p.pos.inode)
                                && !worker_error(event_ret)
                            {
                                bail!(
                                    "scrub progress cursor for device {} is not its physical cursor",
                                    dev.idx,
                                );
                            }
                            if physical_cursor_matches(p.data_type, dev.idx, p.pos.inode) {
                                let checkpoint_dev =
                                    checkpoint_device(&mut checkpoint, dev.idx, member_uuid)?;
                                checkpoint_dev.offset = checkpoint_dev.offset.max(p.pos.offset);
                                checkpoint_changed = true;

                                if event_ret
                                    == bch_ioctl_data_event_ret::BCH_IOCTL_DATA_EVENT_RET_done as u8
                                {
                                    checkpoint_dev.complete = true;
                                }
                            }
                        }

                        if dev.corrected > 0 {
                            exit_code |= 2;
                        }
                        if dev.uncorrected > 0 {
                            exit_code |= 4;
                        }

                        if event_ret != 0 {
                            dev.ret_status = event_ret;
                            dev.progress_fd = None;
                            if worker_error(event_ret) {
                                eprintln!("Scrub worker failed on {}", dev.name);
                                exit_code |= 1;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Reading scrub progress for {}: {e}", dev.name);
                        dev.ret_status = DATA_EVENT_RET_ERROR;
                        dev.progress_fd = None;
                        exit_code |= 1;
                    }
                }
            }

            lines.push(dev.format_line(rate));

            if dev.progress_fd.is_some() {
                all_done = false;
            }
        }

        if checkpoint_changed {
            if let Some(path) = &cli.checkpoint_file {
                save_checkpoint(path, &checkpoint)?;
            }
        }

        let interrupted = INTERRUPTED.load(Ordering::Relaxed);
        if live_output || all_done || interrupted {
            let stdout = io::stdout();
            let mut out = stdout.lock();

            if live_output && !first {
                for i in 0..scrub_devs.len() {
                    if i > 0 {
                        write!(out, "\x1b[1A")?;
                    }
                    write!(out, "\x1b[2K\r")?;
                }
            }

            for (i, line) in lines.iter().enumerate() {
                write!(out, "{}", line)?;
                if i < lines.len() - 1 {
                    writeln!(out)?;
                }
            }
            out.flush()?;
        }

        if all_done {
            writeln!(io::stdout())?;
            break;
        }

        if interrupted {
            if let Some(path) = &cli.checkpoint_file {
                save_checkpoint(path, &checkpoint)?;
            }
            writeln!(io::stdout())?;
            eprintln!("Interrupted");
            exit_code |= 1;
            break;
        }

        last = now;
        first = false;
        thread::sleep(Duration::from_secs(1));
    }

    if exit_code & 1 == 0 {
        if let Some(path) = &cli.checkpoint_file {
            if checkpoint_complete(&checkpoint) {
                remove_checkpoint(path)?;
            }
        }
    }

    if exit_code != 0 {
        process::exit(exit_code);
    }

    Ok(())
}

pub const CMD: super::CmdDef = typed_cmd!(
    "scrub",
    "Verify data checksums; affected paths are logged to dmesg",
    Cli,
    scrub
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, PartialEq)]
    enum CheckpointOperation {
        Open,
        Write,
        FileSync,
        Rename,
        DirectorySync,
    }

    struct RecordingFile {
        operations: Rc<RefCell<Vec<CheckpointOperation>>>,
    }

    impl Write for RecordingFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.operations
                .borrow_mut()
                .push(CheckpointOperation::Write);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct RecordingCheckpointIo {
        operations: Rc<RefCell<Vec<CheckpointOperation>>>,
    }

    impl CheckpointIo for RecordingCheckpointIo {
        type File = RecordingFile;

        fn open_temporary(&self, _: &Path) -> io::Result<Self::File> {
            self.operations.borrow_mut().push(CheckpointOperation::Open);
            Ok(RecordingFile {
                operations: Rc::clone(&self.operations),
            })
        }

        fn sync_temporary(&self, _: &Self::File) -> io::Result<()> {
            self.operations
                .borrow_mut()
                .push(CheckpointOperation::FileSync);
            Ok(())
        }

        fn replace(&self, _: &Path, _: &Path) -> io::Result<()> {
            self.operations
                .borrow_mut()
                .push(CheckpointOperation::Rename);
            Ok(())
        }

        fn sync_parent(&self, _: &Path) -> io::Result<()> {
            self.operations
                .borrow_mut()
                .push(CheckpointOperation::DirectorySync);
            Ok(())
        }
    }

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "bcachefs-scrub-checkpoint-{}-{}-{}",
                std::process::id(),
                name,
                nonce
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn checkpoint_rejects_mismatched_filesystem_or_mode() {
        let checkpoint = new_checkpoint("filesystem-a", 0x1);
        assert!(validate_checkpoint(&checkpoint, "filesystem-b", 0x1).is_err());
        assert!(validate_checkpoint(&checkpoint, "filesystem-a", 0x2).is_err());
    }

    #[test]
    fn checkpoint_rejects_replaced_member_at_same_index() {
        let mut checkpoint = new_checkpoint("filesystem-a", 0x1);
        checkpoint_device(&mut checkpoint, 3, "member-a")
            .unwrap()
            .offset = 4096;
        assert!(checkpoint_device(&mut checkpoint, 3, "member-b").is_err());
    }

    #[test]
    fn checkpoint_resumes_saved_cursor() {
        let mut checkpoint = new_checkpoint("filesystem-a", 0x1);
        checkpoint_device(&mut checkpoint, 3, "member-a")
            .unwrap()
            .offset = 4096;
        assert_eq!(
            checkpoint_device(&mut checkpoint, 3, "member-a")
                .unwrap()
                .offset,
            4096
        );
    }

    #[test]
    fn checkpoint_skips_completed_devices_but_keeps_partial_work() {
        let mut checkpoint = new_checkpoint("filesystem-a", 0x1);
        checkpoint_device(&mut checkpoint, 1, "member-a")
            .unwrap()
            .complete = true;
        checkpoint_device(&mut checkpoint, 2, "member-b")
            .unwrap()
            .offset = 4096;

        assert_eq!(
            checkpoint_start_sector(&mut checkpoint, 1, "member-a").unwrap(),
            None
        );
        assert_eq!(
            checkpoint_start_sector(&mut checkpoint, 2, "member-b").unwrap(),
            Some(4096)
        );
        assert!(!checkpoint_complete(&checkpoint));
    }

    #[test]
    fn checkpoint_detects_all_completed_devices() {
        let mut checkpoint = new_checkpoint("filesystem-a", 0x1);
        checkpoint_device(&mut checkpoint, 1, "member-a")
            .unwrap()
            .complete = true;
        checkpoint_device(&mut checkpoint, 2, "member-b")
            .unwrap()
            .complete = true;
        assert!(checkpoint_complete(&checkpoint));
    }

    #[test]
    fn worker_error_is_not_success_and_nonphysical_progress_is_rejected() {
        assert!(worker_error(DATA_EVENT_RET_ERROR));
        assert!(!worker_error(
            bch_ioctl_data_event_ret::BCH_IOCTL_DATA_EVENT_RET_done as u8
        ));
        assert!(!physical_cursor_matches(DATA_PROGRESS_DATA_TYPE_PHYS, 2, 3));
        assert!(!physical_cursor_matches(0, 2, 2));
        assert!(physical_cursor_matches(DATA_PROGRESS_DATA_TYPE_PHYS, 2, 2));
    }

    #[test]
    fn checkpoint_save_orders_file_and_directory_durability() {
        let operations = Rc::new(RefCell::new(Vec::new()));
        let io = RecordingCheckpointIo {
            operations: Rc::clone(&operations),
        };

        save_checkpoint_with_io(Path::new("checkpoint.json"), &new_checkpoint("fs", 1), &io)
            .unwrap();

        assert_eq!(
            *operations.borrow(),
            vec![
                CheckpointOperation::Open,
                CheckpointOperation::Write,
                CheckpointOperation::FileSync,
                CheckpointOperation::Rename,
                CheckpointOperation::DirectorySync,
            ]
        );
    }

    #[test]
    fn checkpoint_sync_uses_current_directory_for_a_relative_path() {
        assert_eq!(
            checkpoint_parent(Path::new("checkpoint.json")),
            Path::new(".")
        );
    }

    #[test]
    fn checkpoint_save_and_load_use_an_isolated_directory() {
        let dir = TestTempDir::new("save-load");
        let path = dir.path().join("checkpoint.json");
        let mut checkpoint = new_checkpoint("filesystem-a", 1);
        checkpoint_device(&mut checkpoint, 3, "member-a")
            .unwrap()
            .offset = 4096;

        save_checkpoint(&path, &checkpoint).unwrap();

        assert!(path.is_file());
        assert!(!path.with_extension("json.tmp").exists());
        let loaded = load_checkpoint(Some(&path), "filesystem-a", 1).unwrap();
        assert_eq!(
            loaded.devices.get(&3).unwrap().offset,
            4096,
            "real save/load must retain the accepted physical cursor"
        );
    }

    #[test]
    fn production_scrub_range_validator_rejects_shift_overflow_boundaries() {
        let max_shift_safe = u64::MAX >> 1;

        let mut maximum_safe_end = max_shift_safe;
        assert_eq!(
            unsafe {
                bch2_scrub_validate_range(
                    max_shift_safe,
                    1,
                    max_shift_safe - 1,
                    &mut maximum_safe_end,
                    1,
                )
            },
            0,
            "maximum shift-safe sector start/end must succeed"
        );

        let mut shifted_end_overflow = max_shift_safe + 1;
        assert_eq!(
            unsafe {
                bch2_scrub_validate_range(max_shift_safe + 1, 1, 1, &mut shifted_end_overflow, 1)
            },
            -libc::ERANGE,
            "multiplication-valid shifted sector end overflow must fail"
        );

        let mut shifted_start_overflow = max_shift_safe + 2;
        assert_eq!(
            unsafe {
                bch2_scrub_validate_range(
                    max_shift_safe + 2,
                    1,
                    max_shift_safe + 1,
                    &mut shifted_start_overflow,
                    1,
                )
            },
            -libc::ERANGE,
            "shifted sector start overflow must fail before the end shift"
        );
    }
}
