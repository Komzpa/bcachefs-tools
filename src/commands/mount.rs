use std::{
    ffi::{CString, OsString},
    io::{stdout, IsTerminal},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Component, Path, PathBuf},
    ptr, str,
};

use anyhow::{bail, ensure, Context, Result};
use bcachefs_kernel::c::bch_sb_handle;
use bcachefs_kernel::path_to_cstr;
use clap::Parser;
use log::{debug, error, info};
use crate::device_scan;

use crate::{
    key::{KeyHandle, KeySearchError, Keyring, Passphrase, UnlockPolicy},
    logging,
};

const MOUNT_KEYRING: Keyring = Keyring::Session;

fn mount_inner(
    src: OsString,
    target: &std::path::Path,
    fstype: Option<&str>,
    mut mountflags: libc::c_ulong,
    data: Option<String>,
) -> anyhow::Result<()> {
    // bind the CStrings to keep them alive
    let c_src = CString::new(src.clone().into_vec())?;
    let c_target = path_to_cstr(target);
    let data = data.map(CString::new).transpose()?;
    let fstype = fstype.map(CString::new).transpose()?;

    // convert to pointers for ffi
    let c_src = c_src.as_ptr();
    let c_target = c_target.as_ptr();
    let data_ptr = data.as_ref().map_or(ptr::null(), |data| data.as_ptr().cast());
    let fstype = fstype
        .as_ref()
        .map_or(ptr::null(), |fstype| fstype.as_ptr());

    let mut ret;
    loop {
        ret = {
            info!("mounting filesystem");
            // REQUIRES: CAP_SYS_ADMIN
            unsafe { libc::mount(c_src, c_target, fstype, mountflags, data_ptr) }
        };

        let err = errno::errno().0;

        if ret == 0
            || (err != libc::EACCES && err != libc::EROFS)
            || (mountflags & libc::MS_RDONLY) != 0
        {
            break;
        }

        println!("mount: device write-protected, mounting read-only");
        mountflags |= libc::MS_RDONLY;
    }

    drop(data);

    if ret != 0 {
        let err = errno::errno();
        let e = crate::ErrnoError(err);

        if err.0 == libc::EBUSY {
            eprintln!("mount: {}: {:?} already mounted or mount point busy", target.to_string_lossy(), src);
        } else {
            eprintln!("mount: {:?}: {}", src, e);
        }

        Err(e.into())
    } else {
        Ok(())
    }
}

struct TempMount {
    path: PathBuf,
    root: Option<std::fs::File>,
    mounted: bool,
    cleaned: bool,
}

impl TempMount {
    fn new() -> Result<Self> {
        let base = Path::new("/run/mount");
        let base = if base.is_dir() {
            base
        } else {
            Path::new("/tmp")
        };
        let pid = std::process::id();

        for i in 0..1000 {
            let path = base.join(format!("bcachefs-subvol.{pid}.{i}"));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        root: None,
                        mounted: false,
                        cleaned: false,
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
            }
        }

        bail!(
            "could not create temporary mountpoint under {}",
            base.display()
        )
    }

    fn umount(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }

        if self.mounted {
            let c_path = path_to_cstr(&self.path);
            let ret = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
            if ret != 0 {
                return Err(crate::ErrnoError(errno::errno()).into());
            }
            self.mounted = false;
        }

        drop(self.root.take());
        std::fs::remove_dir(&self.path)
            .with_context(|| format!("removing {}", self.path.display()))?;
        self.cleaned = true;
        Ok(())
    }

    fn open_root(&mut self) -> Result<()> {
        self.root = Some(
            std::fs::File::open(&self.path)
                .with_context(|| format!("opening mounted root {}", self.path.display()))?,
        );
        Ok(())
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        if let Err(e) = self.umount() {
            error!("could not clean up temporary bcachefs subvolume mount: {e:#}");
        }
    }
}

fn parse_subvol_path(path: &str) -> Result<PathBuf> {
    let path = path.trim_start_matches('/');
    ensure!(!path.is_empty(), "subvol= path must not be empty");

    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => bail!("subvol= path must not contain '..'"),
            Component::RootDir | Component::Prefix(_) => {
                bail!("subvol= path must be relative to the filesystem root")
            }
        }
    }

    ensure!(
        !normalized.as_os_str().is_empty(),
        "subvol= path must not be empty"
    );
    Ok(normalized)
}

/// Separate the mount-helper-only subvolume selector before handing the
/// remaining options to the parser shared with the FUSE mount path.
fn parse_subvol_mount_options(options: impl AsRef<str>) -> Result<(String, Option<PathBuf>)> {
    let mut remaining = Vec::new();
    let mut subvol = None;
    let mut subvol_seen = false;

    for opt in options.as_ref().split(',') {
        if let Some(path) = opt.strip_prefix("subvol=") {
            ensure!(!subvol_seen, "subvol= specified more than once");
            subvol_seen = true;
            subvol = Some(parse_subvol_path(path)?);
        } else {
            remaining.push(opt);
        }
    }

    Ok((remaining.join(","), subvol))
}

fn reject_fuse_subvol_option(options: &str) -> Result<()> {
    let (_, subvol) = parse_subvol_mount_options(options)?;
    ensure!(
        subvol.is_none(),
        "subvol= is not supported with bcachefs.fuse"
    );
    Ok(())
}

/// A comma-separated mount option string split into its consumers.
///
/// The same option vocabulary feeds three places - the mount(2) syscall
/// (`flags`), the FUSE mount (`fuse_options`), and the filesystem itself
/// (`fs_opts`, handed to parse_mount_opts later) - so it's tabulated once in
/// [`parse_mountflag_options`] rather than re-derived per caller.
#[derive(Default)]
pub(crate) struct ParsedMountOptions {
    /// Filesystem-specific options: everything not consumed as a kernel flag.
    pub fs_opts:      Option<String>,
    /// Kernel mount flags for mount(2).
    pub flags:        libc::c_ulong,
    /// `flags` expressed as fuser options, for the FUSE path. Flags with no
    /// fuser equivalent are omitted here but still apply via `flags`.
    #[cfg(feature = "fuse")]
    pub fuse_options: Vec<fuser::MountOption>,
}

/// Parse a comma-separated mount option string, splitting kernel mount flags
/// (and their fuser equivalents) from filesystem-specific options.
pub(crate) fn parse_mountflag_options(options: impl AsRef<str>) -> ParsedMountOptions {
    debug!("parsing mount options: {}", options.as_ref());

    let mut parsed = ParsedMountOptions::default();
    let mut fs_opts: Vec<&str> = Vec::new();

    // A kernel flag, optionally paired with its fuser option. The fuser arm is
    // only referenced under the `fuse` feature, so its tokens must live inside
    // the cfg - hence the macro rather than a plain match value.
    macro_rules! flag {
        ($ms:expr) => {{ parsed.flags |= $ms; }};
        ($ms:expr, $fuse:expr) => {{
            parsed.flags |= $ms;
            #[cfg(feature = "fuse")]
            parsed.fuse_options.push($fuse);
        }};
    }

    for opt in options.as_ref().split(',') {
        match opt {
            "dirsync"     => flag!(libc::MS_DIRSYNC, fuser::MountOption::DirSync),
            "lazytime"    => flag!(1 << 25), // MS_LAZYTIME
            "mand"        => flag!(libc::MS_MANDLOCK),
            "noatime"     => flag!(libc::MS_NOATIME, fuser::MountOption::NoAtime),
            "nodev"       => flag!(libc::MS_NODEV, fuser::MountOption::NoDev),
            "nodiratime"  => flag!(libc::MS_NODIRATIME),
            "noexec"      => flag!(libc::MS_NOEXEC, fuser::MountOption::NoExec),
            "nosuid"      => flag!(libc::MS_NOSUID, fuser::MountOption::NoSuid),
            "relatime"    => flag!(libc::MS_RELATIME),
            "remount"     => flag!(libc::MS_REMOUNT),
            "ro"          => flag!(libc::MS_RDONLY, fuser::MountOption::RO),
            "rw" | ""     => {}
            "strictatime" => flag!(libc::MS_STRICTATIME),
            "sync"        => flag!(libc::MS_SYNCHRONOUS, fuser::MountOption::Sync),
            // Userspace-only fstab options - not passed to the kernel:
            "auto" | "noauto" | "nofail" | "_netdev"
            | "user" | "nouser" | "users" | "group" | "owner" => {}
            o if o.starts_with("x-") || o.starts_with("X-") || o.starts_with("comment=") => {}
            o => fs_opts.push(o),
        }
    }

    parsed.fs_opts = (!fs_opts.is_empty()).then(|| fs_opts.join(","));
    parsed
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;
const SUBTREE_RESOLVE_FLAGS: u64 = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_subtree_at(root: &std::fs::File, subvol: &Path) -> Result<OwnedFd> {
    let path = CString::new(subvol.as_os_str().as_bytes())?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: SUBTREE_RESOLVE_FLAGS,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as libc::c_int;

    if fd < 0 {
        return Err(crate::ErrnoError(errno::errno()).into());
    }

    // SAFETY: openat2 returned this newly-owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_subtree(tmp: &TempMount, subvol: &Path) -> Result<OwnedFd> {
    let root = tmp
        .root
        .as_ref()
        .context("temporary mount root is not open")?;
    open_subtree_at(root, subvol)
}

fn unmount_bind_target(target: &Path) -> Result<()> {
    let target = path_to_cstr(target);
    if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(crate::ErrnoError(errno::errno()).into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupAction {
    KeepTarget,
    RollBackTarget,
}

fn cleanup_action(target_bound: bool, cleanup_succeeded: bool) -> CleanupAction {
    if target_bound && !cleanup_succeeded {
        CleanupAction::RollBackTarget
    } else {
        CleanupAction::KeepTarget
    }
}

fn finish_subtree_mount(
    operation: Result<()>,
    tmp: &mut TempMount,
    target: &Path,
    target_bound: bool,
) -> Result<()> {
    match tmp.umount() {
        Ok(()) => operation,
        Err(cleanup) => {
            if cleanup_action(target_bound, false) == CleanupAction::RollBackTarget {
                if let Err(rollback) = unmount_bind_target(target) {
                    bail!(
                        "temporary mount cleanup failed after binding {}: {cleanup:#}; \
                         rollback of the target bind also failed: {rollback:#}",
                        target.display()
                    );
                }
            }

            match operation {
                Ok(()) => Err(cleanup.context("temporary mount cleanup failed")),
                Err(operation) => {
                    Err(operation
                        .context(format!("temporary mount cleanup also failed: {cleanup:#}")))
                }
            }
        }
    }
}

fn mount_subtree(
    src: OsString,
    target: &Path,
    mountflags: libc::c_ulong,
    data: Option<String>,
    subvol: &Path,
) -> Result<()> {
    let mut tmp = TempMount::new()?;
    let mut target_bound = false;
    let operation = (|| -> Result<()> {
        mount_inner(src, &tmp.path, Some("bcachefs"), mountflags, data)?;
        tmp.mounted = true;
        tmp.open_root()?;

        let subtree = open_subtree(&tmp, subvol)
            .with_context(|| format!("opening subtree path {}", subvol.display()))?;
        let source = format!("/proc/self/fd/{}", subtree.as_raw_fd());
        mount_inner(OsString::from(source), target, None, libc::MS_BIND, None)?;
        target_bound = true;
        Ok(())
    })();

    finish_subtree_mount(operation, &mut tmp, target, target_bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    fn test_temp_mount() -> TempMount {
        let path = std::env::temp_dir().join(format!(
            "bcachefs-tempmount-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&path).unwrap();

        TempMount {
            path,
            root: None,
            mounted: false,
            cleaned: false,
        }
    }

    #[test]
    fn parse_mountflag_options_splits_kernel_and_fs_options() {
        let p = parse_mountflag_options("ro,noexec,metadata_replicas=2,norecovery");

        assert_eq!(p.fs_opts.as_deref(), Some("metadata_replicas=2,norecovery"));
        assert_ne!(p.flags & libc::MS_RDONLY, 0);
        assert_ne!(p.flags & libc::MS_NOEXEC, 0);
    }

    #[test]
    fn parse_mountflag_options_drops_userspace_fstab_options() {
        let p = parse_mountflag_options("nofail,_netdev,x-systemd.device-timeout=5");

        assert_eq!(p.fs_opts, None);
        assert_eq!(p.flags, 0);
    }

    #[test]
    fn parse_subvol_mount_option() {
        let (options, subvol) =
            parse_subvol_mount_options("rw,noatime,subvol=/@root,X-mount.mkdir").unwrap();
        let p = parse_mountflag_options(options);

        assert_eq!(p.fs_opts, None);
        assert_eq!(p.flags & libc::MS_NOATIME, libc::MS_NOATIME);
        assert_eq!(subvol, Some(PathBuf::from("@root")));
    }

    #[test]
    fn rejects_escaping_subvol_path() {
        assert!(parse_subvol_mount_options("subvol=../root").is_err());
    }

    #[test]
    fn subtree_resolution_rejects_symlink_escape() {
        assert_ne!(SUBTREE_RESOLVE_FLAGS & RESOLVE_BENEATH, 0);
        assert_ne!(SUBTREE_RESOLVE_FLAGS & RESOLVE_NO_MAGICLINKS, 0);

        let root = std::env::temp_dir().join(format!(
            "bcachefs-openat2-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink("/", root.join("escape")).unwrap();

        let root_fd = std::fs::File::open(&root).unwrap();
        assert!(open_subtree_at(&root_fd, Path::new("escape/tmp")).is_err());

        drop(root_fd);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_empty_and_duplicate_subvol_selectors() {
        assert!(parse_subvol_mount_options("subvol=").is_err());
        assert!(parse_subvol_mount_options("subvol=,subvol=home").is_err());
        assert!(parse_subvol_mount_options("subvol=home,subvol=other").is_err());
    }

    #[test]
    fn rejects_subvol_option_for_fuse() {
        assert!(reject_fuse_subvol_option("ro,subvol=home").is_err());
        assert!(reject_fuse_subvol_option("ro").is_ok());
    }

    #[test]
    fn allows_an_ordinary_directory_subtree_selector() {
        let (_, subvol) = parse_subvol_mount_options("subvol=ordinary-directory").unwrap();

        assert_eq!(subvol, Some(PathBuf::from("ordinary-directory")));
    }

    #[test]
    fn cleanup_failure_after_bind_requires_target_rollback() {
        assert_eq!(cleanup_action(true, false), CleanupAction::RollBackTarget);
        assert_eq!(cleanup_action(false, false), CleanupAction::KeepTarget);
        assert_eq!(cleanup_action(true, true), CleanupAction::KeepTarget);
    }

    #[test]
    fn keeps_filesystem_options_with_subvol() {
        let (options, subvol) = parse_subvol_mount_options("compression=lz4,subvol=home").unwrap();
        let p = parse_mountflag_options(options);

        assert_eq!(p.fs_opts.as_deref(), Some("compression=lz4"));
        assert_eq!(subvol, Some(PathBuf::from("home")));
    }

    #[test]
    fn temp_mount_cleanup_is_idempotent() {
        let mut tmp = test_temp_mount();
        let path = tmp.path.clone();

        tmp.umount().unwrap();
        assert!(tmp.cleaned);
        assert!(!path.exists());

        tmp.umount().unwrap();
        assert!(tmp.cleaned);
        assert!(!path.exists());
    }

    #[test]
    fn temp_mount_cleanup_retries_after_directory_removal_failure() {
        let mut tmp = test_temp_mount();
        let blocker = tmp.path.join("blocker");
        std::fs::write(&blocker, b"test fixture").unwrap();

        assert!(tmp.umount().is_err());
        assert!(!tmp.cleaned);
        assert!(tmp.path.is_dir());

        std::fs::remove_file(blocker).unwrap();
        tmp.umount().unwrap();
        assert!(tmp.cleaned);
        assert!(!tmp.path.exists());
    }

    #[test]
    fn unlock_policy_is_the_first_mount_unlock_step_and_uses_the_session_keyring() {
        handle_unlock_with(
            Some(&UnlockPolicy::Ask),
            Some(Path::new("/ignored")),
            |policy, keyring| {
                assert!(matches!(policy, UnlockPolicy::Ask));
                assert_eq!(keyring, Keyring::Session);
                Ok(KeyHandle)
            },
            |_, _| panic!("passphrase file must not override unlock policy"),
            || panic!("keyring search must not run after explicit unlock policy"),
            |_| panic!("prompt fallback must not run after explicit unlock policy"),
        )
        .unwrap();
    }

    #[test]
    fn passphrase_file_precedes_search_and_uses_the_session_keyring() {
        handle_unlock_with(
            None,
            Some(Path::new("/mock-passphrase")),
            |_, _| panic!("unlock policy must not run when it is absent"),
            |path, keyring| {
                assert_eq!(path, Path::new("/mock-passphrase"));
                assert_eq!(keyring, Keyring::Session);
                Ok(KeyHandle)
            },
            || panic!("keyring search must not run after explicit passphrase file"),
            |_| panic!("prompt fallback must not run after explicit passphrase file"),
        )
        .unwrap();
    }

    #[test]
    fn searched_key_short_circuits_the_prompt() {
        handle_unlock_with(
            None,
            None,
            |_, _| panic!("unlock policy must not run when it is absent"),
            |_, _| panic!("passphrase file must not run when it is absent"),
            || Ok(KeyHandle),
            |_| panic!("prompt must not run when a key is already visible"),
        )
        .unwrap();
    }

    #[test]
    fn missing_key_prompts_after_search_and_inserts_into_the_session_keyring() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let search_calls = Rc::clone(&calls);
        let prompt_calls = Rc::clone(&calls);

        handle_unlock_with(
            None,
            None,
            |_, _| panic!("unlock policy must not run when it is absent"),
            |_, _| panic!("passphrase file must not run when it is absent"),
            move || {
                search_calls.borrow_mut().push("search");
                Err(KeySearchError::NotFound(crate::ErrnoError(errno::Errno(
                    libc::ENOKEY,
                ))))
            },
            move |keyring| {
                prompt_calls.borrow_mut().push("prompt");
                assert_eq!(keyring, Keyring::Session);
                Ok(KeyHandle)
            },
        )
        .unwrap();

        assert_eq!(*calls.borrow(), ["search", "prompt"]);
    }

    #[test]
    fn fatal_keyring_search_error_is_returned_without_prompting() {
        let prompted = Rc::new(Cell::new(false));
        let prompt_called = Rc::clone(&prompted);

        let result = handle_unlock_with(
            None,
            None,
            |_, _| panic!("unlock policy must not run when it is absent"),
            |_, _| panic!("passphrase file must not run when it is absent"),
            || {
                Err(KeySearchError::Fatal(crate::ErrnoError(errno::Errno(
                    libc::EACCES,
                ))))
            },
            move |_| {
                prompt_called.set(true);
                Ok(KeyHandle)
            },
        );

        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("fatal keyring-search error must be returned"),
        };

        assert!(matches!(
            err.downcast_ref::<KeySearchError>(),
            Some(KeySearchError::Fatal(crate::ErrnoError(err))) if err.0 == libc::EACCES
        ));
        assert!(!prompted.get());
    }
}

/// If a user explicitly specifies `unlock_policy` or `passphrase_file` then use
/// that without falling back to other mechanisms. If these options are not
/// used, then search for the key or ask for it.
fn handle_unlock(cli: &Cli, sb: &bch_sb_handle) -> Result<KeyHandle> {
    let uuid = sb.sb().uuid();
    handle_unlock_with(
        cli.unlock_policy.as_ref(),
        cli.passphrase_file.as_deref(),
        |policy, keyring| policy.apply(sb, keyring),
        |path, keyring| {
            let passphrase_correct = Passphrase::read_from_file(path)?
                .check(sb)
                .ok_or_else(|| anyhow::anyhow!("incorrect passphrase"))?;
            KeyHandle::new(&passphrase_correct, keyring)
        },
        || KeyHandle::new_from_search(&uuid),
        |keyring| {
            let passphrase_correct = Passphrase::ask_and_check(sb)?;
            KeyHandle::new(&passphrase_correct, keyring)
        },
    )
}

fn handle_unlock_with<Policy, PassphraseFile, Search, Prompt>(
    policy: Option<&UnlockPolicy>,
    passphrase_file: Option<&Path>,
    apply_policy: Policy,
    unlock_file: PassphraseFile,
    search: Search,
    prompt: Prompt,
) -> Result<KeyHandle>
where
    Policy: FnOnce(&UnlockPolicy, Keyring) -> Result<KeyHandle>,
    PassphraseFile: FnOnce(&Path, Keyring) -> Result<KeyHandle>,
    Search: FnOnce() -> std::result::Result<KeyHandle, KeySearchError>,
    Prompt: FnOnce(Keyring) -> Result<KeyHandle>,
{
    if let Some(policy) = policy {
        return apply_policy(policy, MOUNT_KEYRING);
    }

    if let Some(path) = passphrase_file {
        return unlock_file(path, MOUNT_KEYRING);
    }

    match search() {
        Ok(handle) => Ok(handle),
        Err(KeySearchError::NotFound(_)) => prompt(MOUNT_KEYRING),
        Err(err) => Err(err.into()),
    }
}

fn cmd_mount_inner(cli: &Cli) -> Result<()> {
    if cli.no_mtab {
        debug!("ignoring -n/--no-mtab; mount.bcachefs does not update /etc/mtab");
    }
    if cli.sloppy {
        debug!("ignoring -s/--sloppy; bcachefs already ignores unrecognized options");
    }

    let (options, subvol) = parse_subvol_mount_options(&cli.options)?;
    let parsed = parse_mountflag_options(options);
    let opts = bcachefs_kernel::opts::parse_mount_opts(None, parsed.fs_opts.as_deref(), true)
        .unwrap_or_default();

    let sbs = device_scan::scan_sbs(&cli.dev, &opts)?;

    ensure!(!sbs.is_empty(), "No device(s) to mount specified");

    let devices = device_scan::joined_device_str(&sbs);

    let first_sb = &sbs[0].1;
    if unsafe { bch_bindgen::c::bch2_sb_is_encrypted(first_sb.sb) } {
        handle_unlock(cli, first_sb)?;
    }

    drop(sbs);

    if let Some(mountpoint) = cli.mountpoint.as_deref() {
        if cli.fake {
            info!(
                "fake mount (-f/--fake): skipping the mount syscall for {}",
                mountpoint.to_string_lossy()
            );
            return Ok(());
        }

        info!(
            "mounting with params: device: {:?}, target: {}, options: {}",
            devices,
            mountpoint.to_string_lossy(),
            &cli.options
        );

        if let Some(subvol) = subvol.as_deref() {
            mount_subtree(devices, mountpoint, parsed.flags, parsed.fs_opts, subvol)
        } else {
            mount_inner(
                devices,
                mountpoint,
                Some("bcachefs"),
                parsed.flags,
                parsed.fs_opts,
            )
        }
    } else {
        info!(
            "would mount with params: device: {:?}, options: {}",
            devices, &cli.options
        );

        Ok(())
    }
}

/// Mount a bcachefs filesystem by its UUID or label.
#[derive(Parser, Debug)]
#[command(author, version, about,
    long_about = "`mount -t bcachefs` invokes the installed mount.bcachefs helper; \
this is the same mount path exposed as `bcachefs mount`.\n\n\
Mounts a bcachefs filesystem. Devices are discovered automatically \
by scanning for the filesystem UUID or label---unlike btrfs, this is handled \
entirely in userspace.\n\n\
Use OLD_BLKID_UUID=<uuid> in fstab entries when systemd consumes \
UUID=<uuid> before the bcachefs mount helper can scan all members.\n\n\
If the filesystem is encrypted, the passphrase will be looked up in \
the kernel keyrings first; if not found, the user is prompted \
interactively (or reads from stdin if not a terminal) and the key is added \
to the session keyring for the mount. Use -k or --passphrase-file \
to specify alternative unlock methods.\n\n\
Use -o subvol=PATH to mount a directory subtree as the mount root. The path \
is resolved beneath the temporary filesystem root; it need not itself be a \
subvolume or snapshot. bcachefs.fuse rejects subvol=.")]
pub struct Cli {
    /// Path to passphrase file
    ///
    /// This can be used to optionally specify a file to read the passphrase
    /// from. An explictly specified key_location/unlock_policy overrides this
    /// argument.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    /// Passphrase policy to use in case of an encrypted filesystem. If not
    /// specified, the password will be searched for in the keyring. If not
    /// found, the password will be prompted or read from stdin, depending on
    /// whether the stdin is connected to a terminal or not.
    #[arg(short = 'k', long = "key_location", value_enum)]
    unlock_policy: Option<UnlockPolicy>,

    /// Device, UUID=\<UUID\>, OLD_BLKID_UUID=\<UUID\> (fstab), or LABEL=\<label\>
    dev: String,

    /// Where the filesystem should be mounted. If not set, then the filesystem
    /// won't actually be mounted. But all steps preceeding mounting the
    /// filesystem (e.g. asking for passphrase) will still be performed.
    mountpoint: Option<PathBuf>,

    /// Mount options
    #[arg(short, default_value = "")]
    options: String,

    /// Do not update /etc/mtab; accepted for mount(8) compatibility
    #[arg(short = 'n', long = "no-mtab")]
    no_mtab: bool,

    /// Fake mount: do everything except the mount syscall (mount(8) -f)
    #[arg(short = 'f', long)]
    fake: bool,

    /// Ignore unrecognized mount options instead of failing (mount(8) -s).
    /// bcachefs already ignores unknown options, so this is accepted as a no-op.
    #[arg(short = 's', long)]
    sloppy: bool,

    #[arg(short = 't', long = "type", default_value = "")]
    fs_type: String,

    // FIXME: would be nicer to have `--color[=WHEN]` like diff or ls?
    /// Force color on/off. Autodetect tty is used to define default:
    #[arg(short, long, action = clap::ArgAction::Set, default_value_t=stdout().is_terminal())]
    colorize: bool,

    /// Verbose mode
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

struct ModuleCheck {
    loaded:         bool,
    modprobe_error: Option<String>,
}

fn check_bcachefs_module() -> ModuleCheck {
    let path = Path::new("/sys/module/bcachefs");
    if path.exists() {
        return ModuleCheck { loaded: true, modprobe_error: None };
    }

    let modprobe_error = match std::process::Command::new("modprobe").arg("bcachefs").status() {
        Ok(s) if s.success() => None,
        Ok(_)  => Some("modprobe bcachefs exited unsuccessfully".to_string()),
        Err(e) => Some(format!("could not run modprobe bcachefs: {e}")),
    };

    ModuleCheck { loaded: path.exists(), modprobe_error }
}

fn mount(cli: Cli) -> std::process::ExitCode {
    if cli.fs_type == "bcachefs.fuse" {
        if let Err(e) = reject_fuse_subvol_option(&cli.options) {
            eprintln!("FUSE mount failed: {e:#}");
            return std::process::ExitCode::FAILURE;
        }
        if cli.fake {
            info!("fake mount (-f/--fake): skipping FUSE mount");
            return std::process::ExitCode::SUCCESS;
        }
        #[cfg(feature = "fuse")]
        {
            let fuse_cli = super::fusemount::Cli {
                options: if cli.options.is_empty() { None } else { Some(cli.options.clone()) },
                foreground: false,
                device: cli.dev.clone(),
                mountpoint: cli.mountpoint.as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            };
            return match super::fusemount::cmd_fusemount(fuse_cli) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    error!("FUSE mount failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(feature = "fuse"))]
        {
            error!("FUSE support not compiled in (build with the 'fuse' feature)");
            return std::process::ExitCode::FAILURE;
        }
    }

    let module = check_bcachefs_module();

    // TODO: centralize this on the top level CLI
    logging::setup(cli.verbose, cli.colorize);

    match cmd_mount_inner(&cli) {
        Ok(_)   => std::process::ExitCode::SUCCESS,
        Err(e)   => {
            error!("Mount failed for {}: {e}", cli.dev);
            if !module.loaded {
                error!("bcachefs module not loaded?");
                if let Some(e) = module.modprobe_error {
                    error!("{e}");
                }
            }
            std::process::ExitCode::FAILURE
        }
    }
}

pub static CMD: super::CmdDef = {
    fn __cmd() -> clap::Command { <Cli as clap::CommandFactory>::command() }
    fn __run(argv: Vec<String>) -> std::process::ExitCode {
        mount(Cli::parse_from(argv))
    }
    super::CmdDef {
        name: "mount", about: "Mount a filesystem", aliases: &[],
        kind: super::CmdKind::Typed { cmd: __cmd, run: __run },
    }
};
