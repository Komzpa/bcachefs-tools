use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;

use anyhow::{anyhow, Result};
use bch_bindgen::c;
use clap::Parser;
use serde::Serialize;

use crate::commands::DeviceNameArgs;
use crate::wrappers::accounting::{
    data_type, data_type_is_empty, disk_accounting_type, AccountingEntry, DiskAccountingKind,
};
use crate::wrappers::handle::BcachefsHandle;
use crate::wrappers::sysfs::{self, bcachefs_kernel_version, DevInfo, DeviceNameMode};
use bcachefs_kernel::opts::{prt_compression_type, prt_data_type, prt_reconcile_type};
use bcachefs_kernel::util::printbuf::Printbuf;
use bcachefs_kernel::{btree, metadata_version};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "snake_case")]
enum Field {
    Replicas,
    Btree,
    Compression,
    RebalanceWork,
    Devices,
}

impl Field {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replicas => "replicas",
            Self::Btree => "btree",
            Self::Compression => "compression",
            Self::RebalanceWork => "rebalance_work",
            Self::Devices => "devices",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "usage",
    about = "Display detailed filesystem usage",
    long_about = "Displays filesystem space usage broken down by category. \
Output modes: replicas (data/metadata replication), btree (per-btree \
space), compression (ratios and savings), rebalance_work (pending \
reconcile work), devices (per-device breakdown). Use -f to select \
specific fields, -a for all, -h for human-readable sizes.",
    disable_help_flag = true
)]
pub struct Cli {
    /// Print help
    #[arg(long = "help", action = clap::ArgAction::Help)]
    _help: (),

    /// Comma-separated list of fields
    #[arg(short = 'f', long = "fields", value_delimiter = ',', value_enum)]
    fields: Vec<Field>,

    /// Print all accounting fields
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Human-readable units
    #[arg(short = 'h', long = "human-readable")]
    human_readable: bool,

    /// Print machine-readable JSON
    #[arg(long = "json")]
    json: bool,

    #[command(flatten)]
    device_names: DeviceNameArgs,

    /// Filesystem mountpoints
    #[arg(default_value = ".")]
    mountpoints: Vec<String>,
}

fn fs_usage(cli: Cli) -> Result<()> {
    let fields = if cli.all {
        vec![
            Field::Replicas,
            Field::Btree,
            Field::Compression,
            Field::RebalanceWork,
            Field::Devices,
        ]
    } else if cli.fields.is_empty() {
        vec![Field::RebalanceWork]
    } else {
        cli.fields
    };
    let name_mode = cli.device_names.name_mode();

    if cli.json {
        let filesystems = cli
            .mountpoints
            .iter()
            .map(|path| FsUsage::load(path, &fields, name_mode))
            .collect::<Result<Vec<_>>>()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&FsUsageRoot { filesystems })?
        );
    } else {
        for path in &cli.mountpoints {
            let usage = FsUsage::load(path, &fields, name_mode)?;
            let mut out = Printbuf::new();
            out.set_human_readable(cli.human_readable);
            fs_usage_to_text(&mut out, &usage);
            print!("{}", out);
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct FsUsageRoot {
    filesystems: Vec<FsUsage>,
}

/// The single decoded representation of fs usage. Both renderers consume this
/// model; accounting entries are decoded only by `FsUsage::load`.
#[derive(Serialize)]
struct FsUsage {
    mountpoint: String,
    uuid: String,
    fields: Vec<&'static str>,
    capacity_sectors: u64,
    used_sectors: u64,
    online_reserved_sectors: u64,
    replicas_summary: ReplicasSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    replicas: Vec<ReplicaUsage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    persistent_reserved: Vec<PersistentReserved>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    compression: Vec<CompressionUsage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    btree: Vec<BtreeUsage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rebalance_work: Vec<SectorUsage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reconcile_work: Vec<ReconcileWork>,
    devices: Vec<DeviceUsage>,
}

#[derive(Default, Serialize)]
struct ReplicasSummary {
    replicated: Vec<DurabilityUsage>,
    erasure_coded: Vec<EcUsage>,
    cached_sectors: u64,
    reserved_sectors: u64,
}

#[derive(Serialize)]
struct DurabilityUsage {
    durability: u32,
    degraded: u32,
    sectors: u64,
}

#[derive(Serialize)]
struct EcUsage {
    data: u8,
    parity: u8,
    degraded: u32,
    sectors: u64,
}

#[derive(Serialize)]
struct ReplicaUsage {
    data_type: String,
    required: u8,
    replicas: u8,
    durability: u32,
    degraded: u32,
    devices: Vec<String>,
    sectors: u64,
}

#[derive(Serialize)]
struct PersistentReserved {
    replicas: u8,
    sectors: u64,
}

#[derive(Serialize)]
struct CompressionUsage {
    compression_type: String,
    extents: u64,
    compressed_sectors: u64,
    uncompressed_sectors: u64,
    average_extent_bytes: u64,
}

#[derive(Serialize)]
struct BtreeUsage {
    btree: String,
    sectors: u64,
}

#[derive(Serialize)]
struct ReconcileWork {
    work_type: String,
    data_sectors: u64,
    metadata_sectors: u64,
}

#[derive(Serialize)]
struct SectorUsage {
    sectors: u64,
}

#[derive(Serialize)]
struct DeviceUsage {
    label: Option<String>,
    device_index: u32,
    device: String,
    state: String,
    capacity_sectors: Option<u64>,
    used_sectors: Option<u64>,
    hidden_sectors: Option<u64>,
    used_percent: Option<u64>,
    leaving_sectors: u64,
    bucket_size_sectors: Option<u32>,
    buckets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_types: Option<Vec<DeviceDataTypeUsage>>,
}

#[derive(Serialize)]
struct DeviceDataTypeUsage {
    data_type: String,
    sectors: u64,
    buckets: u64,
    fragmented_sectors: u64,
}

impl FsUsage {
    fn load(path: &str, fields: &[Field], name_mode: DeviceNameMode) -> Result<Self> {
        let handle = BcachefsHandle::open(path)
            .map_err(|e| anyhow!("opening filesystem '{}': {}", path, e))?;
        let sysfs_path = sysfs::sysfs_path_from_fd(handle.sysfs_fd())?;
        let devs = sysfs::fs_get_devices(&sysfs_path, name_mode)?;
        let result = handle
            .query_accounting(accounting_types_for_fields(fields))
            .map_err(|e| anyhow!("query_accounting ioctl failed (kernel too old?): {}", e))?;

        let mut entries: Vec<&AccountingEntry> = result.entries.iter().collect();
        entries.sort_by_key(|entry| entry.pos);

        let include_replicas = fields.contains(&Field::Replicas);
        let include_compression = fields.contains(&Field::Compression);
        let include_btree = fields.contains(&Field::Btree);
        let include_work = fields.contains(&Field::RebalanceWork);
        let include_device_types = fields.contains(&Field::Devices);
        let mut replicas_summary = ReplicasSummaryBuilder::default();
        let mut replicas = Vec::new();
        let mut persistent_reserved = Vec::new();
        let mut compression = Vec::new();
        let mut btree_usage = Vec::new();
        let mut rebalance_work = Vec::new();
        let mut reconcile_work = Vec::new();
        let mut leaving_by_device = BTreeMap::new();

        // This is the sole accounting decoder. Text and JSON only render FsUsage.
        for entry in entries {
            match entry.pos.decode() {
                DiskAccountingKind::PersistentReserved { nr_replicas } => {
                    let sectors = entry.counter(0);
                    replicas_summary.add_reserved(sectors);
                    if include_replicas && sectors != 0 {
                        persistent_reserved.push(PersistentReserved {
                            replicas: nr_replicas,
                            sectors,
                        });
                    }
                }
                DiskAccountingKind::Replicas {
                    data_type: kind,
                    nr_devs,
                    nr_required,
                    devs: dev_list,
                } => {
                    let sectors = entry.counter(0);
                    let dev_list = &dev_list[..nr_devs as usize];
                    let durability = replicas_durability(nr_devs, nr_required, dev_list, &devs);
                    replicas_summary.add_replica(kind, nr_devs, nr_required, durability, sectors);
                    if include_replicas && sectors != 0 {
                        replicas.push(ReplicaUsage {
                            data_type: data_type_name(kind),
                            required: nr_required,
                            replicas: nr_devs,
                            durability: durability.durability,
                            degraded: durability.degraded,
                            devices: device_names(dev_list, &devs),
                            sectors,
                        });
                    }
                }
                DiskAccountingKind::Compression { compression_type } if include_compression => {
                    let extents = entry.counter(0);
                    let uncompressed_sectors = entry.counter(1);
                    compression.push(CompressionUsage {
                        compression_type: compression_type_name(compression_type),
                        extents,
                        compressed_sectors: entry.counter(2),
                        uncompressed_sectors,
                        average_extent_bytes: if extents == 0 {
                            0
                        } else {
                            uncompressed_sectors.saturating_mul(512) / extents
                        },
                    });
                }
                DiskAccountingKind::Btree { id } if include_btree => {
                    btree_usage.push(BtreeUsage {
                        btree: btree::types::btree_id_str(id).to_string(),
                        sectors: entry.counter(0),
                    });
                }
                DiskAccountingKind::RebalanceWork if include_work => {
                    rebalance_work.push(SectorUsage {
                        sectors: entry.counter(0),
                    });
                }
                DiskAccountingKind::ReconcileWork { work_type } if include_work => {
                    reconcile_work.push(ReconcileWork {
                        work_type: reconcile_type_name(work_type),
                        data_sectors: entry.counter(0),
                        metadata_sectors: entry.counter(1),
                    });
                }
                DiskAccountingKind::DevLeaving { dev } => {
                    leaving_by_device.insert(dev as u32, entry.counter(0));
                }
                _ => {}
            }
        }

        let mut devices = devs
            .iter()
            .map(|dev| {
                device_usage(
                    &handle,
                    dev,
                    leaving_by_device.get(&dev.idx).copied().unwrap_or(0),
                    include_device_types,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        devices.sort_by(|a, b| {
            a.label
                .cmp(&b.label)
                .then(a.device.cmp(&b.device))
                .then(a.device_index.cmp(&b.device_index))
        });

        Ok(Self {
            mountpoint: path.to_string(),
            uuid: uuid::Uuid::from_bytes(handle.uuid())
                .hyphenated()
                .to_string(),
            fields: fields.iter().map(|field| field.as_str()).collect(),
            capacity_sectors: result.capacity,
            used_sectors: result.used,
            online_reserved_sectors: result.online_reserved,
            replicas_summary: replicas_summary.finish(),
            replicas,
            persistent_reserved,
            compression,
            btree: btree_usage,
            rebalance_work,
            reconcile_work,
            devices,
        })
    }
}

fn accounting_types_for_fields(fields: &[Field]) -> u32 {
    let mut types =
        disk_accounting_type::replicas.bit() | disk_accounting_type::persistent_reserved.bit();
    if fields.contains(&Field::Compression) {
        types |= disk_accounting_type::compression.bit();
    }
    if fields.contains(&Field::Btree) {
        types |= disk_accounting_type::btree.bit();
    }

    let supports_reconcile =
        bcachefs_kernel_version() >= u32::from(metadata_version::reconcile) as u64;
    if supports_reconcile {
        // Device summaries always display leaving work when the kernel exposes it.
        types |= disk_accounting_type::dev_leaving.bit();
        if fields.contains(&Field::RebalanceWork) {
            types |= disk_accounting_type::reconcile_work.bit();
        }
    } else if fields.contains(&Field::RebalanceWork) {
        types |= disk_accounting_type::rebalance_work.bit();
    }
    types
}

fn printbuf_to_string(f: impl FnOnce(&mut Printbuf)) -> String {
    let mut out = Printbuf::new();
    f(&mut out);
    out.to_string()
}

fn data_type_name(kind: data_type) -> String {
    printbuf_to_string(|out| prt_data_type(out, kind))
}

fn compression_type_name(kind: bcachefs_kernel::c::bch_compression_type) -> String {
    printbuf_to_string(|out| prt_compression_type(out, kind))
}

fn reconcile_type_name(kind: bcachefs_kernel::c::bch_reconcile_accounting_type) -> String {
    printbuf_to_string(|out| prt_reconcile_type(out, kind))
}

#[derive(Clone, Copy)]
struct Durability {
    durability: u32,
    degraded: u32,
}

fn replicas_durability(
    nr_devs: u8,
    nr_required: u8,
    dev_list: &[u8],
    devs: &[DevInfo],
) -> Durability {
    let mut durability = 0;
    let mut degraded = 0;
    for &dev_idx in dev_list {
        let dev = devs.iter().find(|dev| dev.idx == dev_idx as u32);
        let dev_durability = dev.map_or(1, |dev| dev.durability);
        if dev.is_none() {
            degraded += dev_durability;
        }
        durability += dev_durability;
    }
    if nr_required > 1 {
        durability = (nr_devs - nr_required + 1) as u32;
    }
    Durability {
        durability,
        degraded,
    }
}

fn device_names(dev_list: &[u8], devs: &[DevInfo]) -> Vec<String> {
    dev_list
        .iter()
        .map(|&dev_idx| {
            if dev_idx == c::BCH_SB_MEMBER_INVALID as u8 {
                "none".to_string()
            } else if let Some(dev) = devs.iter().find(|dev| dev.idx == dev_idx as u32) {
                dev.dev.clone()
            } else {
                dev_idx.to_string()
            }
        })
        .collect()
}

#[derive(Default)]
struct ReplicasSummaryBuilder {
    replicated: BTreeMap<(u32, u32), u64>,
    erasure_coded: BTreeMap<(u8, u8, u32), u64>,
    cached_sectors: u64,
    reserved_sectors: u64,
}

impl ReplicasSummaryBuilder {
    fn add_reserved(&mut self, sectors: u64) {
        self.reserved_sectors += sectors;
    }

    fn add_replica(
        &mut self,
        kind: data_type,
        nr_devs: u8,
        nr_required: u8,
        durability: Durability,
        sectors: u64,
    ) {
        if kind == data_type::cached {
            self.cached_sectors += sectors;
        } else if nr_required > 1 {
            *self
                .erasure_coded
                .entry((nr_required, nr_devs - nr_required, durability.degraded))
                .or_default() += sectors;
        } else {
            *self
                .replicated
                .entry((durability.durability, durability.degraded))
                .or_default() += sectors;
        }
    }

    fn finish(self) -> ReplicasSummary {
        ReplicasSummary {
            replicated: self
                .replicated
                .into_iter()
                .filter_map(|((durability, degraded), sectors)| {
                    (sectors != 0).then_some(DurabilityUsage {
                        durability,
                        degraded,
                        sectors,
                    })
                })
                .collect(),
            erasure_coded: self
                .erasure_coded
                .into_iter()
                .filter_map(|((data, parity, degraded), sectors)| {
                    (sectors != 0).then_some(EcUsage {
                        data,
                        parity,
                        degraded,
                        sectors,
                    })
                })
                .collect(),
            cached_sectors: self.cached_sectors,
            reserved_sectors: self.reserved_sectors,
        }
    }
}

fn device_usage(
    handle: &BcachefsHandle,
    dev: &DevInfo,
    leaving_sectors: u64,
    include_data_types: bool,
) -> Result<DeviceUsage> {
    if !dev.online {
        return Ok(DeviceUsage {
            label: dev.label.clone(),
            device_index: dev.idx,
            device: dev.dev.clone(),
            state: "offline".to_string(),
            capacity_sectors: None,
            used_sectors: None,
            hidden_sectors: None,
            used_percent: None,
            leaving_sectors,
            bucket_size_sectors: None,
            buckets: None,
            data_types: None,
        });
    }

    let usage = handle
        .dev_usage(dev.idx)
        .map_err(|e| anyhow!("getting usage for device {}: {}", dev.idx, e))?;
    let hidden = usage.hidden_sectors();
    let capacity = usage.capacity_sectors() - hidden;
    let used = usage.used_sectors() - hidden;
    let used_percent = if usage.nr_buckets == 0 {
        0
    } else {
        usage.used_buckets() * 100 / usage.nr_buckets
    };
    let data_types = include_data_types.then(|| {
        usage
            .iter_typed()
            .map(|(kind, value)| {
                let sectors = if data_type_is_empty(kind) {
                    value.buckets * usage.bucket_size as u64
                } else {
                    value.sectors
                };
                DeviceDataTypeUsage {
                    data_type: data_type_name(kind),
                    sectors,
                    buckets: value.buckets,
                    fragmented_sectors: value.fragmented,
                }
            })
            .collect()
    });

    Ok(DeviceUsage {
        label: dev.label.clone(),
        device_index: dev.idx,
        device: dev.dev.clone(),
        state: bcachefs_kernel::sb::members::member_state_str(usage.state).to_string(),
        capacity_sectors: Some(capacity),
        used_sectors: Some(used),
        hidden_sectors: Some(hidden),
        used_percent: Some(used_percent),
        leaving_sectors,
        bucket_size_sectors: Some(usage.bucket_size),
        buckets: Some(usage.nr_buckets),
        data_types,
    })
}

fn fs_usage_to_text(out: &mut Printbuf, usage: &FsUsage) {
    writeln!(out, "Filesystem: {}", usage.uuid).unwrap();
    out.aligned(|sub| {
        write!(sub, "Size:\t").unwrap();
        sub.units_sectors(usage.capacity_sectors);
        write!(sub, "\r\n").unwrap();
        write!(sub, "Used:\t").unwrap();
        sub.units_sectors(usage.used_sectors);
        write!(sub, "\r\n").unwrap();
        write!(sub, "Online reserved:\t").unwrap();
        sub.units_sectors(usage.online_reserved_sectors);
        write!(sub, "\r\n").unwrap();
    });
    replicas_summary_to_text(out, &usage.replicas_summary);

    if usage.fields.contains(&"replicas") {
        out.aligned(|sub| {
            write!(
                sub,
                "\nData type\tRequired/total\tDurability\tDevices\tUsage\n"
            )
            .unwrap();
            for entry in &usage.persistent_reserved {
                write!(sub, "reserved:\t1/{}\t\t[]\t ", entry.replicas).unwrap();
                sub.units_sectors(entry.sectors);
                write!(sub, "\r\n").unwrap();
            }
            for entry in &usage.replicas {
                write!(
                    sub,
                    "{}:\t{}/{}\t{}\t[{}]\t",
                    entry.data_type,
                    entry.required,
                    entry.replicas,
                    entry.durability,
                    entry.devices.join(" ")
                )
                .unwrap();
                sub.units_sectors(entry.sectors);
                write!(sub, "\r\n").unwrap();
            }
        });
    }

    if !usage.compression.is_empty() {
        out.aligned(|sub| {
            write!(sub, "\nCompression:\n").unwrap();
            write!(
                sub,
                "type\tcompressed\runcompressed\raverage extent size\r\n"
            )
            .unwrap();
            for entry in &usage.compression {
                write!(sub, "{}\t", entry.compression_type).unwrap();
                sub.units_sectors(entry.compressed_sectors);
                write!(sub, "\r").unwrap();
                sub.units_sectors(entry.uncompressed_sectors);
                write!(sub, "\r").unwrap();
                sub.units_u64(entry.average_extent_bytes);
                write!(sub, "\r\n").unwrap();
            }
        });
    }

    if !usage.btree.is_empty() {
        out.aligned(|sub| {
            write!(sub, "\nBtree usage:\n").unwrap();
            for entry in &usage.btree {
                write!(sub, "{}:\t", entry.btree).unwrap();
                sub.units_sectors(entry.sectors);
                write!(sub, "\r\n").unwrap();
            }
        });
    }

    if !usage.rebalance_work.is_empty() {
        write!(out, "\nPending rebalance work:\n").unwrap();
        for entry in &usage.rebalance_work {
            out.units_sectors(entry.sectors);
            out.newline();
        }
    }
    if !usage.reconcile_work.is_empty() {
        out.aligned(|sub| {
            write!(sub, "\nPending reconcile:\tdata\rmetadata\r\n").unwrap();
            for entry in &usage.reconcile_work {
                write!(sub, "{}:\t", entry.work_type).unwrap();
                sub.units_sectors(entry.data_sectors);
                write!(sub, "\r").unwrap();
                sub.units_sectors(entry.metadata_sectors);
                write!(sub, "\r\n").unwrap();
            }
        });
    }
    devices_to_text(out, &usage.devices, usage.fields.contains(&"devices"));
}

fn replicas_summary_to_text(out: &mut Printbuf, summary: &ReplicasSummary) {
    writeln!(out).unwrap();
    if !summary.erasure_coded.is_empty() {
        writeln!(out, "Replicated:").unwrap();
    }
    durability_summary_to_text(out, &summary.replicated);
    if !summary.erasure_coded.is_empty() {
        write!(out, "\nErasure coded (data+parity):\n").unwrap();
        ec_summary_to_text(out, &summary.erasure_coded);
    }
    if summary.cached_sectors != 0 || summary.reserved_sectors != 0 {
        out.aligned(|sub| {
            if summary.cached_sectors != 0 {
                write!(sub, "cached:\t").unwrap();
                sub.units_sectors(summary.cached_sectors);
                write!(sub, "\r\n").unwrap();
            }
            if summary.reserved_sectors != 0 {
                write!(sub, "reserved:\t").unwrap();
                sub.units_sectors(summary.reserved_sectors);
                write!(sub, "\r\n").unwrap();
            }
        });
    }
}

fn prt_degraded_header(out: &mut Printbuf, max_degraded: u32) {
    write!(out, "\tundegraded\r").unwrap();
    for degraded in 1..=max_degraded {
        write!(out, "-{}x\r", degraded).unwrap();
    }
    out.newline();
}

fn durability_summary_to_text(out: &mut Printbuf, entries: &[DurabilityUsage]) {
    let Some(max_degraded) = entries.iter().map(|entry| entry.degraded).max() else {
        return;
    };
    out.aligned(|sub| {
        prt_degraded_header(sub, max_degraded);
        let mut rows = BTreeMap::<u32, BTreeMap<u32, u64>>::new();
        for entry in entries {
            rows.entry(entry.durability)
                .or_default()
                .insert(entry.degraded, entry.sectors);
        }
        for (durability, values) in rows {
            write!(sub, "{}x:\t", durability).unwrap();
            for degraded in 0..=max_degraded {
                if let Some(sectors) = values.get(&degraded) {
                    sub.units_sectors(*sectors);
                }
                write!(sub, "\r").unwrap();
            }
            sub.newline();
        }
    });
}

fn ec_summary_to_text(out: &mut Printbuf, entries: &[EcUsage]) {
    let Some(max_degraded) = entries.iter().map(|entry| entry.degraded).max() else {
        return;
    };
    out.aligned(|sub| {
        prt_degraded_header(sub, max_degraded);
        let mut rows = BTreeMap::<(u8, u8), BTreeMap<u32, u64>>::new();
        for entry in entries {
            rows.entry((entry.data, entry.parity))
                .or_default()
                .insert(entry.degraded, entry.sectors);
        }
        for ((data, parity), values) in rows {
            write!(sub, "{}+{}:\t", data, parity).unwrap();
            for degraded in 0..=max_degraded {
                if let Some(sectors) = values.get(&degraded) {
                    sub.units_sectors(*sectors);
                }
                write!(sub, "\r").unwrap();
            }
            sub.newline();
        }
    });
}

fn devices_to_text(out: &mut Printbuf, devices: &[DeviceUsage], full: bool) {
    let has_leaving = devices.iter().any(|device| device.leaving_sectors != 0);
    out.newline();
    if full {
        for device in devices {
            device_usage_full_to_text(out, device);
        }
        return;
    }
    out.aligned(|sub| {
        write!(sub, "Device label\tDevice\tState\tSize\rUsed\rUse%\r").unwrap();
        if has_leaving {
            write!(sub, "Leaving\r").unwrap();
        }
        sub.newline();
        for device in devices {
            let label = device.label.as_deref().unwrap_or("(no label)");
            write!(
                sub,
                "{} (device {}):\t{}\t",
                label, device.device_index, device.device
            )
            .unwrap();
            let Some(capacity) = device.capacity_sectors else {
                write!(sub, "offline\t-\r-\r-\r").unwrap();
                if has_leaving {
                    write!(sub, "\r").unwrap();
                }
                sub.newline();
                continue;
            };
            write!(sub, "{}\t", device.state).unwrap();
            sub.units_sectors(capacity);
            write!(sub, "\r").unwrap();
            sub.units_sectors(device.used_sectors.unwrap());
            write!(sub, "\r{:>2}%\r", device.used_percent.unwrap()).unwrap();
            if device.leaving_sectors != 0 {
                sub.units_sectors(device.leaving_sectors);
                write!(sub, "\r").unwrap();
            }
            sub.newline();
        }
    });
}

fn device_usage_full_to_text(out: &mut Printbuf, device: &DeviceUsage) {
    let label = device.label.as_deref().unwrap_or("(no label)");
    let Some(capacity) = device.capacity_sectors else {
        out.aligned(|sub| {
            writeln!(
                sub,
                "{} (device {}):\t{}\toffline\tusage unavailable",
                label, device.device_index, device.device
            )
            .unwrap();
        });
        return;
    };
    out.aligned(|sub| {
        writeln!(
            sub,
            "{} (device {}):\t{}\t{}\t{:>2}%",
            label,
            device.device_index,
            device.device,
            device.state,
            device.used_percent.unwrap()
        )
        .unwrap();
        let sub = &mut *sub.indent(2);
        write!(sub, "\tdata\rbuckets\rfragmented\r\n").unwrap();
        for data_type in device.data_types.as_deref().unwrap_or_default() {
            write!(sub, "{}:\t", data_type.data_type).unwrap();
            sub.units_sectors(data_type.sectors);
            write!(sub, "\r{}\r", data_type.buckets).unwrap();
            if data_type.fragmented_sectors != 0 {
                sub.units_sectors(data_type.fragmented_sectors);
            }
            write!(sub, "\r\n").unwrap();
        }
        write!(sub, "capacity:\t").unwrap();
        sub.units_sectors(capacity + device.hidden_sectors.unwrap());
        write!(sub, "\r{}\r\n", device.buckets.unwrap()).unwrap();
        write!(sub, "bucket size:\t").unwrap();
        sub.units_sectors(device.bucket_size_sectors.unwrap() as u64);
        write!(sub, "\r\n").unwrap();
    });
    out.newline();
}

pub const CMD: super::CmdDef = typed_cmd!("usage", "Show filesystem disk usage", Cli, fs_usage);
