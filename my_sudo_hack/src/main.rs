use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use clap::Parser;
use tokio::signal;

#[derive(Debug, Parser)]
struct TargetPid {
    #[clap(short, long, default_value = "0")]
    pid: u64,
}

/// A simple CLI tool to restrict execution based on user and parent process ID
#[derive(Debug, Parser)]
#[command(
    name = "cli configuration",
    about = "A tool with user restriction options"
)]
struct Cli {
    /// Username of user
    #[arg(short = 'u', long = "username", value_name = "USERNAME")]
    username: Option<String>,

    /// Restrict to only run when sudo is executed by the matching user
    #[arg(
        short = 'r',
        long = "restrict",
        value_name = "RESTRICT",
        default_value_t = false
    )]
    restrict: bool,

    /// Optional Parent PID, will only affect its children
    #[arg(
        short = 't',
        long = "target-ppid",
        value_name = "PPID",
        default_value_t = 0
    )]
    target_ppid: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = TargetPid::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::EbpfLoader::new()
        .set_global("target_pid", &opt.pid, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/my_sudo_hack"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    println!("Waiting for Ctrl-C...");

    let sys_enter_openat_trace_point: &mut TracePoint = ebpf
        .program_mut("handle_openat_enter")
        .unwrap()
        .try_into()?;
    sys_enter_openat_trace_point.load()?;
    sys_enter_openat_trace_point.attach("syscalls", "sys_enter_openat")?;

    let sys_exit_openat_trace_point: &mut TracePoint =
        ebpf.program_mut("handle_openat_exit").unwrap().try_into()?;
    sys_exit_openat_trace_point.load()?;
    sys_exit_openat_trace_point.attach("syscalls", "sys_exit_openat")?;

    let sys_exit_openat_trace_point: &mut TracePoint =
        ebpf.program_mut("handle_read_enter").unwrap().try_into()?;
    sys_exit_openat_trace_point.load()?;
    sys_exit_openat_trace_point.attach("syscalls", "sys_enter_read")?;

    let sys_exit_openat_trace_point: &mut TracePoint =
        ebpf.program_mut("handle_read_exit").unwrap().try_into()?;
    sys_exit_openat_trace_point.load()?;
    sys_exit_openat_trace_point.attach("syscalls", "sys_exit_read")?;

    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
