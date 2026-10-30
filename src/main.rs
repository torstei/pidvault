use std::io::{BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use pidvault::protocol::{Request, Response, VaultStatus};
use pidvault::{daemon, fs, keys, procs, protocol, secret, tree, vault};

/// Per-shell access to an encrypted SSH configuration directory.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Daemon control socket
    #[arg(
        long,
        global = true,
        env = "PIDVAULT_SOCKET",
        default_value = "/run/pidvault.sock"
    )]
    socket: PathBuf,
    /// The agent that signs with vault keys
    #[arg(
        long,
        global = true,
        env = "PIDVAULT_AGENT_SOCKET",
        default_value = "/run/pidvault-agent.sock"
    )]
    agent_socket: PathBuf,
    /// Where the daemon mounts; each of your vaults is a directory inside it
    #[arg(
        long,
        global = true,
        env = "PIDVAULT_MOUNT",
        default_value = "/run/pidvault"
    )]
    mount: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the vaults (started by the systemd unit)
    Daemon {
        /// Where vaults are stored, one directory per uid
        #[arg(long, default_value = "/var/lib/pidvault")]
        state_dir: PathBuf,
        /// Mount and bind as the invoking user. For testing only: the daemon is then
        /// indistinguishable from any other process of that user.
        #[arg(long)]
        unprivileged: bool,
        /// Where the mount helper hands over the FUSE connection
        #[arg(long, default_value = "/run/pidvault-mount.sock")]
        mount_socket: PathBuf,
        /// scrypt cost (log2) for wrapping vault keys; only lower it for tests
        #[arg(long, hide = true)]
        work_factor: Option<u8>,
    },
    /// Mount the view for the daemon (run as root by its own systemd unit)
    #[command(hide = true)]
    MountHelper,
    /// Create a vault, empty or from a directory, and unlock it for the calling shell
    Create {
        /// The vault's name; `default` if left out, except for an ephemeral vault
        #[arg(required_if_eq("ephemeral", "true"))]
        vault: Option<String>,
        /// Keep the vault in memory only, without a passphrase, for the calling shell and
        /// what it starts; it is gone once locked, when the shell exits or the daemon stops
        #[arg(long, conflicts_with_all = ["from", "no_unlock", "passphrase_stdin"])]
        ephemeral: bool,
        /// With --ephemeral: end it by itself after this long, e.g. 90s, 10m, 1h30m
        #[arg(long = "for", value_parser = parse_duration, requires = "ephemeral")]
        for_: Option<Duration>,
        /// Start from the files in this directory instead of an empty vault
        #[arg(long)]
        from: Option<PathBuf>,
        /// Leave the calling shell locked
        #[arg(long)]
        no_unlock: bool,
        /// Read the passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
        /// scrypt cost (log2); only lower it for tests
        #[arg(long, hide = true)]
        work_factor: Option<u8>,
    },
    /// Give the calling shell and its descendants access to a vault
    Unlock {
        #[arg(default_value = fs::DEFAULT_VAULT)]
        vault: String,
        /// Lock again by itself after this long, e.g. 90s, 10m, 1h30m
        #[arg(long = "for", value_parser = parse_duration)]
        for_: Option<Duration>,
        /// Read the passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Revoke the calling shell's access to a vault, or to all of them
    Lock {
        vault: Option<String>,
        /// The vault is this shell's ephemeral one, not a stored one
        #[arg(long, requires = "vault")]
        ephemeral: bool,
        /// Revoke access for all of your shells
        #[arg(long)]
        all: bool,
    },
    /// Show your vaults; exit 0 if the calling shell has the vault (or any) unlocked
    Status {
        vault: Option<String>,
        /// The vault is this shell's ephemeral one, not a stored one
        #[arg(long, requires = "vault")]
        ephemeral: bool,
        /// Print nothing, not even errors
        #[arg(long, short)]
        quiet: bool,
        /// Print only the vaults the calling shell has unlocked and the time each has
        /// left, for a shell prompt; nothing when there are none
        #[arg(long, conflicts_with = "quiet")]
        prompt: bool,
    },
    /// Change the passphrase of a vault
    Passwd {
        #[arg(default_value = fs::DEFAULT_VAULT)]
        vault: String,
        /// Read the old and the new passphrase from the first two lines of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Write a vault, encrypted with its passphrase, to FILE (`-` for stdout); needs the
    /// vault unlocked in the calling shell
    Export {
        file: PathBuf,
        #[arg(long, default_value = fs::DEFAULT_VAULT)]
        vault: String,
        /// Read the passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Make an exported vault yours and unlock it for the calling shell: on a new
    /// machine, or replacing one (which needs it unlocked, and is kept as a backup)
    Import {
        file: PathBuf,
        #[arg(long, default_value = fs::DEFAULT_VAULT)]
        vault: String,
        /// Leave the calling shell locked
        #[arg(long)]
        no_unlock: bool,
        /// Read the file's passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Copy a private key into a vault, removing its passphrase on the way; the vault
    /// must be unlocked in the calling shell
    AddKey {
        file: PathBuf,
        #[arg(long, default_value = fs::DEFAULT_VAULT)]
        vault: String,
        /// Name in the vault [default: the file's name]
        #[arg(long)]
        name: Option<String>,
        /// Read the key's passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Print the lines to put at the top of ~/.ssh/config
    Stub,
    /// Print bash code that marks shells with a vault unlocked, in the prompt and the
    /// terminal title; use it with `eval "$(pidvault shell-init)"` in ~/.bashrc
    ShellInit,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("pidvault: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Daemon {
            state_dir,
            unprivileged,
            mount_socket,
            work_factor,
        } => {
            daemon::run(&daemon::Options {
                socket: cli.socket,
                agent_socket: cli.agent_socket,
                mount: cli.mount,
                mount_socket,
                state_dir,
                unprivileged,
                wrap_work_factor: work_factor,
            })?;
            Ok(ExitCode::SUCCESS)
        }
        Command::MountHelper => {
            daemon::mount_helper(&cli.mount)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Create {
            vault,
            ephemeral,
            for_,
            from,
            no_unlock,
            passphrase_stdin,
            work_factor,
        } => {
            let vault = vault.unwrap_or_else(|| fs::DEFAULT_VAULT.to_owned());
            fs::check_vault_name(&vault)?;
            let status = protocol::call(&cli.socket, &Request::Status)?;
            match status.vault_in(ephemeral, &vault) {
                Some(_) if ephemeral => {
                    bail!("this shell already has an ephemeral vault `{vault}`")
                }
                Some(_) => bail!(
                    "you already have a vault `{vault}`; to replace it, `pidvault import` an exported one"
                ),
                None => {}
            }
            if !no_unlock {
                procs::check_tracing_restricted()?;
            }
            if ephemeral {
                report(protocol::call(
                    &cli.socket,
                    &Request::CreateEphemeral {
                        vault: vault.clone(),
                        for_secs: for_.map(|d| d.as_secs()),
                    },
                )?)?;
                println!(
                    "\nWhat you put in {} stays in memory only. It is gone when this shell \
                     exits or locks it, or the daemon stops.",
                    cli.mount.join(fs::EPHEMERAL).join(&vault).display()
                );
                return Ok(ExitCode::SUCCESS);
            }
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                let first = prompt(&format!("New passphrase for `{vault}`: "))?;
                vault::check_new_passphrase(&first)?;
                if *first != *prompt("Repeat passphrase: ")? {
                    bail!("passphrases do not match");
                }
                first
            };
            vault::check_new_passphrase(&passphrase)?;
            let secret = SecretString::from(passphrase.to_string());
            let sealed = match from {
                Some(from) => {
                    let (sealed, skipped) = vault::seal(&from, secret, work_factor)?;
                    for path in skipped {
                        eprintln!("pidvault: left out {} (not a regular file)", path.display());
                    }
                    sealed
                }
                None => {
                    let config =
                        starter_config(&cli.mount.join(fs::STORED).join(&vault), &cli.agent_socket);
                    let failed = |e| anyhow::anyhow!("cannot prepare the starter config: {e:?}");
                    let mut tree = tree::Tree::empty();
                    let ino = tree
                        .create_file(tree::ROOT, std::ffi::OsStr::new("config"), 0o600)
                        .map_err(failed)?;
                    tree.write(ino, 0, config.as_bytes()).map_err(failed)?;
                    vault::encrypt(&tree.to_tar()?, secret, work_factor)?
                }
            };
            let data = base64::engine::general_purpose::STANDARD.encode(sealed);
            let dir = cli.mount.join(fs::STORED).join(&vault);
            report(protocol::call(
                &cli.socket,
                &Request::Import {
                    vault: vault.clone(),
                    data,
                    passphrase,
                    unlock: !no_unlock,
                },
            )?)?;
            if no_unlock {
                println!("\nunlock it with:  pidvault unlock {vault}");
            }
            println!(
                "\nPut keys in it, which can then be used but never read:\n\
                 \x20   ssh-keygen -t ed25519 -N '' -f {dir}/id_ed25519\n\
                 \x20   pidvault add-key{flag} ~/.ssh/SOME_KEY\n\
                 Describe your hosts in {dir}/config, then use it either through the block\n\
                 `pidvault stub` prints for the top of ~/.ssh/config, or directly:\n\
                 \x20   ssh -F {dir}/config HOST",
                dir = dir.display(),
                flag = if vault == fs::DEFAULT_VAULT {
                    String::new()
                } else {
                    format!(" --vault {vault}")
                },
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Unlock {
            vault,
            for_,
            passphrase_stdin,
        } => {
            procs::check_tracing_restricted()?;
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                prompt(&format!("Passphrase for `{vault}`: "))?
            };
            report(protocol::call(
                &cli.socket,
                &Request::Unlock {
                    vault,
                    passphrase,
                    for_secs: for_.map(|d| d.as_secs()),
                },
            )?)
        }
        Command::Lock {
            vault,
            ephemeral,
            all,
        } => report(protocol::call(
            &cli.socket,
            &Request::Lock {
                vault,
                all,
                ephemeral,
            },
        )?),
        Command::Status {
            vault,
            ephemeral,
            quiet,
            prompt,
        } => {
            let reply = match protocol::call(&cli.socket, &Request::Status) {
                Ok(reply) => reply,
                Err(_) if quiet || prompt => return Ok(ExitCode::from(2)),
                Err(e) => return Err(e),
            };
            if prompt {
                let line = prompt_line(&reply, vault.as_deref().map(|name| (ephemeral, name)));
                if !line.is_empty() {
                    println!("{line}");
                }
            } else if !quiet {
                print_status(&reply);
            }
            let unlocked = match &vault {
                Some(name) => reply
                    .vault_in(ephemeral, name)
                    .is_some_and(|v| v.unlocked_by.is_some()),
                None => reply.any_unlocked(),
            };
            Ok(if unlocked {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Passwd {
            vault,
            passphrase_stdin,
        } => {
            let (old, new) = if passphrase_stdin {
                (passphrase_from_stdin()?, passphrase_from_stdin()?)
            } else {
                let old = prompt(&format!("Current passphrase for `{vault}`: "))?;
                let new = prompt("New passphrase: ")?;
                vault::check_new_passphrase(&new)?;
                if *new != *prompt("Repeat new passphrase: ")? {
                    bail!("passphrases do not match");
                }
                (old, new)
            };
            report(protocol::call(
                &cli.socket,
                &Request::Passwd { vault, old, new },
            )?)
        }
        Command::Export {
            file,
            vault,
            passphrase_stdin,
        } => {
            if file != Path::new("-") && file.exists() {
                bail!("{} already exists", file.display());
            }
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                prompt(&format!("Passphrase for `{vault}`: "))?
            };
            let reply = protocol::call(&cli.socket, &Request::Export { vault, passphrase })?;
            if !reply.ok {
                bail!("{}", reply.message);
            }
            let data = base64::engine::general_purpose::STANDARD
                .decode(reply.data.context("daemon sent no vault")?)
                .context("daemon sent a malformed vault")?;
            write_export(&file, &data)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Import {
            file,
            vault,
            no_unlock,
            passphrase_stdin,
        } => {
            fs::check_vault_name(&vault)?;
            if !no_unlock {
                procs::check_tracing_restricted()?;
            }
            let ciphertext = read_limited(&file)?;
            vault::check_sealed(&ciphertext)
                .with_context(|| format!("{} is not an exported vault", file.display()))?;
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                prompt(&format!("Passphrase for {}: ", file.display()))?
            };
            let data = base64::engine::general_purpose::STANDARD.encode(ciphertext);
            report(protocol::call(
                &cli.socket,
                &Request::Import {
                    vault,
                    data,
                    passphrase,
                    unlock: !no_unlock,
                },
            )?)
        }
        Command::AddKey {
            file,
            vault,
            name,
            passphrase_stdin,
        } => {
            fs::check_vault_name(&vault)?;
            let status = protocol::call(&cli.socket, &Request::Status)?;
            if !status
                .vault(&vault)
                .is_some_and(|v| v.unlocked_by.is_some())
            {
                bail!(
                    "`{vault}` is not unlocked in this shell; run `pidvault unlock {vault}` first"
                );
            }
            let name = match name {
                Some(name) => PathBuf::from(name),
                None => PathBuf::from(file.file_name().context("the key file has no name")?),
            };
            if name.is_absolute()
                || name
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                bail!("--name must be a plain path inside the vault");
            }
            let private_path = cli.mount.join(fs::STORED).join(&vault).join(&name);
            let public_path = private_path.with_file_name(format!(
                "{}.pub",
                private_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            ));
            for path in [&private_path, &public_path] {
                if path.exists() {
                    bail!("{} already exists", path.display());
                }
            }
            let data = secret::SecretBuf::from_reader(
                std::fs::File::open(&file)
                    .with_context(|| format!("opening {}", file.display()))?,
                0,
            )?;
            let key = keys::importable(&data, || {
                if passphrase_stdin {
                    passphrase_from_stdin()
                } else {
                    prompt(&format!("Passphrase for {}: ", file.display()))
                }
            })?;
            create_new(&private_path, key.private.as_bytes())?;
            create_new(&public_path, format!("{}\n", key.public).as_bytes())?;
            println!(
                "added {} to `{vault}` as {} ({})",
                file.display(),
                name.display(),
                key.fingerprint
            );
            println!("use it with:  IdentityFile {}", private_path.display());
            println!(
                "{} itself is unchanged; it has been readable by every process you ran, so retire it once the copy works",
                file.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Stub => {
            println!("{}", stub(&cli.mount, &cli.agent_socket)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::ShellInit => {
            let exe = std::env::current_exe().context("cannot tell where pidvault is installed")?;
            print!("{}", shell_init(&exe));
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// What an empty vault starts with: enough for `ssh -F` to sign through the vault agent.
fn starter_config(dir: &Path, agent_socket: &Path) -> String {
    format!(
        "# Readable only in shells that unlocked this vault. Used through the pidvault block\n\
         # in ~/.ssh/config, or directly:  ssh -F {dir}/config HOST\n\
         \n\
         # Keys in this vault cannot be read, only used through the vault agent.\n\
         IdentityAgent {agent}\n\
         \n\
         # Host example\n\
         #     HostName example.com\n\
         #     User me\n\
         #     IdentityFile {dir}/id_ed25519\n\
         #     UserKnownHostsFile {dir}/known_hosts\n\
         #     # through a jump host, without forwarding your agent to it\n\
         #     ProxyJump jump.example.com\n",
        dir = dir.display(),
        agent = agent_socket.display(),
    )
}

/// A duration like `90s`, `10m` or `1h30m`.
fn parse_duration(text: &str) -> Result<Duration, String> {
    let mut total = 0u64;
    let mut digits = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(format!("unknown unit `{c}`; use s, m or h, e.g. 10m")),
        };
        let n: u64 = digits
            .parse()
            .map_err(|_| format!("a number must come before `{c}`"))?;
        total = n
            .checked_mul(unit)
            .and_then(|s| total.checked_add(s))
            .ok_or("too long")?;
        digits.clear();
    }
    if !digits.is_empty() {
        return Err(format!("`{digits}` needs a unit: s, m or h"));
    }
    if total == 0 {
        return Err("the duration must be longer than nothing".into());
    }
    Ok(Duration::from_secs(total))
}

fn print_status(reply: &Response) {
    if reply.vaults.is_empty() {
        println!("no vault yet; create one with `pidvault create`");
    }
    for vault in &reply.vaults {
        match vault.unlocked_by {
            Some(shell) if vault.ephemeral => println!(
                "{}: of shell {shell}{}, in memory only",
                shown_name(vault),
                vault
                    .expires_in
                    .map(|secs| format!(" for another {}", daemon::format_duration(secs)))
                    .unwrap_or_default(),
            ),
            Some(shell) => println!(
                "{}: unlocked by shell {shell}{} ({} of your shells have it unlocked)",
                vault.name,
                vault
                    .expires_in
                    .map(|secs| format!(" for another {}", daemon::format_duration(secs)))
                    .unwrap_or_default(),
                vault.sessions
            ),
            None => println!(
                "{}: locked here ({} of your other shells have it unlocked)",
                vault.name, vault.sessions
            ),
        }
        for note in &vault.notes {
            println!("  {note}");
        }
    }
}

/// A vault as the user names it: stored ones by name, ephemeral ones as `ephemeral/NAME`.
fn shown_name(vault: &VaultStatus) -> String {
    if vault.ephemeral {
        format!("{}/{}", fs::EPHEMERAL, vault.name)
    } else {
        vault.name.clone()
    }
}

/// The vaults the calling shell has unlocked, each with the time it has left, e.g.
/// `default 9m, work, ephemeral/bao 2h`; with `only`, just that vault.
fn prompt_line(reply: &Response, only: Option<(bool, &str)>) -> String {
    reply
        .vaults
        .iter()
        .filter(|v| {
            v.unlocked_by.is_some()
                && only.is_none_or(|(ephemeral, name)| v.ephemeral == ephemeral && v.name == name)
        })
        .map(|v| match v.expires_in {
            Some(secs) => format!("{} {}", shown_name(v), short_duration(secs)),
            None => shown_name(v),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Time left as a prompt shows it: seconds under a minute, otherwise whole minutes
/// rounded up, so it never shows less time than there is.
fn short_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    let minutes = secs.div_ceil(60);
    match (minutes / 60, minutes % 60) {
        (0, m) => format!("{m}m"),
        (h, 0) => format!("{h}h"),
        (h, m) => format!("{h}h{m}m"),
    }
}

/// Vault names cannot contain anything bash would expand in PS1.
const SHELL_INIT: &str = r#"# pidvault: while this shell has a vault unlocked, a red marker before the prompt
# and the vault names in the terminal title.
__pidvault_prompt() {
    local status=$? vaults
    [[ -n ${__pidvault_head-} ]] && PS1=${PS1//"$__pidvault_head"/}
    [[ -n ${__pidvault_tail-} ]] && PS1=${PS1//"$__pidvault_tail"/}
    __pidvault_head='' __pidvault_tail=''
    if vaults=$(PIDVAULT_EXE status --prompt 2>/dev/null); then
        __pidvault_head="\[\e[1;97;41m\] 🔑 $vaults \[\e[0m\] "
        # last in PS1, after anything else there that sets the title
        __pidvault_tail="\[\e]2;🔑 $vaults — \u@\h: \w\a\]"
        PS1=$__pidvault_head$PS1$__pidvault_tail
        __pidvault_titled=1
    elif [[ -n ${__pidvault_titled-} ]]; then
        printf '\e]2;%s@%s: %s\a' "$USER" "${HOSTNAME%%.*}" "${PWD/#"$HOME"/\~}"
        __pidvault_titled=''
    fi
    return "$status"
}
[[ " ${PROMPT_COMMAND[*]-} " == *" __pidvault_prompt "* ]] || PROMPT_COMMAND+=(__pidvault_prompt)
"#;

fn shell_init(exe: &Path) -> String {
    let quoted = format!("'{}'", exe.display().to_string().replace('\'', r"'\''"));
    SHELL_INIT.replace("PIDVAULT_EXE", &quoted)
}

fn stub(mount: &Path, agent_socket: &Path) -> Result<String> {
    let exe = std::env::current_exe().context("cannot tell where pidvault is installed")?;
    Ok(format!(
        "# pidvault: keep this block above every Host and Match block. In a shell with a vault\n\
         # unlocked, vault entries take precedence, vault keys sign through the vault agent,\n\
         # and no key is handed to any other agent.\n\
         Match exec \"{} status --quiet\"\n\
         \x20   IdentityAgent {}\n\
         \x20   AddKeysToAgent no\n\
         \x20   Include {} {}",
        exe.display(),
        agent_socket.display(),
        mount.join(fs::STORED).join("*").join("config").display(),
        mount.join(fs::EPHEMERAL).join("*").join("config").display()
    ))
}

fn write_export(file: &Path, vault: &[u8]) -> Result<()> {
    if file == Path::new("-") {
        // SAFETY: isatty takes any descriptor and has no other preconditions
        if unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1 {
            bail!("refusing to write a binary vault to a terminal; redirect stdout or name a file");
        }
        let mut out = std::io::stdout().lock();
        out.write_all(vault)?;
        return Ok(out.flush()?);
    }
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)
        .with_context(|| format!("creating {}", file.display()))?;
    out.write_all(vault)?;
    out.sync_all()?;
    Ok(())
}

fn create_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    out.write_all(data)?;
    out.sync_all()?;
    Ok(())
}

fn read_limited(file: &Path) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    std::fs::File::open(file)
        .with_context(|| format!("opening {}", file.display()))?
        .take(MAX_EXPORT + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_EXPORT {
        bail!("{} is larger than any vault", file.display());
    }
    Ok(data)
}

/// Comfortably above an age file holding the largest vault the daemon accepts.
const MAX_EXPORT: u64 = 2 * secret::MAX_SECRET as u64;

fn report(reply: Response) -> Result<ExitCode> {
    if !reply.ok {
        bail!("{}", reply.message);
    }
    if !reply.message.is_empty() {
        println!("{}", reply.message);
    }
    Ok(ExitCode::SUCCESS)
}

fn prompt(text: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(text)?))
}

fn passphrase_from_stdin() -> Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let trimmed = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string());
    if trimmed.is_empty() {
        bail!("empty passphrase");
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prompt_rounds_the_time_left_up() {
        assert_eq!(short_duration(59), "59s");
        assert_eq!(short_duration(60), "1m");
        assert_eq!(short_duration(61), "2m");
        assert_eq!(short_duration(599), "10m");
        assert_eq!(short_duration(3599), "1h");
        assert_eq!(short_duration(5400), "1h30m");
    }

    #[test]
    fn durations_parse_with_units() {
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("10m"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_duration("1h30m"), Ok(Duration::from_secs(5400)));
        for bad in ["10", "m", "10x", "0s", "", "99999999999999999999h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn durations_print_briefly() {
        assert_eq!(daemon::format_duration(42), "42s");
        assert_eq!(daemon::format_duration(600), "10m");
        assert_eq!(daemon::format_duration(612), "10m 12s");
        assert_eq!(daemon::format_duration(5400), "1h 30m");
        assert_eq!(daemon::format_duration(7200), "2h");
    }

    /// The packaged man page is generated from the command line definitions. Run with
    /// PIDVAULT_WRITE_MAN=1 to regenerate it after changing them.
    #[test]
    fn the_man_page_is_up_to_date() {
        use clap::CommandFactory;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/pidvault.1");
        let mut page = Vec::new();
        clap_mangen::Man::new(Cli::command())
            .render(&mut page)
            .unwrap();
        if std::env::var_os("PIDVAULT_WRITE_MAN").is_some() {
            std::fs::write(&path, &page).unwrap();
        }
        let packaged = std::fs::read(&path).unwrap_or_default();
        assert!(
            packaged == page,
            "packaging/pidvault.1 is stale; run PIDVAULT_WRITE_MAN=1 cargo test the_man_page"
        );
    }
}
