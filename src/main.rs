mod daemon;
mod fs;
mod procs;
mod protocol;
mod secret;
mod sessions;
mod tree;
mod users;
mod vault;

use std::io::{BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::protocol::{Request, Response};

/// Per-shell access to an encrypted SSH configuration directory.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Daemon control socket
    #[arg(
        long,
        global = true,
        env = "SSHVAULT_SOCKET",
        default_value = "/run/sshvault.sock"
    )]
    socket: PathBuf,
    /// Where the daemon mounts; each of your vaults is a directory inside it
    #[arg(
        long,
        global = true,
        env = "SSHVAULT_MOUNT",
        default_value = "/run/sshvault"
    )]
    mount: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mount the vaults and serve requests (started by the systemd unit)
    Daemon {
        /// Account the daemon drops to after mounting
        #[arg(long, default_value = "sshvault")]
        run_as: String,
        /// Where vaults are stored, one directory per uid
        #[arg(long, default_value = "/var/lib/sshvault")]
        state_dir: PathBuf,
        /// Run as the invoking user. For testing only: the daemon is then
        /// indistinguishable from any other process of that user.
        #[arg(long)]
        unprivileged: bool,
        /// scrypt cost (log2) for wrapping vault keys; only lower it for tests
        #[arg(long, hide = true)]
        work_factor: Option<u8>,
    },
    /// Create a vault, empty or from a directory, and unlock it for the calling shell
    Create {
        #[arg(default_value = fs::DEFAULT_VAULT)]
        vault: String,
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
        /// Read the passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Revoke the calling shell's access to a vault, or to all of them
    Lock {
        vault: Option<String>,
        /// Revoke access for all of your shells
        #[arg(long)]
        all: bool,
    },
    /// Show your vaults; exit 0 if the calling shell has the vault (or any) unlocked
    Status {
        vault: Option<String>,
        /// Print nothing, not even errors
        #[arg(long, short)]
        quiet: bool,
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
    /// Print the lines to put at the top of ~/.ssh/config
    Stub,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sshvault: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Daemon {
            run_as,
            state_dir,
            unprivileged,
            work_factor,
        } => {
            daemon::run(&daemon::Options {
                socket: cli.socket,
                mount: cli.mount,
                state_dir,
                run_as: (!unprivileged).then_some(run_as),
                wrap_work_factor: work_factor,
            })?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Create {
            vault,
            from,
            no_unlock,
            passphrase_stdin,
            work_factor,
        } => {
            fs::check_vault_name(&vault)?;
            let status = protocol::call(&cli.socket, &Request::Status)?;
            if status.vault(&vault).is_some() {
                bail!(
                    "you already have a vault `{vault}`; to replace it, `sshvault import` an exported one"
                );
            }
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                let first = prompt(&format!("New passphrase for `{vault}`: "))?;
                if *first != *prompt("Repeat passphrase: ")? {
                    bail!("passphrases do not match");
                }
                first
            };
            let secret = SecretString::from(passphrase.to_string());
            let sealed = match from {
                Some(from) => {
                    let (sealed, skipped) = vault::seal(&from, secret, work_factor)?;
                    for path in skipped {
                        eprintln!("sshvault: left out {} (not a regular file)", path.display());
                    }
                    sealed
                }
                None => vault::encrypt(&tree::Tree::empty().to_tar()?, secret, work_factor)?,
            };
            let data = base64::engine::general_purpose::STANDARD.encode(sealed);
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
        Command::Unlock {
            vault,
            passphrase_stdin,
        } => {
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                prompt(&format!("Passphrase for `{vault}`: "))?
            };
            report(protocol::call(
                &cli.socket,
                &Request::Unlock { vault, passphrase },
            )?)
        }
        Command::Lock { vault, all } => {
            report(protocol::call(&cli.socket, &Request::Lock { vault, all })?)
        }
        Command::Status { vault, quiet } => {
            let reply = match protocol::call(&cli.socket, &Request::Status) {
                Ok(reply) => reply,
                Err(_) if quiet => return Ok(ExitCode::from(2)),
                Err(e) => return Err(e),
            };
            if !quiet {
                print_status(&reply);
            }
            let unlocked = match &vault {
                Some(name) => reply.vault(name).is_some_and(|v| v.unlocked_by.is_some()),
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
        Command::Stub => {
            println!("{}", stub(&cli.mount)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_status(reply: &Response) {
    if reply.vaults.is_empty() {
        println!("no vault yet; create one with `sshvault create`");
    }
    for vault in &reply.vaults {
        match vault.unlocked_by {
            Some(shell) => println!(
                "{}: unlocked by shell {shell} ({} of your shells have it unlocked)",
                vault.name, vault.sessions
            ),
            None => println!(
                "{}: locked here ({} of your other shells have it unlocked)",
                vault.name, vault.sessions
            ),
        }
    }
}

fn stub(mount: &Path) -> Result<String> {
    let exe = std::env::current_exe().context("cannot tell where sshvault is installed")?;
    Ok(format!(
        "# sshvault: keep this block above every Host and Match block. In a shell with a vault\n\
         # unlocked, vault entries take precedence and no key is handed to an agent.\n\
         Match exec \"{} status --quiet\"\n\
         \x20   AddKeysToAgent no\n\
         \x20   Include {}",
        exe.display(),
        mount.join("*").join("config").display()
    ))
}

fn write_export(file: &Path, vault: &[u8]) -> Result<()> {
    if file == Path::new("-") {
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
