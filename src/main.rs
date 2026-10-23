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
    /// Where the daemon mounts; your files appear under `self` inside it
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
    /// Encrypt a directory and hand it to the daemon as your vault
    Create {
        #[arg(long)]
        from: PathBuf,
        /// Read the passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
        /// scrypt cost (log2); only lower it for tests
        #[arg(long, hide = true)]
        work_factor: Option<u8>,
    },
    /// Write your vault, encrypted with its passphrase, to FILE (`-` for stdout);
    /// needs an unlocked shell
    Export {
        file: PathBuf,
        /// Read the passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Change the passphrase of your vault
    Passwd {
        /// Read the old and the new passphrase from the first two lines of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Make an exported vault yours: on a new machine, or replacing your current one
    /// (which needs an unlocked shell and is kept as a backup)
    Import {
        file: PathBuf,
        /// Read the file's passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Give the calling shell and its descendants access to your vault
    Unlock {
        /// Read the passphrase from the first line of stdin
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Revoke access for the calling shell
    Lock {
        /// Revoke access for all of your shells
        #[arg(long)]
        all: bool,
    },
    /// Exit 0 if the calling shell is unlocked, 1 if not
    Status {
        #[arg(long, short)]
        quiet: bool,
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
            from,
            passphrase_stdin,
            work_factor,
        } => {
            let status = protocol::call(&cli.socket, &Request::Status)?;
            if status.has_vault {
                bail!("you already have a vault; to replace it, `sshvault import` an exported one");
            }
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                let first = prompt("New vault passphrase: ")?;
                if *first != *prompt("Repeat passphrase: ")? {
                    bail!("passphrases do not match");
                }
                first
            };
            let (sealed, skipped) = vault::seal(
                &from,
                SecretString::from(passphrase.to_string()),
                work_factor,
            )?;
            for path in skipped {
                eprintln!("sshvault: left out {} (not a regular file)", path.display());
            }
            let vault = base64::engine::general_purpose::STANDARD.encode(sealed);
            report(protocol::call(
                &cli.socket,
                &Request::Import { vault, passphrase },
            )?)
        }
        Command::Unlock { passphrase_stdin } => {
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                prompt("Vault passphrase: ")?
            };
            report(protocol::call(
                &cli.socket,
                &Request::Unlock { passphrase },
            )?)
        }
        Command::Export {
            file,
            passphrase_stdin,
        } => {
            if file != Path::new("-") && file.exists() {
                bail!("{} already exists", file.display());
            }
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                prompt("Vault passphrase: ")?
            };
            let reply = protocol::call(&cli.socket, &Request::Export { passphrase })?;
            if !reply.ok {
                bail!("{}", reply.message);
            }
            let vault = base64::engine::general_purpose::STANDARD
                .decode(reply.vault.context("daemon sent no vault")?)
                .context("daemon sent a malformed vault")?;
            write_export(&file, &vault)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Passwd { passphrase_stdin } => {
            let (old, new) = if passphrase_stdin {
                (passphrase_from_stdin()?, passphrase_from_stdin()?)
            } else {
                let old = prompt("Current passphrase: ")?;
                let new = prompt("New passphrase: ")?;
                if *new != *prompt("Repeat new passphrase: ")? {
                    bail!("passphrases do not match");
                }
                (old, new)
            };
            report(protocol::call(&cli.socket, &Request::Passwd { old, new })?)
        }
        Command::Import {
            file,
            passphrase_stdin,
        } => {
            let ciphertext = read_limited(&file)?;
            vault::check_sealed(&ciphertext)
                .with_context(|| format!("{} is not an exported vault", file.display()))?;
            let passphrase = if passphrase_stdin {
                passphrase_from_stdin()?
            } else {
                prompt(&format!("Passphrase for {}: ", file.display()))?
            };
            let vault = base64::engine::general_purpose::STANDARD.encode(ciphertext);
            report(protocol::call(
                &cli.socket,
                &Request::Import { vault, passphrase },
            )?)
        }
        Command::Lock { all } => report(protocol::call(&cli.socket, &Request::Lock { all })?),
        Command::Status { quiet } => {
            let reply = protocol::call(&cli.socket, &Request::Status)?;
            if !quiet {
                match (reply.has_vault, reply.unlocked_by) {
                    (false, _) => {
                        println!("no vault yet; create one with `sshvault create --from DIR`")
                    }
                    (true, Some(shell)) => {
                        println!(
                            "unlocked by shell {shell} ({} of your shells unlocked)",
                            reply.sessions
                        )
                    }
                    (true, None) => {
                        println!("locked ({} of your other shells unlocked)", reply.sessions)
                    }
                }
            }
            Ok(if reply.unlocked_by.is_some() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Stub => {
            println!("{}", stub(&cli.mount));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn stub(mount: &Path) -> String {
    format!(
        "# sshvault: keep above every Host and Match block so vault entries take precedence\n\
         Include {}",
        mount.join(fs::SELF).join("config").display()
    )
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
