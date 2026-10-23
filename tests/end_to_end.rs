use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sshvault");
const PASSPHRASE: &str = "correct horse";

struct Fixture {
    dir: tempfile::TempDir,
    daemon: Option<Child>,
}

fn username() -> String {
    let out = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

impl Fixture {
    /// Starts an unprivileged daemon and gives the current user a vault holding `files`.
    /// `@MNT@` in file contents is replaced by the user's view of the mount.
    /// Returns `None` when this machine cannot mount FUSE filesystems.
    fn start(files: &[(&str, &str)]) -> Option<Fixture> {
        let fixture = Fixture::start_empty()?;
        let src = fixture.path("src");
        std::fs::create_dir(&src).unwrap();
        let mnt = fixture.mnt().display().to_string();
        for (name, content) in files {
            std::fs::write(src.join(name), content.replace("@MNT@", &mnt)).unwrap();
        }
        let create = fixture.create_vault(&src);
        assert!(create.status.success(), "{create:?}");
        Some(fixture)
    }

    fn start_empty() -> Option<Fixture> {
        if !Path::new("/dev/fuse").exists() || which("fusermount3").is_none() {
            eprintln!("skipping: FUSE is not available");
            return None;
        }
        // unix socket paths are limited to 108 bytes
        let dir = tempfile::Builder::new()
            .prefix("sv")
            .tempdir_in("/tmp")
            .unwrap();
        let mut fixture = Fixture { dir, daemon: None };
        let daemon = fixture
            .command(BIN)
            .args(["daemon", "--unprivileged", "--state-dir"])
            .arg(fixture.path("state"))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        fixture.daemon = Some(daemon);
        fixture.wait_until_serving();
        Some(fixture)
    }

    fn create_vault(&self, src: &Path) -> Output {
        let mut create = self.command(BIN);
        create
            .args([
                "create",
                "--passphrase-stdin",
                "--work-factor",
                "10",
                "--from",
            ])
            .arg(src);
        run_with_stdin(create, PASSPHRASE)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// The current user's directory inside the mount.
    fn mnt(&self) -> PathBuf {
        self.path("mnt/self")
    }

    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        cmd.env("SSHVAULT_SOCKET", self.path("control.sock"))
            .env("SSHVAULT_MOUNT", self.path("mnt"))
            .env("SSHVAULT_INSECURE_ALLOW_SAME_UID_DAEMON", "1")
            .env("SV", BIN)
            .env("MNT", self.mnt())
            .env_remove("SSH_AUTH_SOCK");
        cmd
    }

    /// Runs `script` in a fresh `sh` that unlocks itself first.
    fn unlocked_shell(&self, script: &str) -> Output {
        let full = format!(
            "printf '%s\\n' \"$PW\" | \"$SV\" unlock --passphrase-stdin >/dev/null || exit 99\n{script}"
        );
        self.command("sh")
            .env("PW", PASSPHRASE)
            .args(["-c", &full])
            .output()
            .unwrap()
    }

    fn outsider(&self, script: &str) -> Output {
        self.command("sh").args(["-c", script]).output().unwrap()
    }

    fn wait_until_serving(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let status = self.command(BIN).args(["status", "-q"]).status().unwrap();
            if status.code() != Some(2) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("daemon did not come up");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
            let _ = daemon.wait();
        }
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|d| Path::new(d).join(program))
        .find(|p| p.exists())
}

fn run_with_stdin(mut cmd: Command, input: &str) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{input}").unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const CONFIG: &str = "Host x\n  User fromvault\n";

#[test]
fn outsider_sees_an_empty_directory() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.outsider("ls -A \"$MNT\"; cat \"$MNT/config\"");
    assert_eq!(stdout(&o), "");
    assert!(!o.status.success());
}

#[test]
fn unlocked_shell_and_its_descendants_read_the_vault() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.unlocked_shell("cat \"$MNT/config\" && sh -c 'sh -c \"cat $MNT/config\"'");
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), format!("{CONFIG}{CONFIG}"));
}

#[test]
fn outsider_is_refused_while_a_shell_is_unlocked() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let mut shell = f
        .command("sh")
        .env("PW", PASSPHRASE)
        .args(["-c", "printf '%s\\n' \"$PW\" | \"$SV\" unlock --passphrase-stdin >/dev/null && echo $$ && sleep 30"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(shell.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let shell_pid = line.trim();

    let direct = f.outsider("cat \"$MNT/config\"");
    let via_proc_root = f.outsider(&format!("cat /proc/{shell_pid}/root\"$MNT/config\""));
    let via_proc_cwd = f.outsider(&format!("cd /proc/{shell_pid}/cwd && cat \"$MNT/config\""));
    shell.kill().unwrap();
    shell.wait().unwrap();

    for attempt in [direct, via_proc_root, via_proc_cwd] {
        assert!(!attempt.status.success(), "{attempt:?}");
        assert_eq!(stdout(&attempt), "");
    }
}

#[test]
fn access_ends_when_the_shell_exits() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    assert!(f.unlocked_shell("true").status.success());
    let o = f.command(BIN).arg("status").output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).starts_with("locked (0 "), "{o:?}");
}

#[test]
fn wrong_passphrase_is_rejected() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f
        .command("sh")
        .args([
            "-c",
            "echo wrong | \"$SV\" unlock --passphrase-stdin; cat \"$MNT/config\"",
        ])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert_eq!(stdout(&o), "");
}

#[test]
fn lock_revokes_access_for_the_shell() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.unlocked_shell("\"$SV\" lock >/dev/null && cat \"$MNT/config\"");
    assert!(!o.status.success());
    assert_eq!(stdout(&o), "");
}

#[test]
fn vault_is_read_only() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.unlocked_shell(
        "echo planted >> \"$MNT/config\" || echo refused; touch \"$MNT/new\" || echo refused",
    );
    assert_eq!(stdout(&o), "refused\nrefused\n");
}

fn write_stub(f: &Fixture) -> PathBuf {
    let stub = f.command(BIN).arg("stub").output().unwrap();
    let path = f.path("ssh_config");
    let mut text = stdout(&stub);
    text.push_str("\nHost *\n  User fallback\n");
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn ssh_config_resolution_depends_on_the_shell() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let stub = write_stub(&f);
    let query = format!("ssh -G -F {} x | grep '^user '", stub.display());
    assert_eq!(stdout(&f.unlocked_shell(&query)), "user fromvault\n");
    assert_eq!(stdout(&f.outsider(&query)), "user fallback\n");
}

struct Sshd {
    child: Child,
    port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_sshd(dir: &Path, authorized_key: &str) -> Option<Sshd> {
    let sshd = Path::new("/usr/sbin/sshd");
    if !sshd.exists() {
        eprintln!("skipping: no sshd");
        return None;
    }
    let host_key = dir.join("host_key");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(dir.join("authorized_keys"), authorized_key).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = dir.join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nAuthorizedKeysFile {}\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile none\n",
            host_key.display(),
            dir.join("authorized_keys").display()
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "sshd did not come up");
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(Sshd { child, port })
}

#[test]
fn real_ssh_login_uses_the_vault_key_only_from_the_unlocked_shell() {
    let keys = tempfile::tempdir().unwrap();
    let key = keys.path().join("id_test");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let private = std::fs::read_to_string(&key).unwrap();
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();

    let Some(sshd) = start_sshd(keys.path(), &public) else {
        return;
    };
    let user = std::env::var("USER").unwrap();
    let config = format!(
        "Host vaulthost\n  HostName 127.0.0.1\n  Port {}\n  User {user}\n  IdentityFile @MNT@/id_test\n  \
         IdentitiesOnly yes\n  IdentityAgent none\n  BatchMode yes\n  StrictHostKeyChecking no\n  \
         UserKnownHostsFile /dev/null\n  LogLevel ERROR\n",
        sshd.port
    );
    let Some(f) = Fixture::start(&[("config", &config), ("id_test", &private)]) else {
        return;
    };
    let stub = write_stub(&f);

    let login = format!("ssh -F {} vaulthost echo logged-in", stub.display());
    let inside = f.unlocked_shell(&login);
    assert_eq!(stdout(&inside), "logged-in\n", "{inside:?}");

    let outside = f.outsider(&login);
    assert!(!outside.status.success());
    let with_explicit_key = f.outsider(&format!(
        "ssh -F /dev/null -o BatchMode=yes -o IdentityAgent=none -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -i \"$MNT/id_test\" -p {} {user}@127.0.0.1 echo logged-in",
        sshd.port
    ));
    assert_eq!(stdout(&with_explicit_key), "");
}

#[test]
fn client_refuses_a_daemon_running_as_its_own_user() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f
        .command("sh")
        .env_remove("SSHVAULT_INSECURE_ALLOW_SAME_UID_DAEMON")
        .env("PW", PASSPHRASE)
        .args([
            "-c",
            "printf '%s\\n' \"$PW\" | \"$SV\" unlock --passphrase-stdin; cat \"$MNT/config\"",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert_eq!(stdout(&o), "");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("runs as your own user"),
        "{o:?}"
    );
}

#[test]
fn a_vault_cannot_be_replaced() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let other = f.path("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("config"), "Host x\n  ProxyCommand evil\n").unwrap();
    assert!(!f.create_vault(&other).status.success());
    assert_eq!(stdout(&f.unlocked_shell("cat \"$MNT/config\"")), CONFIG);
}

#[test]
fn self_is_the_only_entry_and_belongs_to_the_caller() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.outsider("ls -A \"$SSHVAULT_MOUNT\"; stat -c '%A %U' \"$MNT\"");
    assert_eq!(stdout(&o), format!("self\ndrwx------ {}\n", username()));
    for name in [username(), "root".to_string()] {
        let probe = f.outsider(&format!("ls \"$SSHVAULT_MOUNT/{name}\""));
        assert!(!probe.status.success(), "{name}: {probe:?}");
    }
}

#[test]
fn unlock_without_a_vault_explains_what_to_do() {
    let Some(f) = Fixture::start_empty() else {
        return;
    };
    let o = f.unlocked_shell("true");
    assert_eq!(o.status.code(), Some(99));
    let status = f.command(BIN).arg("status").output().unwrap();
    assert!(stdout(&status).contains("no vault yet"), "{status:?}");
}

/// `unlock` registers its parent. If that parent exits first, the client is adopted by a
/// subreaper such as `systemd --user`, which must not end up unlocking a whole login.
/// The outer shell here plays that subreaper, in a session of its own.
#[test]
fn an_orphaned_unlock_does_not_unlock_its_adopter() {
    use std::os::unix::process::CommandExt;
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let script = r#"
        mkfifo "$FIFO"
        setsid sh -c '( "$SV" unlock --passphrase-stdin < "$FIFO" > "$OUT" 2>&1 & )'
        sleep 0.2
        printf '%s\n' "$PW" > "$FIFO"
        for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$OUT" ] && break; sleep 0.2; done
        cat "$MNT/config" 2>/dev/null
        true
    "#;
    let mut adopter = f.command("sh");
    adopter
        .env("PW", PASSPHRASE)
        .env("FIFO", f.path("fifo"))
        .env("OUT", f.path("unlock.out"))
        .args(["-c", script]);
    unsafe {
        adopter.pre_exec(|| {
            libc::setsid();
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
            Ok(())
        });
    }
    let o = adopter.output().unwrap();
    let unlock_said = std::fs::read_to_string(f.path("unlock.out")).unwrap_or_default();
    assert_eq!(
        stdout(&o),
        "",
        "adopter could read the vault; unlock said: {unlock_said}"
    );
    assert!(
        unlock_said.contains("directly from the shell"),
        "{unlock_said}"
    );
}
