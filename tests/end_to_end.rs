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
        fixture.spawn_daemon();
        Some(fixture)
    }

    fn spawn_daemon(&mut self) {
        let daemon = self
            .command(BIN)
            .args([
                "daemon",
                "--unprivileged",
                "--work-factor",
                "10",
                "--state-dir",
            ])
            .arg(self.path("state"))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.daemon = Some(daemon);
        self.wait_until_serving();
    }

    fn stop_daemon(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
            let _ = daemon.wait();
        }
    }

    fn restart_daemon(&mut self) {
        self.stop_daemon();
        self.spawn_daemon();
    }

    /// Waits until the daemon holds no unlocked shell, and so no decrypted tree.
    fn wait_until_locked(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let o = self.command(BIN).arg("status").output().unwrap();
            if stdout(&o).lines().all(|line| line.contains("(0 ")) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("daemon still holds unlocked shells");
    }

    fn create_vault(&self, src: &Path) -> Output {
        let mut create = self.command(BIN);
        // run straight from the test process, which must not become an unlocked shell
        create
            .args([
                "create",
                "--no-unlock",
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
        self.path("mnt/default")
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
        self.stop_daemon();
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
    // the command may exit before reading, e.g. when it refuses straight away
    let _ = writeln!(child.stdin.take().unwrap(), "{input}");
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
    assert!(stdout(&o).starts_with("default: locked here (0 "), "{o:?}");
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
fn edits_from_an_unlocked_shell_persist() {
    let Some(mut f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let edit = r#"
        set -e
        cd "$MNT"
        echo "  Port 2222" >> config
        sed -i 's/User fromvault/User edited/' config
        mkdir keys
        printf secret > keys/id
        chmod 644 keys/id
        stat -c %a keys/id
        mv keys/id keys/id_moved
        touch scratch && rm scratch
    "#;
    let o = f.unlocked_shell(edit);
    assert_eq!(stdout(&o), "600\n", "{o:?}");
    let expected = "Host x\n  User edited\n  Port 2222\n";

    f.wait_until_locked();
    let read_back = "cat \"$MNT/config\" \"$MNT/keys/id_moved\"; ls \"$MNT\"";
    assert_eq!(
        stdout(&f.unlocked_shell(read_back)),
        format!("{expected}secretconfig\nkeys\n")
    );

    f.restart_daemon();
    assert_eq!(
        stdout(&f.unlocked_shell(read_back)),
        format!("{expected}secretconfig\nkeys\n")
    );
}

#[test]
fn only_unlocked_shells_can_write() {
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

    let attempts = [
        "echo planted > \"$MNT/new\"",
        "echo planted >> \"$MNT/config\"",
        "rm \"$MNT/config\"",
        "mkdir \"$MNT/dir\"",
        "echo planted > \"$SSHVAULT_MOUNT/new\"",
    ];
    let results: Vec<Output> = attempts.iter().map(|a| f.outsider(a)).collect();
    let content = stdout(&f.unlocked_shell("cat \"$MNT/config\"; ls \"$MNT\""));
    shell.kill().unwrap();
    shell.wait().unwrap();

    for (attempt, o) in attempts.iter().zip(results) {
        assert!(!o.status.success(), "{attempt} succeeded");
    }
    assert_eq!(content, format!("{CONFIG}config\n"));
}

#[test]
fn the_vault_cannot_grow_past_its_limit() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.unlocked_shell("head -c 5000000 /dev/zero 2>&1 > \"$MNT/big\" || echo refused");
    let out = stdout(&o);
    assert!(
        out.contains("No space left on device") && out.contains("refused"),
        "{o:?}"
    );
}

#[test]
fn passwd_changes_the_passphrase_and_keeps_unsaved_edits() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.unlocked_shell(
        "echo '  Port 2222' >> \"$MNT/config\" && printf '%s\\n%s\\n' \"$PW\" new-pass | \"$SV\" passwd --passphrase-stdin",
    );
    assert!(o.status.success(), "{o:?}");
    f.wait_until_locked();

    let old = f.outsider("echo \"$PW\" | \"$SV\" unlock --passphrase-stdin");
    assert!(!old.status.success());
    let o = f.outsider(
        "echo new-pass | \"$SV\" unlock --passphrase-stdin >/dev/null && cat \"$MNT/config\"",
    );
    assert_eq!(stdout(&o), format!("{CONFIG}  Port 2222\n"));
}

#[test]
fn export_needs_the_vault_passphrase() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let out = f.path("export.age");
    let o = f.unlocked_shell(&format!(
        "echo wrong | \"$SV\" export --passphrase-stdin '{}'",
        out.display()
    ));
    assert!(!o.status.success());
    assert!(!out.exists());
}

#[test]
fn an_export_includes_edits_not_yet_saved() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let out = f.path("export.age");
    let o = f.unlocked_shell(&format!(
        "echo '  Port 2222' >> \"$MNT/config\" && printf '%s\\n' \"$PW\" | \"$SV\" export --passphrase-stdin '{}'",
        out.display()
    ));
    assert!(o.status.success(), "{o:?}");
    let Some(new) = Fixture::start_empty() else {
        return;
    };
    assert!(import(&new, &out, PASSPHRASE).status.success());
    assert_eq!(
        stdout(&new.unlocked_shell("cat \"$MNT/config\"")),
        format!("{CONFIG}  Port 2222\n")
    );
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
fn create_does_not_replace_an_existing_vault() {
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
fn the_mount_lists_only_the_callers_vaults_which_belong_to_the_caller() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.outsider("ls -A \"$SSHVAULT_MOUNT\"; stat -c '%A %U' \"$MNT\" \"$SSHVAULT_MOUNT\"");
    assert_eq!(
        stdout(&o),
        format!(
            "default\ndrwx------ {}\ndrwxr-xr-x {}\n",
            username(),
            username()
        )
    );
    for name in ["work", "root", ".."] {
        let probe = f.outsider(&format!("ls \"$SSHVAULT_MOUNT/{name}/config\""));
        assert!(!probe.status.success(), "{name}: {probe:?}");
    }
}

/// Runs `script` in a fresh `sh` that has unlocked exactly `vaults`, each with `PASSPHRASE`.
fn shell_with(f: &Fixture, vaults: &[&str], script: &str) -> Output {
    let unlocks: String = vaults
        .iter()
        .map(|v| format!("printf '%s\\n' \"$PW\" | \"$SV\" unlock {v} --passphrase-stdin >/dev/null || exit 99\n"))
        .collect();
    f.command("sh")
        .env("PW", PASSPHRASE)
        .args(["-c", &format!("{unlocks}{script}")])
        .output()
        .unwrap()
}

fn create_named(f: &Fixture, name: &str, config: &str) {
    let o = shell_with(
        f,
        &[],
        &format!(
            "printf '%s\\n' \"$PW\" | \"$SV\" create {name} --no-unlock --passphrase-stdin --work-factor 10 >/dev/null || exit 1\n\
             printf '%s\\n' \"$PW\" | \"$SV\" unlock {name} --passphrase-stdin >/dev/null && printf '{config}' > \"$SSHVAULT_MOUNT/{name}/config\""
        ),
    );
    assert!(o.status.success(), "{o:?}");
}

#[test]
fn a_shell_sees_only_the_vaults_it_unlocked() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    create_named(&f, "work", "Host w\n  User fromwork\n");
    let read_both = "cat \"$SSHVAULT_MOUNT/default/config\" 2>/dev/null; cat \"$SSHVAULT_MOUNT/work/config\" 2>/dev/null; ls \"$SSHVAULT_MOUNT\"";
    assert_eq!(
        stdout(&shell_with(&f, &["work"], read_both)),
        "Host w\n  User fromwork\ndefault\nwork\n"
    );
    assert_eq!(
        stdout(&shell_with(&f, &["default"], read_both)),
        format!("{CONFIG}default\nwork\n")
    );
    assert_eq!(
        stdout(&shell_with(&f, &["default", "work"], read_both)),
        format!("{CONFIG}Host w\n  User fromwork\ndefault\nwork\n")
    );
    let write_other = shell_with(
        &f,
        &["work"],
        "echo planted >> \"$SSHVAULT_MOUNT/default/config\"",
    );
    assert!(!write_other.status.success());
}

#[test]
fn lock_can_lock_one_vault() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    create_named(&f, "work", "Host w\n");
    let o = shell_with(
        &f,
        &["default", "work"],
        "\"$SV\" lock work >/dev/null; cat \"$SSHVAULT_MOUNT/work/config\" 2>/dev/null; cat \"$MNT/config\"; \"$SV\" status",
    );
    let out = stdout(&o);
    assert!(out.starts_with(CONFIG), "{o:?}");
    assert!(out.contains("default: unlocked by shell"), "{o:?}");
    assert!(out.contains("work: locked here"), "{o:?}");
}

#[test]
fn ssh_never_adds_keys_to_an_agent_from_an_unlocked_shell() {
    let Some(f) = Fixture::start(&[("config", "Host x\n  AddKeysToAgent yes\n")]) else {
        return;
    };
    let stub = f.command(BIN).arg("stub").output().unwrap();
    let path = f.path("ssh_config");
    std::fs::write(
        &path,
        format!("{}\nHost *\n  AddKeysToAgent yes\n", stdout(&stub)),
    )
    .unwrap();
    let query = format!("ssh -G -F {} x | grep '^addkeystoagent '", path.display());
    assert_eq!(stdout(&f.unlocked_shell(&query)), "addkeystoagent false\n");
    assert_eq!(stdout(&f.outsider(&query)), "addkeystoagent true\n");
}

#[test]
fn a_vault_stored_before_vaults_had_names_becomes_the_default() {
    let Some(mut f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    f.stop_daemon();
    let dir = f.path(&format!("state/{}", uid()));
    std::fs::rename(dir.join("default.sshvault"), dir.join("vault.sshvault")).unwrap();
    f.spawn_daemon();
    assert_eq!(stdout(&f.unlocked_shell("cat \"$MNT/config\"")), CONFIG);
    assert!(!dir.join("vault.sshvault").exists());
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

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

fn export_from_unlocked_shell(f: &Fixture, to: &Path) -> Output {
    f.unlocked_shell(&format!(
        "printf '%s\\n' \"$PW\" | \"$SV\" export --passphrase-stdin '{}'",
        to.display()
    ))
}

/// Imports from a shell that has not been unlocked.
fn import(f: &Fixture, file: &Path, passphrase: &str) -> Output {
    f.outsider(&format!(
        "printf '%s\\n' '{passphrase}' | \"$SV\" import --passphrase-stdin '{}'",
        file.display()
    ))
}

#[test]
fn export_needs_an_unlocked_shell() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let out = f.path("export.age");
    let o = f.outsider(&format!("\"$SV\" export '{}'", out.display()));
    assert!(!o.status.success());
    assert!(!out.exists());
}

#[test]
fn an_export_moves_to_a_new_machine() {
    let Some(old) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let out = old.path("export.age");
    let o = export_from_unlocked_shell(&old, &out);
    assert!(o.status.success(), "{o:?}");
    assert!(
        std::fs::read(&out)
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let Some(new) = Fixture::start_empty() else {
        return;
    };
    let o = new.outsider(&format!(
        "echo '{PASSPHRASE}' | \"$SV\" import --passphrase-stdin '{}' >/dev/null && cat \"$MNT/config\"",
        out.display()
    ));
    assert_eq!(stdout(&o), CONFIG, "import should unlock its shell: {o:?}");
    assert_eq!(stdout(&new.outsider("cat \"$MNT/config\"")), "");
}

#[test]
fn export_never_overwrites_a_file() {
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let out = f.path("export.age");
    std::fs::write(&out, "keep me").unwrap();
    assert!(!export_from_unlocked_shell(&f, &out).status.success());
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep me");
}

#[test]
fn import_checks_the_passphrase_before_storing() {
    let Some(old) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let out = old.path("export.age");
    assert!(export_from_unlocked_shell(&old, &out).status.success());
    let Some(new) = Fixture::start_empty() else {
        return;
    };
    assert!(!import(&new, &out, "wrong").status.success());
    let status = new.command(BIN).arg("status").output().unwrap();
    assert!(stdout(&status).contains("no vault yet"), "{status:?}");
}

#[test]
fn replacing_a_vault_needs_an_unlocked_shell_and_keeps_the_old_one() {
    const OTHER: &str = "Host x\n  User replaced\n";
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let Some(other) = Fixture::start(&[("config", OTHER)]) else {
        return;
    };
    let replacement = other.path("export.age");
    assert!(
        export_from_unlocked_shell(&other, &replacement)
            .status
            .success()
    );

    assert!(!import(&f, &replacement, PASSPHRASE).status.success());
    assert_eq!(stdout(&f.unlocked_shell("cat \"$MNT/config\"")), CONFIG);

    let unlock = "printf '%s\\n' \"$PW\" | \"$SV\" unlock --passphrase-stdin >/dev/null && ";
    let mut shell = f.command("sh");
    shell.env("PW", PASSPHRASE).args([
        "-c",
        &format!(
            "{unlock}printf '%s\\n' \"$PW\" | \"$SV\" import --passphrase-stdin '{}' >/dev/null && cat \"$MNT/config\"",
            replacement.display()
        ),
    ]);
    let o = shell.output().unwrap();
    assert_eq!(stdout(&o), OTHER, "{o:?}");
    let previous = f.path(&format!("state/{}/default.sshvault.previous", uid()));
    assert!(previous.exists(), "no backup at {}", previous.display());
}

#[test]
fn ssh_records_host_keys_in_the_vault_and_ssh_keygen_can_remove_them() {
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
         IdentitiesOnly yes\n  IdentityAgent none\n  BatchMode yes\n  UserKnownHostsFile @MNT@/known_hosts\n  \
         StrictHostKeyChecking accept-new\n  LogLevel ERROR\n",
        sshd.port
    );
    let Some(f) = Fixture::start(&[("config", &config), ("id_test", &private)]) else {
        return;
    };
    let stub = write_stub(&f);
    let first = f.unlocked_shell(&format!("ssh -F {} vaulthost echo first", stub.display()));
    assert_eq!(stdout(&first), "first\n", "{first:?}");

    f.wait_until_locked();
    let strict = f.unlocked_shell(&format!(
        "ssh -F {} -o StrictHostKeyChecking=yes vaulthost echo known; grep -c . \"$MNT/known_hosts\"",
        stub.display()
    ));
    assert_eq!(stdout(&strict), "known\n1\n", "{strict:?}");

    let removed = f.unlocked_shell(&format!(
        "ssh-keygen -q -R '[127.0.0.1]:{}' -f \"$MNT/known_hosts\" >/dev/null && grep -c . \"$MNT/known_hosts\"; test -s \"$MNT/known_hosts.old\" && echo backup",
        sshd.port
    ));
    assert_eq!(stdout(&removed), "0\nbackup\n", "{removed:?}");
}

#[test]
fn vim_can_edit_the_config() {
    let Some(vim) = which("vim").or_else(|| which("vim.tiny")) else {
        eprintln!("skipping: no vim");
        return;
    };
    let Some(f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    let o = f.unlocked_shell(&format!(
        "cd \"$MNT\" && '{}' -N -u NONE -es -c '%s/fromvault/vim/' -c wq config </dev/null; cat config; ls -A",
        vim.display()
    ));
    assert_eq!(stdout(&o), "Host x\n  User vim\nconfig\n", "{o:?}");
}

#[test]
fn create_makes_an_empty_vault_and_unlocks_its_shell() {
    let Some(f) = Fixture::start_empty() else {
        return;
    };
    let o = f.outsider(&format!(
        "echo '{PASSPHRASE}' | \"$SV\" create --passphrase-stdin --work-factor 10 >/dev/null && ls -A \"$MNT\" && echo 'Host n' > \"$MNT/config\" && cat \"$MNT/config\""
    ));
    assert_eq!(stdout(&o), "Host n\n", "{o:?}");
    assert_eq!(stdout(&f.outsider("cat \"$MNT/config\"")), "");
    f.wait_until_locked();
    assert_eq!(stdout(&f.unlocked_shell("cat \"$MNT/config\"")), "Host n\n");
}

#[test]
fn create_with_no_unlock_leaves_the_shell_locked() {
    let Some(f) = Fixture::start_empty() else {
        return;
    };
    let o = f.outsider(&format!(
        "echo '{PASSPHRASE}' | \"$SV\" create --no-unlock --passphrase-stdin --work-factor 10 >/dev/null && \"$SV\" status"
    ));
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(stdout(&o).starts_with("default: locked here"), "{o:?}");
}

#[test]
fn status_right_after_a_restart_lists_the_vaults() {
    let Some(mut f) = Fixture::start(&[("config", CONFIG)]) else {
        return;
    };
    f.restart_daemon();
    let o = f.command(BIN).arg("status").output().unwrap();
    assert!(stdout(&o).starts_with("default: locked here"), "{o:?}");
}
