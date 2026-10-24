use std::path::Path;

const MAINTAINER: &str = "Torstein Tauno Svendsen <torstei@gmail.com>";

/// The package's Debian-format changelog, one entry per dated release heading in
/// CHANGELOG.md, newest first.
fn debian_changelog(changelog: &str) -> String {
    let mut out = String::new();
    for line in changelog.lines() {
        let Some(heading) = line.strip_prefix("## ") else {
            continue;
        };
        let Some((version, date)) = heading.split_once(" - ") else {
            continue;
        };
        let [year, month, day] = date
            .split('-')
            .map(|part| part.parse::<i64>().expect("release date as YYYY-MM-DD"))
            .collect::<Vec<_>>()[..]
        else {
            panic!("release date as YYYY-MM-DD: {heading}");
        };
        out.push_str(&format!(
            "sshvault ({version}-1) stable; urgency=medium\n\n  \
             * Release {version}; see changelog.gz in this directory.\n\n \
             -- {MAINTAINER}  {}\n\n",
            rfc2822_noon(year, month, day)
        ));
    }
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

fn rfc2822_noon(year: i64, month: i64, day: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // days since 1970-01-01, a Thursday
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    format!(
        "{}, {day:02} {} {year} 12:00:00 +0000",
        WEEKDAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize]
    )
}

#[test]
fn release_dates_get_their_weekday() {
    assert_eq!(
        rfc2822_noon(2026, 10, 23),
        "Fri, 23 Oct 2026 12:00:00 +0000"
    );
    assert_eq!(rfc2822_noon(2024, 2, 29), "Thu, 29 Feb 2024 12:00:00 +0000");
    assert_eq!(rfc2822_noon(1970, 1, 1), "Thu, 01 Jan 1970 12:00:00 +0000");
}

/// The packaged Debian changelog is generated from CHANGELOG.md. Run with
/// SSHVAULT_WRITE_CHANGELOG=1 to regenerate it after dating a release there.
#[test]
fn the_debian_changelog_is_up_to_date() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("packaging/changelog.Debian");
    let generated = debian_changelog(&std::fs::read_to_string(root.join("CHANGELOG.md")).unwrap());
    assert!(
        generated.starts_with("sshvault ("),
        "no dated release in CHANGELOG.md"
    );
    if std::env::var_os("SSHVAULT_WRITE_CHANGELOG").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let packaged = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        packaged == generated,
        "packaging/changelog.Debian is stale; run SSHVAULT_WRITE_CHANGELOG=1 cargo test --test packaging"
    );
}

/// deny.toml serves cargo deny, osv-scanner.toml serves Scorecard and OSV; an advisory
/// accepted in one and not the other would fail one of them.
#[test]
fn both_scanners_accept_the_same_advisories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |name: &str| -> toml::Table {
        std::fs::read_to_string(root.join(name))
            .unwrap()
            .parse()
            .unwrap()
    };
    let ids = |entries: &toml::Value| -> Vec<String> {
        let mut ids: Vec<String> = entries
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(
        ids(&read("deny.toml")["advisories"]["ignore"]),
        ids(&read("osv-scanner.toml")["IgnoredVulns"])
    );
}
