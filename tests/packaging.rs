use std::path::Path;

const MAINTAINER: &str = "Torstein Tauno Svendsen <torstei@gmail.com>";

/// The package's Debian-format changelog, one entry per dated release heading in
/// CHANGELOG.md, newest first. Releases are dated noon, a minute later for each earlier
/// release that day, since every entry needs a later time than the one before it.
fn debian_changelog(changelog: &str) -> String {
    let releases: Vec<(&str, &str)> = changelog
        .lines()
        .filter_map(|line| line.strip_prefix("## ")?.split_once(" - "))
        .collect();
    let mut out = String::new();
    for (index, &(version, date)) in releases.iter().enumerate() {
        let [year, month, day] = date
            .split('-')
            .map(|part| part.parse::<i64>().expect("release date as YYYY-MM-DD"))
            .collect::<Vec<_>>()[..]
        else {
            panic!("release date as YYYY-MM-DD: {version} - {date}");
        };
        let earlier_that_day = releases[index + 1..]
            .iter()
            .filter(|&&(_, other)| other == date)
            .count() as i64;
        out.push_str(&format!(
            "pidvault ({version}-1) stable; urgency=medium\n\n  \
             * Release {version}; see changelog.gz in this directory.\n\n \
             -- {MAINTAINER}  {}\n\n",
            rfc2822(year, month, day, earlier_that_day)
        ));
    }
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

/// Noon plus `minutes` on the given day.
fn rfc2822(year: i64, month: i64, day: i64, minutes: i64) -> String {
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
        "{}, {day:02} {} {year} {:02}:{:02}:00 +0000",
        WEEKDAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        12 + minutes / 60,
        minutes % 60
    )
}

#[test]
fn release_dates_get_their_weekday() {
    assert_eq!(rfc2822(2026, 10, 23, 0), "Fri, 23 Oct 2026 12:00:00 +0000");
    assert_eq!(rfc2822(2024, 2, 29, 0), "Thu, 29 Feb 2024 12:00:00 +0000");
    assert_eq!(rfc2822(1970, 1, 1, 0), "Thu, 01 Jan 1970 12:00:00 +0000");
}

#[test]
fn releases_on_the_same_day_get_later_times() {
    let generated = debian_changelog(
        "## Unreleased\n\n## 0.3.1 - 2026-10-24\n\n## 0.3.0 - 2026-10-24\n\n## 0.2.0 - 2026-10-23\n",
    );
    let times: Vec<&str> = generated
        .lines()
        .filter_map(|line| line.split_once(">  ").map(|(_, time)| time))
        .collect();
    assert_eq!(
        times,
        [
            "Sat, 24 Oct 2026 12:01:00 +0000",
            "Sat, 24 Oct 2026 12:00:00 +0000",
            "Fri, 23 Oct 2026 12:00:00 +0000",
        ]
    );
}

/// The packaged Debian changelog is generated from CHANGELOG.md. Run with
/// PIDVAULT_WRITE_CHANGELOG=1 to regenerate it after dating a release there.
#[test]
fn the_debian_changelog_is_up_to_date() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("packaging/changelog.Debian");
    let generated = debian_changelog(&std::fs::read_to_string(root.join("CHANGELOG.md")).unwrap());
    assert!(
        generated.starts_with("pidvault ("),
        "no dated release in CHANGELOG.md"
    );
    if std::env::var_os("PIDVAULT_WRITE_CHANGELOG").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let packaged = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        packaged == generated,
        "packaging/changelog.Debian is stale; run PIDVAULT_WRITE_CHANGELOG=1 cargo test --test packaging"
    );
}

/// deny.toml serves cargo deny, osv-scanner.toml serves Scorecard and OSV; an advisory
/// accepted in one and not the other would fail one of them. OSV reads a config only
/// beside the lockfile it applies to, so fuzz/ carries a copy for fuzz/Cargo.lock.
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
    assert_eq!(read("osv-scanner.toml"), read("fuzz/osv-scanner.toml"));
}
