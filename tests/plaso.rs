//! plaso's User Access Logging test databases (Apache-2.0, a Windows Server
//! 2019 domain controller, `tests/fixtures/plaso/`, stored gzip-compressed):
//! every client, role, name resolution and system identity row against
//! plaso's own reading (`tests/oracle/plaso.tsv`), and the per-day counts.

use std::collections::BTreeSet;
use std::io::Read;

use common::time::Ts;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/plaso/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// A time as a FILETIME, as plaso writes it.
fn filetime(time: Option<Ts>) -> String {
    time.and_then(|t| t.ticks())
        .map(|ticks| (ticks + 116_444_736_000_000_000).to_string())
        .unwrap_or_default()
}

#[test]
fn every_row_matches_plaso() {
    let identity = ual::read_identity(&fixture("SystemIdentity.mdb")).unwrap();
    let year = ual::read_year(&fixture("{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb")).unwrap();
    assert_eq!((identity.problems.len(), year.problems.len()), (0, 0));
    let name = |role: &str| identity.role_name(role).unwrap_or("Unknown").to_owned();
    let mut lines = BTreeSet::new();
    for client in &year.clients {
        lines.insert(
            [
                "client".to_owned(),
                client.role.clone(),
                name(&client.role),
                client.user.clone().unwrap_or_default(),
                client.address.clone().unwrap_or_default(),
                client.total_accesses.to_string(),
                filetime(client.first_access),
                filetime(client.last_access),
                client.tenant.clone().unwrap_or_default(),
            ]
            .join("\t"),
        );
    }
    for role in &year.roles {
        lines.insert(
            [
                "role".to_owned(),
                role.role.clone(),
                name(&role.role),
                filetime(role.first_seen),
                filetime(role.last_seen),
            ]
            .join("\t"),
        );
    }
    for resolution in &year.resolutions {
        lines.insert(
            [
                "dns".to_owned(),
                resolution.address.clone(),
                resolution.host.clone(),
                filetime(resolution.last_seen),
            ]
            .join("\t"),
        );
    }
    for system in &identity.systems {
        let build = system
            .os_version
            .as_deref()
            .and_then(|v| v.rsplit('.').next())
            .unwrap_or_default();
        lines.insert(
            [
                "system".to_owned(),
                filetime(system.created),
                system.host_name.clone().unwrap_or_default(),
                system.domain.clone().unwrap_or_default(),
                build.to_owned(),
            ]
            .join("\t"),
        );
    }
    let expected: BTreeSet<String> = include_str!("oracle/plaso.tsv")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines, expected);
    assert_eq!(
        identity.years,
        [(
            2022,
            "{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb".to_owned()
        )]
    );
    assert_eq!(identity.roles.len(), 14);
}

#[test]
fn days_count_the_accesses() {
    let year = ual::read_year(&fixture("{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb")).unwrap();
    for client in &year.clients {
        // One day of use here: the day of the year of its accesses
        // (2022-07-16, day 197), its count no more than the total.
        assert_eq!(client.days.len(), 1, "{client:?}");
        let (day, count) = client.days[0];
        let first = client.first_access.and_then(|t| t.to_iso8601()).unwrap();
        assert!(first.starts_with("2022-07-16"), "{first}");
        assert_eq!(day, 197);
        assert!(u32::from(count) <= client.total_accesses);
    }
}
