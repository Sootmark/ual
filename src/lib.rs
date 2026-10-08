//! Windows Server's User Access Logging (UAL, Windows Server 2012 and
//! later, `Windows\System32\LogFiles\Sum`), for forensics: which accounts
//! and addresses used which of the server's roles (file server, Active
//! Directory, …), when first and last, and how many times each day of the
//! year. It survives event log rollover: a year of lateral movement to a
//! server in one table.
//!
//! The folder holds ESE databases, read with `sootmark-ese`:
//!
//! - `Current.mdb` and one `{GUID}.mdb` per earlier year: who used which
//!   role (`CLIENTS`, with a count for each day of the year), each role's
//!   first and last use (`ROLE_ACCESS`), the addresses names resolved to
//!   (`DNS`) and the virtual machines hosted (`VIRTUALMACHINES`);
//! - `SystemIdentity.mdb`: the server's identity (`SYSTEM_IDENTITY`), which
//!   file holds which year (`CHAINED_DATABASES`) and the roles' names
//!   (`ROLE_IDS`).
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let identity = ual::read_identity(&std::fs::read("Sum/SystemIdentity.mdb")?)?;
//! let year = ual::read_year(&std::fs::read("Sum/Current.mdb")?)?;
//! for client in &year.clients {
//!     let role = identity.role_name(&client.role).unwrap_or("?");
//!     println!("{:?} from {:?} used {role} {} times", client.user, client.address, client.total_accesses);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Damage is reported in `problems`, never a panic; a value of the wrong
//! type is left empty.

use std::net::{Ipv4Addr, Ipv6Addr};

use common::time::Ts;
use ese::{Database, Table, Value};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The days a `CLIENTS` row counts (`Day1` to `Day366`).
const DAYS: u16 = 366;

/// Which UAL database a file is, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `Current.mdb` or a `{GUID}.mdb`: a year's accesses.
    Year,
    /// `SystemIdentity.mdb`: the server, its years and its roles.
    Identity,
}

/// The kind of UAL database `name` (a path or a bare name) is, case
/// ignored.
#[must_use]
pub fn detect(name: &str) -> Option<Kind> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let upper = base.to_ascii_uppercase();
    let stem = upper.strip_suffix(".MDB")?;
    if stem == "SYSTEMIDENTITY" {
        Some(Kind::Identity)
    } else if stem == "CURRENT" || is_braced_guid(stem) {
        Some(Kind::Year)
    } else {
        None
    }
}

/// `{8-4-4-4-12}` hex digits.
fn is_braced_guid(text: &str) -> bool {
    let Some(inner) = text.strip_prefix('{').and_then(|t| t.strip_suffix('}')) else {
        return false;
    };
    let groups: Vec<&str> = inner.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A client's use of a role during the year.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// The role used (`{10a9226f-50ee-49d8-a393-9a501d47ce04}`): named in
    /// `SystemIdentity.mdb`'s `ROLE_IDS`.
    pub role: String,
    /// The tenant (Hyper-V and the like), `None` when unset.
    pub tenant: Option<String>,
    /// Accesses during the year.
    pub total_accesses: u32,
    /// When the row was first written: the year's first access.
    pub first_access: Option<Ts>,
    /// The year's last access.
    pub last_access: Option<Ts>,
    /// Where from (`10.0.10.21`, `fe80::…`).
    pub address: Option<String>,
    /// The account (`CONTOSO\alice`, `ual\dc-1$`).
    pub user: Option<String>,
    /// The client's name, rarely set.
    pub client_name: Option<String>,
    /// The days of the year with accesses, and how many: (day 1 to 366,
    /// count).
    pub days: Vec<(u16, u16)>,
}

/// A role's first and last use during the year.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAccess {
    /// The role.
    pub role: String,
    /// Its first use.
    pub first_seen: Option<Ts>,
    /// Its last use.
    pub last_seen: Option<Ts>,
}

/// A name an address was resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The address.
    pub address: String,
    /// The name.
    pub host: String,
    /// When last seen.
    pub last_seen: Option<Ts>,
}

/// A virtual machine the server hosted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualMachine {
    /// Its identifier.
    pub id: Option<String>,
    /// Its BIOS identifier.
    pub bios: Option<String>,
    /// When created.
    pub created: Option<Ts>,
    /// When last seen active.
    pub last_active: Option<Ts>,
    /// Its serial number.
    pub serial: Option<String>,
}

/// A year's database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Year {
    /// `CLIENTS`.
    pub clients: Vec<Client>,
    /// `ROLE_ACCESS`.
    pub roles: Vec<RoleAccess>,
    /// `DNS`.
    pub resolutions: Vec<Resolution>,
    /// `VIRTUALMACHINES`.
    pub virtual_machines: Vec<VirtualMachine>,
    /// Damage met.
    pub problems: Vec<String>,
}

/// The server, as `SYSTEM_IDENTITY` describes it (one row per change).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    /// When the row was written.
    pub created: Option<Ts>,
    /// The server's DNS host name.
    pub host_name: Option<String>,
    /// Its domain.
    pub domain: Option<String>,
    /// Windows' version (`10.0.17763`).
    pub os_version: Option<String>,
    /// Its manufacturer, model and serial number.
    pub manufacturer: Option<String>,
    /// Its model.
    pub product: Option<String>,
    /// Its serial number.
    pub serial: Option<String>,
}

/// `SystemIdentity.mdb`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// `SYSTEM_IDENTITY`.
    pub systems: Vec<System>,
    /// `CHAINED_DATABASES`: which file holds which year.
    pub years: Vec<(u16, String)>,
    /// `ROLE_IDS`: each role's identifier, product and name.
    pub roles: Vec<Role>,
    /// Damage met.
    pub problems: Vec<String>,
}

/// A role the server has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    /// Its identifier.
    pub id: String,
    /// The product it belongs to (an identifier).
    pub product: Option<String>,
    /// Its name (`File Server`).
    pub name: Option<String>,
}

impl Identity {
    /// The name of role `id`, if listed (case ignored).
    #[must_use]
    pub fn role_name(&self, id: &str) -> Option<&str> {
        self.roles
            .iter()
            .find(|role| role.id.eq_ignore_ascii_case(id))
            .and_then(|role| role.name.as_deref())
    }
}

/// Why a database can't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Read a year's database (`Current.mdb`, `{GUID}.mdb`).
///
/// # Errors
/// When it isn't an ESE database, or has no `CLIENTS` table.
pub fn read_year(data: &[u8]) -> Result<Year, Error> {
    let db = open(data, "CLIENTS")?;
    let mut year = Year {
        problems: db.problems.clone(),
        ..Year::default()
    };
    year.clients = rows(&db, "CLIENTS", &mut year.problems, |table, values| {
        let get = |name| field(table, values, name);
        Client {
            role: guid(get("RoleGuid")).unwrap_or_default(),
            tenant: guid(get("TenantId")),
            total_accesses: get("TotalAccesses")
                .and_then(Value::as_i64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0),
            first_access: time(get("InsertDate")),
            last_access: time(get("LastAccess")),
            address: get("Address").and_then(Value::as_bytes).and_then(address),
            user: text(get("AuthenticatedUserName")),
            client_name: text(get("ClientName")),
            days: (1..=DAYS)
                .filter_map(|day| {
                    let count = field(table, values, &format!("Day{day}"))?.as_i64()?;
                    let count = u16::try_from(count).ok().filter(|&c| c > 0)?;
                    Some((day, count))
                })
                .collect(),
        }
    });
    year.roles = rows(&db, "ROLE_ACCESS", &mut year.problems, |table, values| {
        let get = |name| field(table, values, name);
        RoleAccess {
            role: guid(get("RoleGuid")).unwrap_or_default(),
            first_seen: time(get("FirstSeen")),
            last_seen: time(get("LastSeen")),
        }
    });
    year.resolutions = rows(&db, "DNS", &mut year.problems, |table, values| {
        let get = |name| field(table, values, name);
        Resolution {
            address: text(get("Address")).unwrap_or_default(),
            host: text(get("HostName")).unwrap_or_default(),
            last_seen: time(get("LastSeen")),
        }
    });
    year.virtual_machines = rows(
        &db,
        "VIRTUALMACHINES",
        &mut year.problems,
        |table, values| {
            let get = |name| field(table, values, name);
            VirtualMachine {
                id: guid(get("VmGuid")),
                bios: guid(get("BIOSGuid")),
                created: time(get("CreationTime")),
                last_active: time(get("LastSeenActive")),
                serial: text(get("SerialNumber")),
            }
        },
    );
    Ok(year)
}

/// Read `SystemIdentity.mdb`.
///
/// # Errors
/// When it isn't an ESE database, or has no `ROLE_IDS` table.
pub fn read_identity(data: &[u8]) -> Result<Identity, Error> {
    let db = open(data, "ROLE_IDS")?;
    let mut identity = Identity {
        problems: db.problems.clone(),
        ..Identity::default()
    };
    identity.systems = rows(
        &db,
        "SYSTEM_IDENTITY",
        &mut identity.problems,
        |table, values| {
            let get = |name| field(table, values, name);
            let number = |name| get(name).and_then(Value::as_i64);
            let os_version = match (
                number("OSMajor"),
                number("OSMinor"),
                number("OSBuildNumber"),
            ) {
                (Some(major), Some(minor), Some(build)) => Some(format!("{major}.{minor}.{build}")),
                _ => None,
            };
            System {
                created: time(get("CreationTime")),
                host_name: text(get("SystemDNSHostName")),
                domain: text(get("SystemDomainName")),
                os_version,
                manufacturer: text(get("SystemManufacturer")),
                product: text(get("SystemProductName")),
                serial: text(get("SystemSerialNumber")),
            }
        },
    );
    identity.years = rows(
        &db,
        "CHAINED_DATABASES",
        &mut identity.problems,
        |table, values| {
            let get = |name| field(table, values, name);
            let year = get("Year")
                .and_then(Value::as_i64)
                .and_then(|y| u16::try_from(y).ok())
                .unwrap_or(0);
            (year, text(get("FileName")).unwrap_or_default())
        },
    );
    identity.roles = rows(&db, "ROLE_IDS", &mut identity.problems, |table, values| {
        let get = |name| field(table, values, name);
        Role {
            id: guid(get("RoleGuid")).unwrap_or_default(),
            product: text(get("ProductName")),
            name: text(get("RoleName")),
        }
    });
    Ok(identity)
}

/// Open an ESE database that must have table `required`.
fn open<'a>(data: &'a [u8], required: &str) -> Result<Database<'a>, Error> {
    let db = Database::open(data).map_err(|e| Error(e.to_string()))?;
    if db.table(required).is_none() {
        return Err(Error(format!(
            "no {required} table: not this User Access Logging database"
        )));
    }
    Ok(db)
}

/// Every row of `name` read with `read`, damage to `problems`; none when
/// the table is missing.
fn rows<T>(
    db: &Database<'_>,
    name: &str,
    problems: &mut Vec<String>,
    read: impl Fn(&Table, &[Value]) -> T,
) -> Vec<T> {
    let (Some(table), Ok(mut rows)) = (db.table(name), db.rows(name)) else {
        return Vec::new();
    };
    let found = rows.by_ref().map(|row| read(table, &row.values)).collect();
    problems.extend(rows.problems().iter().map(|p| format!("{name}: {p}")));
    found
}

fn field<'v>(table: &Table, values: &'v [Value], name: &str) -> Option<&'v Value> {
    values
        .get(table.column_index(name)?)
        .filter(|v| !v.is_null())
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_text)
        .map(str::to_owned)
        .filter(|t| !t.is_empty())
}

/// UAL keeps FILETIMEs in columns typed as dates: the bits are the
/// FILETIME.
fn time(value: Option<&Value>) -> Option<Ts> {
    let ticks = match value? {
        Value::DateTime(days) => days.to_bits(),
        Value::I64(ticks) | Value::Currency(ticks) => *ticks as u64,
        _ => return None,
    };
    let ts = Ts::from_filetime(ticks);
    ts.ticks().is_some().then_some(ts)
}

/// A GUID as Windows writes it, lower case, in braces.
fn guid(value: Option<&Value>) -> Option<String> {
    let bytes: [u8; 16] = match value? {
        Value::Guid(bytes) => *bytes,
        Value::Binary(bytes) => bytes.as_slice().try_into().ok()?,
        _ => return None,
    };
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail = common::sha256::hex(&bytes[10..]);
    Some(format!(
        "{{{data1:08x}-{data2:04x}-{data3:04x}-{:02x}{:02x}-{tail}}}",
        bytes[8], bytes[9]
    ))
}

/// An address stored as 4 or 16 bytes.
fn address(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()),
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(
            detect(r"C:\Windows\System32\LogFiles\Sum\Current.mdb"),
            Some(Kind::Year)
        );
        assert_eq!(
            detect("Sum/{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb"),
            Some(Kind::Year)
        );
        assert_eq!(detect("SystemIdentity.mdb"), Some(Kind::Identity));
        assert_eq!(detect("{not-a-guid}.mdb"), None);
        assert_eq!(detect("Current.edb"), None);
    }

    #[test]
    fn guids_addresses_and_times() {
        let stored = Value::Guid([
            131, 204, 15, 197, 141, 188, 245, 77, 138, 61, 137, 215, 248, 15, 7, 75,
        ]);
        assert_eq!(
            guid(Some(&stored)).as_deref(),
            Some("{c50fcc83-bc8d-4df5-8a3d-89d7f80f074b}")
        );
        assert_eq!(address(&[10, 0, 10, 21]).as_deref(), Some("10.0.10.21"));
        let mut loopback = [0; 16];
        loopback[15] = 1;
        assert_eq!(address(&loopback).as_deref(), Some("::1"));
        assert_eq!(address(&[1, 2, 3]), None);
        let filetime = 0x01d8_0000_0000_0000_u64;
        assert_eq!(
            time(Some(&Value::DateTime(f64::from_bits(filetime)))),
            Some(Ts::from_filetime(filetime))
        );
        assert_eq!(time(Some(&Value::Text("x".to_owned()))), None);
    }

    #[test]
    fn other_databases_are_errors() {
        assert!(read_year(b"not a database").is_err());
        assert!(read_identity(&[]).is_err());
    }
}
