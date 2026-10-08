# ual

Windows Server's User Access Logging (UAL, Windows Server 2012 and later, `Windows\System32\LogFiles\Sum`), for forensics: which accounts and addresses used which of the server's roles (file server, Active Directory, print, …), when first and last, and how many times on each day of the year. It outlives event log rollover: a year of lateral movement to a server in one table. Read with [`sootmark-ese`](https://crates.io/crates/sootmark-ese), an ESE reader written from the format; no other dependency but their sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-ual = "0.1"
```

```rust
let identity = ual::read_identity(&std::fs::read("Sum/SystemIdentity.mdb")?)?;
let year = ual::read_year(&std::fs::read("Sum/Current.mdb")?)?;
for client in &year.clients {
    let role = identity.role_name(&client.role).unwrap_or("?");
    println!("{:?} from {:?} used {role} {} times", client.user, client.address, client.total_accesses);
}
```

## What you get

- `read_year(bytes)` for `Current.mdb` and each earlier year's `{GUID}.mdb`:
  - `clients` (`CLIENTS`): the role used, the account (`CONTOSO\alice`, `ual\dc-1$`), the address (IPv4 or IPv6), the tenant, the year's total accesses, its first and last access (UTC), and every day of the year with accesses and how many (`Day1` to `Day366`);
  - `roles` (`ROLE_ACCESS`): each role's first and last use;
  - `resolutions` (`DNS`): the names addresses resolved to, and when last seen;
  - `virtual_machines` (`VIRTUALMACHINES`): the virtual machines hosted, with their identifiers, creation and last activity.
- `read_identity(bytes)` for `SystemIdentity.mdb`: the server (`SYSTEM_IDENTITY`: host and domain names, Windows version, hardware), which file holds which year (`CHAINED_DATABASES`), and the roles' names (`ROLE_IDS`, with `role_name(id)`).
- `detect(name)`: which database a file is, by name.
- Times are FILETIMEs kept in columns typed as dates, read as such. Damage goes to `problems`, never a panic.

## How it's checked

- plaso's test databases (Apache-2.0, a Windows Server 2019 domain controller, `tests/fixtures/plaso/`, see its `NOTICE`): every row against plaso's own User Access Logging parser (`tests/oracle/`): 14 clients with their roles, accounts, addresses, counts and both times, 3 roles, 6 name resolutions and 2 system identities, all 42 of plaso's events, equal. plaso doesn't read the per-day counts: each client's counted day is checked to be the day of its accesses.
- Property tests: arbitrary bytes, and a database damaged anywhere, give rows, problems or an error, never a panic.

## Licence

MIT or Apache-2.0, at your option.
