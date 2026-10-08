//! Any input gives rows, problems or an error, never a panic.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..40_000)) {
        let _ = ual::read_year(&data);
        let _ = ual::read_identity(&data);
    }

    #[test]
    fn a_database_damaged(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..100)) {
        let compressed = include_bytes!("fixtures/plaso/{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb.gz");
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut common::gzip::Decoder::new(&compressed[..]), &mut data).unwrap();
        let len = data.len();
        for (at, byte) in flips {
            data[at % len] = byte;
        }
        let _ = ual::read_year(&data);
        let _ = ual::read_identity(&data);
    }
}
