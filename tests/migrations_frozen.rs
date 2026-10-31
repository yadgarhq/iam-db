//! Every migration iam-db has shipped stays byte for byte as it shipped
//! (yaadgaar #488, #249).
//!
//! `yadgar-store` records a SHA-256 of each applied migration's exact bytes and
//! refuses to boot when a recorded digest differs from the binary's. So a
//! cosmetic edit to an applied migration (a re-indent, a move to another
//! module, a change to a `format!` constant its SQL is built from) reaches no
//! deployed store as new SQL and instead stops every one of them booting.
//!
//! The digests are of each migration's SQL as `origin/main` carried it when this
//! file was written. They are literals, never derived at run time. The
//! comparison uses `Migration::checksum`, the same function the boot check
//! calls, so this test and the boot refusal cannot disagree about what a digest
//! is.

use yadgar_iam_db::schema;

const FROZEN: [(u64, &str, &str); 21] = [
    (
        1,
        "create_user",
        "53d694dd75b74cfe41dbfae587e6df5e6ffa4040c655f81574b5961a26cfcbc3",
    ),
    (
        2,
        "create_password",
        "e0c96ae7bfe2636690151579dde43daef613bcf8c0d6ee330940f3e2f8234146",
    ),
    (
        3,
        "create_team",
        "04fca9d3139bab267e27a401540bcd90384f14f410c89bc9927e8cecc78c3ab8",
    ),
    (
        4,
        "create_team_member",
        "c1d8196d6245e4d084d5d7c51fc49fb5686a1c13478660328bd3d0846e54b338",
    ),
    (
        5,
        "create_credential",
        "5b646a1c01dacf99245ece72f92b035a38d81dc627c294c7147103d37585ca7b",
    ),
    (
        6,
        "create_enrolment",
        "428ef17aecc6294b46e2022aca458a31f70a30d8fe1fad73f9838cf85e1691fa",
    ),
    (
        7,
        "create_enrolment_redemption",
        "9f2220409f27963e3a8f5f87c4bbf6e5c2a20c9e28ba6cbe38d9dac2e576b304",
    ),
    (
        8,
        "add_user_is_admin",
        "33bb6b1d6084d3badc556cd9fdcafd10af16f6fd4bb974ee1c6a422bfb45bc7b",
    ),
    (
        9,
        "create_rate_limit_override",
        "4d5827f60a927637f1cff078a08a72d9d696978f656946791d6a76527a655dc3",
    ),
    (
        10,
        "create_org_setting",
        "205c699b15afcd173daafaad077c583f3f09630f1e10069328d78a4248c35b0e",
    ),
    (
        11,
        "create_team_setting_override",
        "060c87a0272743bacf50bd952c746f283b3097ce274a17d064de10f0bd9dd210",
    ),
    (
        12,
        "seed_owner_reads_own_record",
        "3464604d739b10a947463721a5fb34d5244dfbfa632e885977a43839e42f931e",
    ),
    (
        13,
        "create_inherited_setting_write",
        "12ffb6501a330f4b60098f9b0b481bd093b9b65f1c79198379048e5618474834",
    ),
    (
        14,
        "create_key_identity",
        "5ebeb1395b6fd040261954c8059ef022f38e92fd1a3e83e53394868e4f7a52b7",
    ),
    (
        15,
        "enrolment_revokes_existing_credentials",
        "782f92a11203902434deb3f594a1ed17e41ede1b083759a1f214b324ac486b42",
    ),
    (
        16,
        "user_credential_epoch",
        "4958d57c248ff422cf12a85269eb9691cfbb7c2c2444c71887e487103d40a7d8",
    ),
    (
        17,
        "enrolment_voided_at",
        "be5c15579bcb0dc7fb8fd3db14640270cd6edfb171d6786690b4895781fd9244",
    ),
    (
        18,
        "redemption_credential_epoch",
        "07a46fbcded43d2eac0c053c8471cb98f22621277d948a34655b6ba8f43cac34",
    ),
    (
        19,
        "create_team_member_pending",
        "da7dc0ff1992fcdea2dbcdb70886b5f46f7b6a1a39370e85ec31fc2fd2077d52",
    ),
    (
        20,
        "create_team_sync_lock",
        "22f3d0f379360a4c634a191fb85094befe3708cc823b70db36b3654db7704c13",
    ),
    (
        21,
        "seed_team_sync_lock",
        "1fac0e63bc64b607806b678e974086048cd6d8eff1978696d43bbff7a5677672",
    ),
];

#[test]
fn every_shipped_migration_is_unchanged() {
    let set = schema::migrations().expect("set");
    let all: Vec<_> = set.pending_after(0).collect();
    for (version, name, digest) in FROZEN {
        let m = all
            .iter()
            .find(|m| m.version == version)
            .unwrap_or_else(|| panic!("migration {version} is gone"));
        assert_eq!(m.name, name, "migration {version} was renamed");
        assert_eq!(
            m.checksum(),
            digest,
            "migration {version} ({name}) was edited"
        );
    }
}

#[test]
fn the_set_holds_exactly_the_frozen_migrations() {
    // A new migration is added here deliberately, with its digest, in the PR
    // that adds it. Forgetting to is the failure this assertion names.
    let set = schema::migrations().expect("set");
    let expected: Vec<u64> = FROZEN.iter().map(|(v, _, _)| *v).collect();
    assert_eq!(set.versions(), expected);
}
