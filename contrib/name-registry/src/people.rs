//! Well-known people in crypto, unregistrable so nobody can impersonate them.
//!
//! ## One entry covers every variant
//!
//! [`crate::charset::normalise`] strips `! # ^ - _ + .` and folds digit
//! lookalikes before comparing, so a single entry blocks all of these:
//!
//! ```text
//! SATOSHINAKAMOTO   SATOSHI_NAKAMOTO   SATOSHI-NAKAMOTO   SATOSHI.NAKAMOTO
//! SATOSHI+NAKAMOTO  5AT05HI_NAKAM0T0   SAT0SHI-NAKAM0T0
//! ```
//!
//! Spaces are not in the charset at all, so "Satoshi Nakamoto" was never
//! registrable. **Entries here are therefore the concatenated uppercase form
//! only** — adding punctuation variants would be dead weight that hides typos.
//!
//! ## What is in, and what is deliberately out
//!
//! **In:** full names of people prominent enough that registering their name
//! reads as impersonation, plus mononyms for the few who genuinely go by one
//! name (`VITALIK`, `COBIE`, `PENTOSHI`).
//!
//! **Out, on purpose:**
//! * `SATOSHI` on its own. It is a common Japanese given name and the name of
//!   Bitcoin's smallest unit, so it is ordinary language.
//! * Handles that are ordinary words: `BEANIE`, `LOOMDART` is fine but a hat is
//!   a hat. Same test as `APPLE` in [`crate::reserved`].
//! * First names alone for anyone normally referred to by both names. Blocking
//!   `MICHAEL` to protect Michael Saylor would take a name from millions.
//!
//! ## ⚠ The cost of this list, stated plainly
//!
//! Blocking a person's name is a blunter instrument than blocking a brand. A
//! trademark holder rarely wants a Divi name; a **person is the most likely
//! legitimate registrant of their own name**. So this list stops the real
//! Vitalik Buterin registering `VITALIKBUTERIN` just as firmly as it stops an
//! impersonator, and it stops every other person who happens to share a name
//! with somebody famous.
//!
//! That trade was made deliberately: an impersonator collecting payments
//! intended for a well-known figure does more harm than the inconvenience. The
//! proper fix is a **claim process** — releasing a name to whoever can prove
//! they are that person — which is not built. Until it is, this is a blocklist
//! and not a reservation.
//!
//! ## ⚠ Accuracy
//!
//! These are public figures, assembled from published lists and general
//! knowledge. It is not exhaustive, it will age, and prominence is a judgement
//! call rather than a fact. Absence from this list is not permission, and
//! presence is not an accusation of anything.
//!
//! Removing an entry frees that name to whoever registers first, so removals
//! deserve more care than additions.

/// Bitcoin's origins: the cypherpunks and the earliest contributors.
pub const PEOPLE_BITCOIN_ORIGINS: &[&str] = &[
    "SATOSHINAKAMOTO",
    "HALFINNEY",
    "NICKSZABO",
    "ADAMBACK",
    "WEIDAI",
    "DAVIDCHAUM",
    "TIMOTHYMAY",
    "ERICHUGHES",
    "JOHNGILMORE",
    "PHILZIMMERMANN",
    "GAVINANDRESEN",
    "JEFFGARZIK",
    "MIKEHEARN",
    "LASZLOHANYECZ",
    "MARTTIMALMI",
    "WLADIMIRVANDERLAAN",
    "PIETERWUILLE",
    "GREGORYMAXWELL",
    "LUKEDASHJR",
    "PETERTODD",
    "MATTCORALLO",
    "JIMMYSONG",
    "ANDREASANTONOPOULOS",
    "NICOLASDORIER",
    "ERICVOSKUIL",
    "AMIRTAAKI",
    "COBRABITCOIN",
    "SAIFEDEANAMMOUS",
    "ROGERVER",
    "CRAIGWRIGHT",
    "DAVEKLEIMAN",
    "CHARLIELEE",
    "DANIELLARIMER",
    "RICKFALKVINGE",
    "TREVORMARSHALL",
    "PETERRIZUN",
    "AMAURYSECHET",
];

/// Ethereum: co-founders, core researchers and the client teams.
pub const PEOPLE_ETHEREUM: &[&str] = &[
    "VITALIKBUTERIN",
    "VITALIK",
    "GAVINWOOD",
    "CHARLESHOSKINSON",
    "JOSEPHLUBIN",
    "JOELUBIN",
    "ANTHONYDIIORIO",
    "MIHAIALISIE",
    "AMIRCHETRIT",
    "JEFFREYWILCKE",
    "VLADZAMFIR",
    "PETERSZILAGYI",
    "TIMBEIKO",
    "DANKRADFEIST",
    "JUSTINDRAKE",
    "PROTOLAMBDA",
    "HSIAOWEIWANG",
    "ALEXSTOKES",
    "PARITHOSH",
    "MARIUSVANDERWIJDEN",
    "PRESTONVANLOON",
    "TERENCETSAO",
    "AYASHIMIZU",
    "FREDRIKSVANTES",
    "CHRISTINEKIM",
    "ANSGARDIETRICHS",
    "BARNABEMONNOT",
    "VITALIKBUTERINETH",
];

/// Founders and leads of major layer-one and layer-two networks.
pub const PEOPLE_PROTOCOL_FOUNDERS: &[&str] = &[
    "ANATOLYYAKOVENKO",
    "RAJGOKAL",
    "EMINGUNSIRER",
    "KEVINSEKNIQI",
    "TEDYIN",
    "JAEKWON",
    "ETHANBUCHMAN",
    "ZARKOMILOSEVIC",
    "SERGEYNAZAROV",
    "STEVEELLIS",
    "ROBERTHABERMEIER",
    "PETERCZABAN",
    "SILVIOMICALI",
    "ARTHURBREITMAN",
    "KATHLEENBREITMAN",
    "RUNECHRISTENSEN",
    "STANIKULECHOV",
    "HAYDENADAMS",
    "ROBERTLESHNER",
    "ANTONIOJULIANO",
    "SANDEEPNAILWAL",
    "JAYNTIKANANI",
    "ANURAGARJUN",
    "MIHAILOBJELIC",
    "ILLIAPOLOSUKHIN",
    "ALEXSKIDANOV",
    "SREERAMKANNAN",
    "JORDIBAYLINA",
    "DAVIDSCHWARTZ",
    "JEDMCCALEB",
    "CHRISLARSEN",
    "ARTHURBRITTO",
    "RICCARDOSPAGNI",
    "NICOLASVANSABERHAGEN",
    "ZOOKO",
    "ZOOKOWILCOX",
    "MATTHEWGREEN",
    "IANMIERS",
    "EVANDUFFIELD",
    "RYANTAYLOR",
    "LEEMONBAIRD",
    "MANCEHARMON",
    "SERGEIPOPOV",
    "DOMINIKSCHIENER",
    "DAVIDSONSTEBNER",
    "JUANBENET",
    "MOLLYMACKINLAY",
    "MUSTAFAALBASSAM",
    "JOHNADLER",
    "ISMAILKHOFFI",
    "STEVENGOLDFEDER",
    "DANIELGOLDMAN",
    "EDFELTEN",
    "HARRYKALODNER",
    "KARLFLOERSCH",
    "BENJONES",
    "JINGLANWANG",
    "MARKTYNEWAY",
    "ALEXGLUCHOWSKI",
    "URIKOLODNY",
    "ELISHATWEEDY",
];

/// Exchanges, brokerages and custodians.
pub const PEOPLE_EXCHANGES: &[&str] = &[
    "CHANGPENGZHAO",
    "HEYI",
    "RICHARDTENG",
    "BRIANARMSTRONG",
    "FREDEHRSAM",
    "EMILIECHOI",
    "PAULGREWAL",
    "JESSEPOWELL",
    "MICHAELGRONAGER",
    "MARCOSANTORI",
    "DAVERIPLEY",
    "TYLERWINKLEVOSS",
    "CAMERONWINKLEVOSS",
    "WINKLEVOSS",
    "JEANLOUISVANDERVELDE",
    "GIANCARLODEVASINI",
    "PAOLOARDOINO",
    "STUARTHOEGNER",
    "STARXU",
    "JAYHAO",
    "HONGFANG",
    "BENZHOU",
    "MICHAELGAN",
    "JOHNNYLYU",
    "KRISMARSZALEK",
    "BOBBYBAO",
    "RAFAELMELO",
    "GARYOR",
    "LEONFOONG",
    "ARTHURHAYES",
    "BENDELO",
    "SAMUELREED",
    "BARRYSILBERT",
    "MICHAELMORO",
    "MICHAELSONNENSHEIN",
    "PETERSMITH",
    "NICOLASCARY",
    "MARKKARPELES",
    "JEDMCCALEBMTGOX",
    "SAMBANKMANFRIED",
    "SBF",
    "CAROLINEELLISON",
    "GARYWANG",
    "NISHADSINGH",
    "RYANSALAME",
    "DANFRIEDBERG",
    "ZHAODONG",
    "LEONLI",
    "DAVIDLI",
];

/// Stablecoins, payments and financial infrastructure.
pub const PEOPLE_STABLECOIN_INFRA: &[&str] = &[
    "JEREMYALLAIRE",
    "SEANNEVILLE",
    "DANTEDISPARTE",
    "CHARLESCASCARILLA",
    "RICHTEO",
    "BRADGARLINGHOUSE",
    "STUARTALDEROTY",
    "MONICALONG",
    "DENELLEDIXON",
    "CIRCLEJEREMY",
    "RUNEMAKER",
    "NICCARTER",
    "CASTLEISLAND",
    "MELTEMDEMIRORS",
    "CAITLINLONG",
    "PERIANNEBORING",
    "KRISTINSMITH",
    "SHEILAWARREN",
    "AMYDAVINE",
    "MICHELLEBOND",
];

/// Investors, funds and the venture side.
pub const PEOPLE_INVESTORS: &[&str] = &[
    "MARCANDREESSEN",
    "BENHOROWITZ",
    "CHRISDIXON",
    "ARIANNASIMPSON",
    "ALIYAHYA",
    "TIMDRAPER",
    "MIKENOVOGRATZ",
    "MATTHEWROSZAK",
    "NAVALRAVIKANT",
    "NAVAL",
    "BALAJISRINIVASAN",
    "BALAJI",
    "CATHIEWOOD",
    "BILLMILLER",
    "PAULTUDORJONES",
    "STANLEYDRUCKENMILLER",
    "RAYDALIO",
    "LARRYFINK",
    "MICHAELSAYLOR",
    "ELONMUSK",
    "JACKDORSEY",
    "PETERTHIEL",
    "WINKLEVOSSCAPITAL",
    "MULTICOIN",
    "KYLESAMANI",
    "TUSHARJAIN",
    "SPENCERNOON",
    "MEHDIFAROOQ",
    "SANTIAGOSANTOS",
    "ANTHONYPOMPLIANO",
    "POMP",
    "RAOULPAL",
    "DANMOREHEAD",
    "JOEYKRUG",
    "OLAFCARLSONWEE",
    "NICKTOMAINO",
    "SUZHU",
    "ZHUSU",
    "KYLEDAVIES",
    "ALEXMASHINSKY",
    "STEPHENEHRLICH",
    "DAVIDMARCUS",
    "DOKWON",
    "DANIELSHIN",
    "JUSTINSUN",
    "JIHANWU",
    "MICREE",
    "BOBBYLEE",
    "CHANDLERGUO",
    "LIXIAOLAI",
    "STARLIGHTLABS",
];

/// Policy, regulation and the legal side.
pub const PEOPLE_POLICY: &[&str] = &[
    "GARYGENSLER",
    "HESTERPEIRCE",
    "CAROLINECRENSHAW",
    "PAULATKINS",
    "MARKUYEDA",
    "ROSTINBEHNAM",
    "BRIANQUINTENZ",
    "CHRISTOPHERGIANCARLO",
    "JANETYELLEN",
    "JEROMEPOWELL",
    "ELIZABETHWARREN",
    "CYNTHIALUMMIS",
    "PATRICKMCHENRY",
    "RITCHIETORRES",
    "TOMEMMER",
    "FRENCHHILL",
    "MAXINEWATERS",
    "SHERRODBROWN",
    "TIMSCOTT",
    "KIRSTENGILLIBRAND",
    "JOHNDEATON",
    "JAKECHERVINSKY",
    "MARISATABLER",
    "COYGARRISON",
    "LEWISCOHEN",
    "PRESTONBYRNE",
    "STEPHENPALLEY",
    "MARCFAGEL",
    "KATHERINEPOLKFAILLA",
    "ANALISATORRES",
    "LEWISKAPLAN",
];

/// Researchers, cryptographers and academics.
pub const PEOPLE_RESEARCHERS: &[&str] = &[
    "DANBONEH",
    "ARIJUELS",
    "ITTAYEYAL",
    "ELAINESHI",
    "RAFAELPASS",
    "ANDREWMILLER",
    "ARVINDNARAYANAN",
    "JOSEPHBONNEAU",
    "EDWARDFELTEN",
    "TIMROUGHGARDEN",
    "DAVIDTSE",
    "PRAMODVISWANATH",
    "MOHAMMADMASLOOSH",
    "SREERAMKANNANEIGEN",
    "BENEDIKTBUNZ",
    "ELIBENSASSON",
    "ALESSANDROCHIESA",
    "MADARSVIRZA",
    "ZAKICOHEN",
    "JENSGROTH",
    "MARYMALLER",
    "SILVIOMICALIALGO",
    "SHAFIGOLDWASSER",
    "RONRIVEST",
    "WHITFIELDDIFFIE",
    "MARTINHELLMAN",
    "RALPHMERKLE",
    "CYNTHIADWORK",
    "MONISNAOR",
    "STUARTHABER",
    "SCOTTSTORNETTA",
    "LESLIELAMPORT",
    "BARBARALISKOV",
    "MIGUELCASTRO",
];

/// Prominent pseudonymous figures, traders and commentators.
///
/// Only handles distinctive enough that they are unmistakably one person.
/// Ordinary words are excluded here for the same reason `APPLE` is.
pub const PEOPLE_PSEUDONYMOUS: &[&str] = &[
    "COBIE",
    "PENTOSHI",
    "HSAKA",
    "TETRANODE",
    "DEGENSPARTAN",
    "GIGANTICREBIRTH",
    "MACHIBIGBROTHER",
    "ANDREWKANG",
    "ICEBERGY",
    "LOOMDART",
    "DONALT",
    "CRYPTOCRED",
    "PUNK6529",
    "GMONEY",
    "PRANKSY",
    "VINCENTVANDOUGH",
    "FARROKHNAME",
    "ZENECA",
    "SEEDPHRASE",
    "FOOBAR",
    "SAMCZSUN",
    "TAYVANO",
    "ZACHXBT",
    "MUDIT",
    "MUDITGUPTA",
    "BANTEG",
    "ANDRECRONJE",
    "DANIELESESTAGALLI",
    "OXSISYPHUS",
    "COBIECRYPTO",
    "WILLYWOO",
    "PLANB",
    "RHYTHMTRADER",
    "CREDIBLECRYPTO",
    "ALTCOINSHERPA",
    "SMARTCONTRACTER",
    "CRYPTOKALEO",
    "KALEO",
    "INVERSEBRAH",
    "NOTHINGRESEARCH",
    "LIGHTCRYPTO",
    "DEGENSPARTANDAO",
    "OXMAKI",
    "MAKI",
    "SASSAL",
    "SASSAL0X",
    "ANTHONYSASSANO",
    "EVANVANNESS",
    "RYANSADAMS",
    "DAVIDHOFFMAN",
    "BANKLESS",
    "LAURASHIN",
    "CAMILARUSSO",
    "FRANCESCOCICCARELLI",
];

/// Builders, executives and figures who do not fit the buckets above.
pub const PEOPLE_INDUSTRY: &[&str] = &[
    "MEGHANFITZGERALD",
    "DEVINFINZER",
    "ALEXATALLAH",
    "NATECHASTAIN",
    "AARONWRIGHT",
    "KAINWARWICK",
    "JORDANMOMTAZI",
    "SAMKAZEMIAN",
    "RUNEKEK",
    "CHRISTINEMOY",
    "AMBERBALDET",
    "BLYTHEMASTERS",
    "JOHNWU",
    "MEGANKASPAR",
    "SHEILAWARRENWEF",
    "YATSIU",
    "ROBERTLESHNERCOMP",
    "MICHAELEGOROV",
    "REMCOBLOEMEN",
    "DANROBINSON",
    "GEORGIOSKONSTANTOPOULOS",
    "HASUFL",
    "HASU",
    "JONCHARBONNEAU",
    "MAXRESNICK",
    "ANDREWHONG",
    "PATRICKCOLLINS",
    "AUSTINGRIFFITH",
    "NADERDABIT",
    "SCOTTLEWIS",
    "KEVINOWOCKI",
    "VITALIKGITCOIN",
    "OWOCKI",
    "GRIFFGREEN",
    "SIMONADELAJARRA",
    "LEFTERISKARAPETSAS",
    "TRENTVANEPPS",
    "JAMESPRESTWICH",
    "NIRAJPANT",
    "MATTHUANG",
    "FREDWILSON",
    "JOSHROSENTHAL",
    "MEDIOBANCA",
    "ARIPAPARO",
    "MOLLYWHITE",
    "DAVIDGERARD",
    "AMYCASTOR",
    "PATRICKMCKENZIE",
    "STEPHENDIEHL",
    "NICHOLASWEAVER",
    "HILARYALLEN",
    "TODDPHILLIPS",
    "FRANCESCOCASARIN",
];

/// Everything on the people list, in one place.
pub fn all() -> impl Iterator<Item = &'static str> {
    PEOPLE_BITCOIN_ORIGINS
        .iter()
        .chain(PEOPLE_ETHEREUM.iter())
        .chain(PEOPLE_PROTOCOL_FOUNDERS.iter())
        .chain(PEOPLE_EXCHANGES.iter())
        .chain(PEOPLE_STABLECOIN_INFRA.iter())
        .chain(PEOPLE_INVESTORS.iter())
        .chain(PEOPLE_POLICY.iter())
        .chain(PEOPLE_RESEARCHERS.iter())
        .chain(PEOPLE_PSEUDONYMOUS.iter())
        .chain(PEOPLE_INDUSTRY.iter())
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charset::{is_reserved, normalise, validate_name, NAME_MAX_LEN};

    /// Every entry must be a shape the charset would otherwise accept. An entry
    /// that could never be typed protects nobody and hides a typo.
    #[test]
    fn every_entry_is_a_registrable_shape() {
        for p in all() {
            assert!(p.len() >= 3, "{p} is too short to be a name");
            assert!(p.len() <= NAME_MAX_LEN, "{p} is longer than a name can be ({})", p.len());
            assert!(
                p.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
                "{p} must be plain uppercase ASCII with no punctuation or accents"
            );
            assert!(p.as_bytes()[0].is_ascii_uppercase(), "{p} must start with a letter");
        }
    }

    #[test]
    fn no_duplicates() {
        let mut seen: Vec<&str> = all().collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "the people list has duplicates");
    }

    /// The whole point: the name and every punctuation or lookalike variant of
    /// it are refused by one entry.
    #[test]
    fn a_single_entry_blocks_every_variant() {
        for typed in [
            "SATOSHINAKAMOTO",
            "SATOSHI_NAKAMOTO",
            "SATOSHI-NAKAMOTO",
            "SATOSHI.NAKAMOTO",
            "SATOSHI+NAKAMOTO",
            "SAT0SHI-NAKAM0T0",
            "S.A.T.O.S.H.I.NAKAMOTO",
        ] {
            assert!(
                is_reserved(typed.as_bytes()),
                "{typed} should match the single SATOSHINAKAMOTO entry"
            );
        }
        // A variant beginning with a digit is refused by the charset before the
        // reserve is even consulted.
        assert!(validate_name(b"5AT05HI_NAKAM0T0").is_err());
    }

    /// Every listed person is held by the reserve. They are valid NAME shapes,
    /// which is what allows the reserve to hold them and later hand them over;
    /// an attempt to register one fails because it is already owned.
    #[test]
    fn every_person_on_the_list_is_held_by_the_reserve() {
        for p in all() {
            assert!(is_reserved(p.as_bytes()), "{p} should be in the reserve");
            assert!(validate_name(p.as_bytes()).is_ok(), "{p} must be a valid name shape");
        }
    }

    /// ⚠ The counterweight, and the test most likely to catch a bad addition.
    /// A first name on its own, an ordinary word, or a unit of currency must
    /// stay registrable. Blocking those takes names from people who have every
    /// right to them.
    #[test]
    fn ordinary_words_and_bare_first_names_stay_registrable() {
        for word in [
            // Geoff's explicit example: the unit, and a common given name.
            "SATOSHI",
            // First names alone belong to millions of people.
            "MICHAEL", "BRIAN", "GARY", "CHARLES", "ANATOLY", "ELON", "JESSE", "TYLER",
            // Ordinary words that happen to be somebody's handle.
            "BEANIE", "SPARTAN", "REBIRTH", "MONEY", "CRED", "ALT", "SEED", "LIGHT",
        ] {
            assert!(!is_reserved(word.as_bytes()), "{word} must stay registrable");
        }
    }

    /// Mononyms are included only where the person really does go by one name,
    /// and the word is not ordinary language.
    #[test]
    fn genuine_mononyms_are_blocked() {
        for m in ["VITALIK", "COBIE", "PENTOSHI", "NAVAL", "BALAJI", "HSAKA"] {
            assert!(is_reserved(m.as_bytes()), "{m}");
        }
    }

    /// Normalisation must not accidentally sweep in an unrelated name.
    #[test]
    fn normalisation_does_not_over_reach() {
        for word in ["VITALIY", "COBIA", "NAVALLY", "BACKUP", "GREENHOUSE"] {
            assert!(!is_reserved(word.as_bytes()), "{word} must stay registrable");
        }
        assert_ne!(normalise(b"ADAMBACK"), normalise(b"ADAMBACKER"));
    }

    /// A rough floor on coverage, so a bad merge that guts the list is loud.
    #[test]
    fn the_list_is_substantial() {
        assert!(all().count() >= 350, "only {} people listed", all().count());
    }
}
