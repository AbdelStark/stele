//! RFC-0002 §7 — separate control harness; never linked into a prover or verifier.
#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod batching;
pub mod catalog;
#[doc(hidden)]
pub mod development;
#[doc(hidden)]
pub mod fraction;
#[doc(hidden)]
pub mod fraction_transcript;
#[doc(hidden)]
pub mod integer_linear;
#[doc(hidden)]
pub mod lookup;
#[cfg(feature = "standard-unproven")]
#[doc(hidden)]
pub mod lookup_grind;
#[doc(hidden)]
pub mod matmul;
#[doc(hidden)]
pub mod pcs;
#[doc(hidden)]
pub mod pcs_a1;
#[doc(hidden)]
pub mod pcs_expander;
#[doc(hidden)]
pub mod pcs_opening;
#[doc(hidden)]
pub mod pcs_opening_continuation;
#[doc(hidden)]
pub mod pcs_opening_field;
#[cfg(feature = "standard-unproven")]
#[doc(hidden)]
pub mod pcs_policy2;
#[doc(hidden)]
pub mod requant;
#[doc(hidden)]
pub mod small;
#[doc(hidden)]
pub mod stacked;
#[doc(hidden)]
pub mod stacked_certified;
#[doc(hidden)]
pub mod streaming;
#[doc(hidden)]
pub mod sumcheck;
#[doc(hidden)]
pub mod zerocheck;
#[cfg(feature = "controls")]
#[doc(hidden)]
pub mod zk;
#[cfg(feature = "controls")]
pub mod zk_relation;

extern crate self as stele_negative_controls;
#[path = "../pcs/nc_0602.rs"]
mod nc_0602;
#[path = "../transcript/nc_0801.rs"]
mod nc_0801;

/// Executable controls; configuration passes do not earn statement-binding credit.
pub const CONTROLS: &[catalog::RegisteredControl] = &[
    catalog::RegisteredControl {
        id: 316,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || integer_linear::run(316),
    },
    catalog::RegisteredControl {
        id: 317,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || integer_linear::run(317),
    },
    catalog::RegisteredControl {
        id: 318,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: || integer_linear::run(318),
    },
    catalog::RegisteredControl {
        id: 315,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || lookup::run(315),
    },
    catalog::RegisteredControl {
        id: 308,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: || requant::run(308),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 902,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || zk::run(902),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 903,
        kind: catalog::ControlKind::Proof,
        expected_error: "UnsupportedSource",
        run: || zk::run(903),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 904,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk::run(904),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 905,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || zk::run(905),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 906,
        kind: catalog::ControlKind::Proof,
        expected_error: "MaskBudget",
        run: || zk::run(906),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 907,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk::run(907),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 908,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: || zk::run(908),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 909,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk::run(909),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 910,
        kind: catalog::ControlKind::Proof,
        expected_error: "ProofShape",
        run: || zk::run(910),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 911,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || zk::run(911),
    },
    catalog::RegisteredControl {
        id: 912,
        kind: catalog::ControlKind::Proof,
        expected_error: "StatementMismatch",
        run: || development::run(912),
    },
    catalog::RegisteredControl {
        id: 933,
        kind: catalog::ControlKind::Proof,
        expected_error: "StatementMismatch",
        run: || development::run(933),
    },
    catalog::RegisteredControl {
        id: 934,
        kind: catalog::ControlKind::Proof,
        expected_error: "MaskBudget",
        run: || development::run(934),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 913,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk::run(913),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 914,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || zk::run(914),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 915,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || zk::run(915),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 916,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk::run(916),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 917,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: || zk::run(917),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 918,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: || zk::run(918),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 919,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk::run(919),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 920,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk_relation::run(920),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 921,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk_relation::run(921),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 922,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk_relation::run(922),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 923,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk_relation::run(923),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 924,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk_relation::run(924),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 925,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk_relation::run(925),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 926,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zk_relation::run(926),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 927,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || zk_relation::run(927),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 928,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: || zk_relation::run(928),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 929,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: || zk_relation::run(929),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 935,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || development::run_records(935),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 936,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || development::run_records(936),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 937,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || development::run_records(937),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 938,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || development::run_records(938),
    },
    catalog::RegisteredControl {
        id: 1300,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || development::run(1300),
    },
    catalog::RegisteredControl {
        id: 1301,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || development::run(1301),
    },
    catalog::RegisteredControl {
        id: 1304,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || development::run(1304),
    },
    catalog::RegisteredControl {
        id: 1305,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || development::run(1305),
    },
    catalog::RegisteredControl {
        id: 1309,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || development::run(1309),
    },
    #[cfg(feature = "controls")]
    catalog::RegisteredControl {
        id: 1310,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: development::run_width,
    },
    catalog::RegisteredControl {
        id: 309,
        kind: catalog::ControlKind::Proof,
        expected_error: "CertificateContext",
        run: || requant::run(309),
    },
    catalog::RegisteredControl {
        id: 310,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || requant::run(310),
    },
    catalog::RegisteredControl {
        id: 311,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || requant::run(311),
    },
    catalog::RegisteredControl {
        id: 312,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: || {
            requant::run(312)?;
            integer_linear::run(312)
        },
    },
    catalog::RegisteredControl {
        id: 313,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || requant::run(313),
    },
    catalog::RegisteredControl {
        id: 314,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch / FinalEvaluationMismatch",
        run: || {
            requant::run(314)?;
            integer_linear::run(314)
        },
    },
    catalog::RegisteredControl {
        id: 305,
        kind: catalog::ControlKind::Proof,
        expected_error: "ColumnMismatch",
        run: || matmul::run(305),
    },
    catalog::RegisteredControl {
        id: 605,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: || {
            matmul::run(605)?;
            integer_linear::run(605)
        },
    },
    catalog::RegisteredControl {
        id: 306,
        kind: catalog::ControlKind::Proof,
        expected_error: "ColumnMismatch",
        run: || {
            matmul::run(306)?;
            integer_linear::run(306)
        },
    },
    catalog::RegisteredControl {
        id: 307,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: || {
            matmul::run(307)?;
            integer_linear::run(307)
        },
    },
    catalog::RegisteredControl {
        id: 611,
        kind: catalog::ControlKind::Proof,
        expected_error: "ColumnMismatch",
        run: || {
            matmul::run(611)?;
            integer_linear::run(611)
        },
    },
    catalog::RegisteredControl {
        id: 400,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || lookup::run(400),
    },
    catalog::RegisteredControl {
        id: 401,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || lookup::run(401),
    },
    catalog::RegisteredControl {
        id: 402,
        kind: catalog::ControlKind::Proof,
        expected_error: "SelectorMismatch",
        run: || lookup::run(402),
    },
    catalog::RegisteredControl {
        id: 403,
        kind: catalog::ControlKind::Proof,
        expected_error: "TableDenominatorMismatch",
        run: || lookup::run(403),
    },
    catalog::RegisteredControl {
        id: 415,
        kind: catalog::ControlKind::Proof,
        expected_error: "GroupBound",
        run: || lookup::run(415),
    },
    catalog::RegisteredControl {
        id: 416,
        kind: catalog::ControlKind::Proof,
        expected_error: "Pole",
        run: || lookup::run(416),
    },
    catalog::RegisteredControl {
        id: 417,
        kind: catalog::ControlKind::Proof,
        expected_error: "PieceSumMismatch",
        run: || lookup::run(417),
    },
    catalog::RegisteredControl {
        id: 418,
        kind: catalog::ControlKind::Proof,
        expected_error: "CertificateContext",
        run: || lookup::run(418),
    },
    catalog::RegisteredControl {
        id: 419,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || lookup::run(419),
    },
    catalog::RegisteredControl {
        id: 420,
        kind: catalog::ControlKind::Proof,
        expected_error: "GroupBound",
        run: || lookup::run(420),
    },
    catalog::RegisteredControl {
        id: 421,
        kind: catalog::ControlKind::Proof,
        expected_error: "Statement",
        run: || lookup::run(421),
    },
    catalog::RegisteredControl {
        id: 422,
        kind: catalog::ControlKind::Proof,
        expected_error: "Statement",
        run: || lookup::run(422),
    },
    catalog::RegisteredControl {
        id: 423,
        kind: catalog::ControlKind::Proof,
        expected_error: "Statement",
        run: || lookup::run(423),
    },
    catalog::RegisteredControl {
        id: 424,
        kind: catalog::ControlKind::Proof,
        expected_error: "Statement",
        run: || lookup::run(424),
    },
    catalog::RegisteredControl {
        id: 211,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch / ValueMismatch",
        run: stacked_certified::run_point,
    },
    catalog::RegisteredControl {
        id: 213,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: stacked_certified::run_root,
    },
    catalog::RegisteredControl {
        id: 203,
        kind: catalog::ControlKind::Proof,
        expected_error: "CoefficientMismatch",
        run: || stacked::run(203),
    },
    catalog::RegisteredControl {
        id: 212,
        kind: catalog::ControlKind::Proof,
        expected_error: "CoefficientMismatch",
        run: || stacked::run(212),
    },
    catalog::RegisteredControl {
        id: 609,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: pcs_a1::run,
    },
    catalog::RegisteredControl {
        id: 601,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || {
            pcs::run(601)?;
            pcs_opening::run(601)
        },
    },
    catalog::RegisteredControl {
        id: 803,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || {
            pcs::run(803)?;
            pcs_opening::run(803)
        },
    },
    catalog::RegisteredControl {
        id: 610,
        kind: catalog::ControlKind::Proof,
        expected_error: "ValueMismatch",
        run: || {
            pcs_opening::run(610)?;
            lookup::run(610)?;
            requant::run(610)?;
            integer_linear::run(610)
        },
    },
    catalog::RegisteredControl {
        id: 600,
        kind: catalog::ControlKind::Proof,
        expected_error: "ColumnMismatch",
        run: || {
            pcs::run(600)?;
            pcs_opening::run(600)
        },
    },
    catalog::RegisteredControl {
        id: 606,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch / CertificateContext",
        run: || {
            pcs::run(606)?;
            pcs_opening::run(606)?;
            matmul::run(606)?;
            requant::run(309)?;
            integer_linear::run(606)
        },
    },
    catalog::RegisteredControl {
        id: 607,
        kind: catalog::ControlKind::Proof,
        expected_error: "NoncanonicalField",
        run: || {
            pcs::run(607)?;
            pcs_opening_field::run()
        },
    },
    catalog::RegisteredControl {
        id: 608,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || pcs::run(608),
    },
    catalog::RegisteredControl {
        id: 603,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || lookup::run(603),
    },
    catalog::RegisteredControl {
        id: 612,
        kind: catalog::ControlKind::Proof,
        expected_error: "CertificateContext / ColumnMismatch / InvalidRegistry",
        run: || pcs_expander::run(612),
    },
    catalog::RegisteredControl {
        id: 613,
        kind: catalog::ControlKind::Proof,
        expected_error: "UnsupportedSource",
        run: || pcs_expander::run(613),
    },
    catalog::RegisteredControl {
        id: 614,
        kind: catalog::ControlKind::Proof,
        expected_error: "ColumnMismatch / NoncanonicalField",
        run: || pcs_expander::run(614),
    },
    catalog::RegisteredControl {
        id: 411,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: fraction_transcript::run_order,
    },
    catalog::RegisteredControl {
        id: 409,
        kind: catalog::ControlKind::Proof,
        expected_error: "SelectorMismatch",
        run: || fraction::run(409),
    },
    catalog::RegisteredControl {
        id: 410,
        kind: catalog::ControlKind::Proof,
        expected_error: "SourceMismatch",
        run: || fraction::run(410),
    },
    catalog::RegisteredControl {
        id: 406,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || fraction::run(406),
    },
    catalog::RegisteredControl {
        id: 407,
        kind: catalog::ControlKind::Proof,
        expected_error: "LeafMismatch",
        run: || fraction::run(407),
    },
    catalog::RegisteredControl {
        id: 408,
        kind: catalog::ControlKind::Proof,
        expected_error: "CoefficientMismatch",
        run: || fraction::run(408),
    },
    catalog::RegisteredControl {
        id: 210,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: streaming::run,
    },
    catalog::RegisteredControl {
        id: 204,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: small::run,
    },
    catalog::RegisteredControl {
        id: 207,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch / FinalEvaluationMismatch",
        run: || zerocheck::run(207),
    },
    catalog::RegisteredControl {
        id: 208,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || zerocheck::run(208),
    },
    catalog::RegisteredControl {
        id: 209,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: || zerocheck::run(209),
    },
    catalog::RegisteredControl {
        id: 202,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || batching::run(202),
    },
    catalog::RegisteredControl {
        id: 206,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || batching::run(206),
    },
    catalog::RegisteredControl {
        id: 602,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: nc_0602::run,
    },
    catalog::RegisteredControl {
        id: 200,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || sumcheck::run(200),
    },
    catalog::RegisteredControl {
        id: 201,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || sumcheck::run(201),
    },
    catalog::RegisteredControl {
        id: 205,
        kind: catalog::ControlKind::Proof,
        expected_error: "ClaimMismatch",
        run: || {
            sumcheck::run(205)?;
            batching::run(205)
        },
    },
    catalog::RegisteredControl {
        id: 800,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || {
            sumcheck::run(800)?;
            zerocheck::run(800)
        },
    },
    catalog::RegisteredControl {
        id: 802,
        kind: catalog::ControlKind::Proof,
        expected_error: "FinalEvaluationMismatch",
        run: || {
            sumcheck::run(802)?;
            batching::run(802)?;
            zerocheck::run(802)?;
            fraction_transcript::run_continuation()?;
            pcs_opening_continuation::run()?;
            stacked::run_continuation()?;
            lookup::run(802)?;
            matmul::run(802)?;
            requant::run(802)?;
            integer_linear::run(802)
        },
    },
    catalog::RegisteredControl {
        id: 801,
        kind: catalog::ControlKind::Configuration,
        expected_error: "DuplicateLabel",
        run: nc_0801::run,
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 806,
        kind: catalog::ControlKind::Proof,
        expected_error: "GrindMismatch",
        run: || pcs_policy2::run(806),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 807,
        kind: catalog::ControlKind::Proof,
        expected_error: "GrindMismatch",
        run: || pcs_policy2::run(807),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 808,
        kind: catalog::ControlKind::Proof,
        expected_error: "RootMismatch",
        run: || pcs_policy2::run(808),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 809,
        kind: catalog::ControlKind::Proof,
        expected_error: "ProofShape",
        run: || pcs_policy2::run(809),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 813,
        kind: catalog::ControlKind::Proof,
        expected_error: "GrindMismatch",
        run: || pcs_policy2::run(813),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 814,
        kind: catalog::ControlKind::Proof,
        expected_error: "GrindMismatch",
        run: || lookup_grind::run(814),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 815,
        kind: catalog::ControlKind::Proof,
        expected_error: "GrindMismatch",
        run: || lookup_grind::run(815),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 816,
        kind: catalog::ControlKind::Proof,
        expected_error: "RoundSumMismatch",
        run: || lookup_grind::run(816),
    },
    #[cfg(feature = "standard-unproven")]
    catalog::RegisteredControl {
        id: 817,
        kind: catalog::ControlKind::Proof,
        expected_error: "CertificateContext",
        run: || lookup_grind::run(817),
    },
];

/// A one-value mutation applied to an honest witness, proof or configuration.
/// Each control must assert that exactly its intended value changes.
pub trait ProverHook<W> {
    /// Mutate the selected value without changing the public statement.
    fn tamper(&self, witness: &mut W);
}

/// A control passes only on the expected verifier rejection, never a prover error.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlFailure<P, V> {
    /// The honest proof could not be produced.
    HonestProverFailed(P),
    /// The verifier rejected the honest proof.
    HonestRejected(V),
    /// The hook did not change the witness or proof.
    NoTamper,
    /// The modified witness did not reach the verifier.
    TamperedProverFailed(P),
    /// The verifier accepted the tampered proof.
    TamperAccepted,
    /// The verifier failed a different check than the control targets.
    WrongRejection {
        /// Required rejection.
        expected: V,
        /// Observed rejection.
        actual: V,
    },
}

/// Prove and verify the honest witness, then repeat with its tampered copy.
/// Callers supply the real prover/verifier; the harness has no check-disabling API.
pub fn check_control<W, H, Proof, P, V>(
    honest: &W,
    hook: &H,
    prove: impl Fn(&W) -> Result<Proof, P>,
    verify: impl Fn(&Proof) -> Result<(), V>,
    expected: V,
) -> Result<(), ControlFailure<P, V>>
where
    W: Clone + PartialEq,
    H: ProverHook<W>,
    V: PartialEq,
{
    let proof = prove(honest).map_err(ControlFailure::HonestProverFailed)?;
    verify(&proof).map_err(ControlFailure::HonestRejected)?;
    let mut tampered = honest.clone();
    hook.tamper(&mut tampered);
    if tampered == *honest {
        return Err(ControlFailure::NoTamper);
    }
    let proof = prove(&tampered).map_err(ControlFailure::TamperedProverFailed)?;
    match verify(&proof) {
        Ok(()) => Err(ControlFailure::TamperAccepted),
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(ControlFailure::WrongRejection { expected, actual }),
    }
}

/// RFC-0006 A1: verify an honest production proof, then one mutated proof value.
/// The control asserts exactly one change and supplies the unchanged real verifier.
pub fn check_proof_control<Proof, H, P, V>(
    prove: impl FnOnce() -> Result<Proof, P>,
    hook: &H,
    verify: impl Fn(&Proof) -> Result<(), V>,
    expected: V,
) -> Result<(), ControlFailure<P, V>>
where
    Proof: Clone + PartialEq,
    H: ProverHook<Proof>,
    V: PartialEq,
{
    let honest = prove().map_err(ControlFailure::HonestProverFailed)?;
    verify(&honest).map_err(ControlFailure::HonestRejected)?;
    let mut tampered = honest.clone();
    hook.tamper(&mut tampered);
    if tampered == honest {
        return Err(ControlFailure::NoTamper);
    }
    match verify(&tampered) {
        Ok(()) => Err(ControlFailure::TamperAccepted),
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(ControlFailure::WrongRejection { expected, actual }),
    }
}

/// Failure of a configuration-validation control (RFC-0012 A1, NC-0801 only).
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigurationFailure<E> {
    /// The production validator rejected the honest configuration.
    HonestRejected(E),
    /// The hook did not change the configuration.
    NoTamper,
    /// The production validator accepted the tampered configuration.
    TamperAccepted,
    /// Rejection occurred at a different boundary than the control targets.
    WrongRejection {
        /// Required rejection.
        expected: E,
        /// Observed rejection.
        actual: E,
    },
}

/// Validate the honest configuration and its one-value-tampered copy.
/// This path has no proof wrapper and earns no proof-statement binding coverage.
/// The caller must use the production validator and assert its exact mutation.
pub fn check_configuration<C, H, E>(
    honest: &C,
    hook: &H,
    validate: impl Fn(&C) -> Result<(), E>,
    expected: E,
) -> Result<(), ConfigurationFailure<E>>
where
    C: Clone + PartialEq,
    H: ProverHook<C>,
    E: PartialEq,
{
    validate(honest).map_err(ConfigurationFailure::HonestRejected)?;
    let mut tampered = honest.clone();
    hook.tamper(&mut tampered);
    if tampered == *honest {
        return Err(ConfigurationFailure::NoTamper);
    }
    match validate(&tampered) {
        Ok(()) => Err(ConfigurationFailure::TamperAccepted),
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(ConfigurationFailure::WrongRejection { expected, actual }),
    }
}
