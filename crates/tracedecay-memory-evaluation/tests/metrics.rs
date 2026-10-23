//! Behavioral tests for the tdmem-0904 metric catalog and evaluator.
//!
//! The baseline tests run the real conformance runner over the checked-in
//! corpus (no-memory and explicit-documentation lanes) and feed its output
//! through the production conversion, so the seam that the differential
//! runner will call is the seam under test.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use tracedecay_memory_conformance::{
    BaselineLane, BaselineRunConfig, BaselineRunner, ScenarioCorpus,
};
use tracedecay_memory_evaluation::{
    AdmittedCandidate, BaselineAnnotations, CATALOG_JSON, CandidateAnnotation, CandidateLabel,
    CatalogError, CheckOutcome, CorrectionEvidence, CorruptStateEvidence, DiscoveryEvidence,
    EvaluationError, Measured, MetricCatalog, MetricClass, MetricId, MetricReport, MetricValue,
    ProvenanceState, ProviderRunIdentity, ProviderRunRecord, RubricCheckResult, SafetyFailure,
    ScenarioRunRecord, TaskOutcome, TerminalGateEvidence, Verdict, evaluate,
    nearest_rank_percentile, provider_run_from_baseline,
};

const CORPUS_PATH: &str = "../../product/evaluation/coding-memory-scenarios.v1.json";
static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

type TestResult = Result<(), Box<dyn Error>>;

fn catalog() -> Result<MetricCatalog, CatalogError> {
    MetricCatalog::embedded()
}

fn corpus_json() -> Result<Value, Box<dyn Error>> {
    // Resolve against this run's directory, not a cached Bazel execroot.
    let path = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest directory")?)
        .join(CORPUS_PATH);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn provider() -> ProviderRunIdentity {
    ProviderRunIdentity {
        lane_id: "provider:test".to_owned(),
        provider_id: Some("test".to_owned()),
        run_identity_sha256: None,
    }
}

fn candidate(label: CandidateLabel) -> AdmittedCandidate {
    AdmittedCandidate {
        request_id: "request_stale_001".to_owned(),
        candidate_ref: format!("candidate_{}", label.as_str()),
        scope_match: true,
        provenance: ProvenanceState::Available,
        label,
        contains_forgotten_source: false,
    }
}

/// A scenario whose every safety-critical check passed and whose task passed.
fn passing_scenario(catalog: &MetricCatalog, scenario_id: &str) -> ScenarioRunRecord {
    let rubric_checks = catalog
        .safety_critical_check_ids(scenario_id)
        .iter()
        .map(|check_id| RubricCheckResult {
            check_id: check_id.clone(),
            outcome: CheckOutcome::Pass,
        })
        .collect();
    let corrupt_state = if scenario_id == "provider_corruption" {
        CorruptStateEvidence::Enumerated {
            admitted_from_corrupt_state: 0,
        }
    } else {
        CorruptStateEvidence::NotExercised
    };
    ScenarioRunRecord {
        scenario_id: scenario_id.to_owned(),
        terminal_gate: TerminalGateEvidence {
            passed: true,
            observed_terminal_codes: vec!["success".to_owned()],
            violations: Vec::new(),
        },
        task_outcome: TaskOutcome::Pass,
        rubric_checks,
        candidates: Vec::new(),
        recall_latency_micros: Vec::new(),
        context_tokens: Measured::Value { value: 0 },
        curation_seconds: Measured::Unmeasured {
            reason: "not_measured".to_owned(),
        },
        correction: CorrectionEvidence::NotApplicable {
            reason: "none".to_owned(),
        },
        discovery: DiscoveryEvidence::NotEnumerated {
            reason: "not_enumerated".to_owned(),
        },
        corrupt_state,
    }
}

fn passing_run(catalog: &MetricCatalog) -> ProviderRunRecord {
    ProviderRunRecord {
        provider: provider(),
        scenarios: catalog
            .scenario_ids()
            .into_iter()
            .map(|id| passing_scenario(catalog, id))
            .collect(),
    }
}

fn metric<'a>(
    report: &'a MetricReport,
    scenario_id: &str,
    metric_id: MetricId,
) -> Result<&'a MetricValue, Box<dyn Error>> {
    let scenario = report
        .scenario(scenario_id)
        .ok_or_else(|| format!("scenario {scenario_id} missing from report"))?;
    Ok(&scenario
        .metrics
        .get(&metric_id)
        .ok_or_else(|| format!("metric {metric_id} missing from {scenario_id}"))?
        .value)
}

// ---------------------------------------------------------------------------
// Catalog binding
// ---------------------------------------------------------------------------

#[test]
fn embedded_catalog_binds_exactly_the_computed_metrics() -> TestResult {
    let catalog = catalog()?;
    let ids: BTreeSet<MetricId> = catalog.metrics.iter().map(|m| m.metric_id).collect();
    assert_eq!(ids, MetricId::ALL.into_iter().collect());
    assert_eq!(catalog.metrics.len(), MetricId::ALL.len());
    assert_eq!(
        catalog.corpus_binding.corpus_id,
        "tracedecay.coding-memory.scenarios.v1"
    );
    assert_eq!(
        catalog.terminal_contract_binding.contract_id,
        "tracedecay.memory.provider.terminal.v1"
    );
    for metric in &catalog.metrics {
        assert!(metric.version >= 1, "{}", metric.metric_id);
        assert_eq!(
            metric.class == MetricClass::Safety,
            metric.safety_gating,
            "{}",
            metric.metric_id
        );
        assert!(!metric.numerator.is_empty());
        assert!(!metric.denominator.population.is_empty());
    }
    let safety: BTreeSet<MetricId> = catalog
        .metrics
        .iter()
        .filter(|m| m.safety_gating)
        .map(|m| m.metric_id)
        .collect();
    assert_eq!(
        safety,
        [
            MetricId::HarmfulStaleRecallRate,
            MetricId::ScopeLeakage,
            MetricId::CorruptStateRecall,
            MetricId::DeletedSourceRecall,
        ]
        .into_iter()
        .collect()
    );
    Ok(())
}

#[test]
fn embedded_catalog_binds_every_corpus_scenario_and_rubric_check() -> TestResult {
    let catalog = catalog()?;
    let corpus = corpus_json()?;
    let scenarios = corpus["scenarios"].as_array().ok_or("corpus scenarios")?;
    let corpus_ids: BTreeSet<&str> = scenarios.iter().filter_map(|s| s["id"].as_str()).collect();
    assert_eq!(catalog.scenario_ids(), corpus_ids);
    for scenario in scenarios {
        let id = scenario["id"].as_str().ok_or("scenario id")?;
        let checks: BTreeSet<&str> = scenario["adjudication_rubric"]["checks"]
            .as_array()
            .ok_or("checks")?
            .iter()
            .filter_map(|c| c["check_id"].as_str())
            .collect();
        for critical in catalog.safety_critical_check_ids(id) {
            assert!(checks.contains(critical.as_str()), "{id}:{critical}");
        }
        let mut bound: BTreeSet<&str> = BTreeSet::new();
        for metric in &catalog.metrics {
            for binding in &metric.rubric_check_bindings {
                if binding.scenario_id == id {
                    for check_id in &binding.check_ids {
                        assert!(checks.contains(check_id.as_str()), "{id}:{check_id}");
                        bound.insert(check_id.as_str());
                    }
                }
            }
            if let Some(applicable) = &metric.applicable_scenarios {
                for applicable_id in applicable {
                    assert!(corpus_ids.contains(applicable_id.as_str()));
                }
            }
        }
        assert_eq!(bound, checks, "every rubric check of {id} maps to a metric");
    }
    Ok(())
}

#[test]
fn catalog_rejects_drift_from_the_computed_metric_set() -> TestResult {
    let mut value: Value = serde_json::from_str(CATALOG_JSON)?;
    let metrics = value["metrics"].as_array_mut().ok_or("metrics")?;
    let dropped = metrics.pop().ok_or("last metric")?;
    let missing = MetricCatalog::from_json_str(&value.to_string());
    assert!(
        matches!(missing, Err(CatalogError::MissingMetric { .. })),
        "{missing:?}"
    );

    let mut value: Value = serde_json::from_str(CATALOG_JSON)?;
    value["metrics"]
        .as_array_mut()
        .ok_or("metrics")?
        .push(dropped);
    let duplicate = MetricCatalog::from_json_str(&value.to_string());
    assert!(
        matches!(duplicate, Err(CatalogError::DuplicateMetric { .. })),
        "{duplicate:?}"
    );

    let mut value: Value = serde_json::from_str(CATALOG_JSON)?;
    value["metrics"][0]["metric_id"] = json!("unknown_metric");
    assert!(MetricCatalog::from_json_str(&value.to_string()).is_err());

    let mut value: Value = serde_json::from_str(CATALOG_JSON)?;
    value["safety_gate"]["aggregate_task_score_can_hide_safety"] = json!(true);
    assert!(MetricCatalog::from_json_str(&value.to_string()).is_err());

    let mut value: Value = serde_json::from_str(CATALOG_JSON)?;
    for metric in value["metrics"].as_array_mut().ok_or("metrics")? {
        if metric["metric_id"] == "scope_leakage" {
            metric["safety_gating"] = json!(false);
        }
    }
    let ungated = MetricCatalog::from_json_str(&value.to_string());
    assert!(
        matches!(ungated, Err(CatalogError::InvalidMetric { .. })),
        "{ungated:?}"
    );

    let mut value: Value = serde_json::from_str(CATALOG_JSON)?;
    for metric in value["metrics"].as_array_mut().ok_or("metrics")? {
        if metric["metric_id"] == "harmful_stale_recall_rate" {
            metric["denominator"]["unresolved_label_policy"] = json!("exclude_and_report");
        }
    }
    let policy = MetricCatalog::from_json_str(&value.to_string());
    assert!(
        matches!(policy, Err(CatalogError::InvalidMetric { .. })),
        "{policy:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Percentiles
// ---------------------------------------------------------------------------

#[test]
fn nearest_rank_percentile_follows_the_catalog_definition() {
    assert_eq!(nearest_rank_percentile(&[], 50), None);
    assert_eq!(nearest_rank_percentile(&[7], 50), Some(7));
    assert_eq!(nearest_rank_percentile(&[7], 95), Some(7));
    let ten: Vec<u64> = (1..=10).rev().collect();
    assert_eq!(nearest_rank_percentile(&ten, 50), Some(5));
    assert_eq!(nearest_rank_percentile(&ten, 95), Some(10));
    assert_eq!(nearest_rank_percentile(&ten, 100), Some(10));
    assert_eq!(nearest_rank_percentile(&ten, 1), Some(1));
    assert_eq!(nearest_rank_percentile(&ten, 0), None);
    assert_eq!(nearest_rank_percentile(&ten, 101), None);
    let twenty: Vec<u64> = (1..=20).collect();
    assert_eq!(nearest_rank_percentile(&twenty, 95), Some(19));
}

// ---------------------------------------------------------------------------
// Safety cannot be hidden by the aggregate
// ---------------------------------------------------------------------------

#[test]
fn perfect_aggregate_with_one_scope_leak_fails_the_verdict() -> TestResult {
    let catalog = catalog()?;
    let mut run = passing_run(&catalog);
    let target = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "project_worktree_scope")
        .ok_or("scenario")?;
    let mut leaked = candidate(CandidateLabel::Useful);
    leaked.scope_match = false;
    target.candidates.push(candidate(CandidateLabel::Useful));
    target.candidates.push(leaked);

    let report = evaluate(&catalog, &run)?;
    let aggregate = report.aggregate_task_score.as_ref().ok_or("aggregate")?;
    assert_eq!(aggregate.value, 1.0);
    assert_eq!(aggregate.resolved_scenarios, 9);
    assert_eq!(aggregate.indeterminate_scenarios, 0);
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(!report.safety_gate.passed);
    assert!(
        report.safety_gate.failures.iter().any(|f| matches!(
            f,
            SafetyFailure::MetricExceededCeiling { scenario_id, metric_id: MetricId::ScopeLeakage, value, ceiling }
                if scenario_id == "project_worktree_scope" && *value == 0.5 && *ceiling == 0.0
        )),
        "{:?}",
        report.safety_gate.failures
    );
    assert_eq!(
        metric(&report, "project_worktree_scope", MetricId::ScopeLeakage)?,
        &MetricValue::Ratio {
            numerator: 1,
            denominator: 2,
            value: 0.5
        }
    );
    let provider_leak = &report.provider_metrics[&MetricId::ScopeLeakage].value;
    assert_eq!(provider_leak.numeric(), Some(0.5));
    Ok(())
}

#[test]
fn clean_run_passes_and_reports_not_applicable_populations() -> TestResult {
    let catalog = catalog()?;
    let report = evaluate(&catalog, &passing_run(&catalog))?;
    assert_eq!(report.verdict, Verdict::Pass);
    assert!(report.safety_gate.passed);
    assert!(report.safety_gate.failures.is_empty());
    assert_eq!(
        report.aggregate_task_score.as_ref().map(|a| a.value),
        Some(1.0)
    );
    assert!(matches!(
        metric(&report, "restart", MetricId::ScopeLeakage)?,
        MetricValue::NotApplicable { .. }
    ));
    assert!(matches!(
        metric(&report, "restart", MetricId::HarmfulStaleRecallRate)?,
        MetricValue::NotApplicable { .. }
    ));
    assert!(matches!(
        metric(&report, "restart", MetricId::DeletedSourceRecall)?,
        MetricValue::NotApplicable { .. }
    ));
    assert!(matches!(
        metric(&report, "provider_corruption", MetricId::CorruptStateRecall)?,
        MetricValue::Quantity { value, samples: 1 } if *value == 0.0
    ));
    assert!(matches!(
        metric(&report, "restart", MetricId::CorruptStateRecall)?,
        MetricValue::NotApplicable { .. }
    ));
    assert!(matches!(
        metric(&report, "restart", MetricId::RecallLatencyP50)?,
        MetricValue::Indeterminate { reason } if reason == "no_samples"
    ));
    assert!(matches!(
        metric(&report, "restart", MetricId::HumanCurationTime)?,
        MetricValue::Indeterminate { .. }
    ));
    assert!(matches!(
        metric(&report, "restart", MetricId::RepeatedDiscoveryRate)?,
        MetricValue::Indeterminate { .. }
    ));
    assert_eq!(report.catalog_id, "tracedecay.coding-memory.metrics.v1");
    assert_eq!(report.catalog_version, catalog.catalog_version);
    assert_eq!(report.corpus_id, catalog.corpus_binding.corpus_id);
    assert_eq!(report.scenarios.len(), 9);
    for scenario in &report.scenarios {
        assert_eq!(scenario.metrics.len(), MetricId::ALL.len());
    }
    Ok(())
}

#[test]
fn safety_critical_check_that_is_not_a_pass_fails_the_gate() -> TestResult {
    let catalog = catalog()?;

    let mut run = passing_run(&catalog);
    let cancellation = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "cancellation")
        .ok_or("scenario")?;
    cancellation.rubric_checks[0].outcome = CheckOutcome::Indeterminate;
    let report = evaluate(&catalog, &run)?;
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::SafetyCriticalCheckNotPassed { scenario_id, outcome: CheckOutcome::Indeterminate, .. }
            if scenario_id == "cancellation"
    )));

    let mut run = passing_run(&catalog);
    let privacy = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "privacy_deletion")
        .ok_or("scenario")?;
    privacy.rubric_checks.clear();
    let report = evaluate(&catalog, &run)?;
    assert_eq!(report.verdict, Verdict::Fail);
    let missing = report
        .safety_gate
        .failures
        .iter()
        .filter(|f| matches!(f, SafetyFailure::SafetyCriticalCheckMissing { .. }))
        .count();
    assert_eq!(
        missing,
        catalog.safety_critical_check_ids("privacy_deletion").len()
    );

    let mut run = passing_run(&catalog);
    run.scenarios[0].terminal_gate.passed = false;
    run.scenarios[0].terminal_gate.violations = vec!["3:internal_failure".to_owned()];
    let report = evaluate(&catalog, &run)?;
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::TerminalGateFailed { violations, .. } if violations == &["3:internal_failure"]
    )));
    Ok(())
}

#[test]
fn corrupt_state_and_deletion_violations_fail_regardless_of_aggregate() -> TestResult {
    let catalog = catalog()?;

    let mut run = passing_run(&catalog);
    let corruption = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "provider_corruption")
        .ok_or("scenario")?;
    corruption.corrupt_state = CorruptStateEvidence::Enumerated {
        admitted_from_corrupt_state: 1,
    };
    let report = evaluate(&catalog, &run)?;
    assert_eq!(
        report.aggregate_task_score.as_ref().map(|a| a.value),
        Some(1.0)
    );
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::MetricExceededCeiling { metric_id: MetricId::CorruptStateRecall, value, .. } if *value == 1.0
    )));

    let mut run = passing_run(&catalog);
    let corruption = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "provider_corruption")
        .ok_or("scenario")?;
    corruption.corrupt_state = CorruptStateEvidence::NotEnumerable {
        reason: "runner could not enumerate".to_owned(),
    };
    let report = evaluate(&catalog, &run)?;
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::MetricIndeterminate {
            metric_id: MetricId::CorruptStateRecall,
            ..
        }
    )));

    let mut run = passing_run(&catalog);
    let privacy = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "privacy_deletion")
        .ok_or("scenario")?;
    let mut leaked = candidate(CandidateLabel::Useful);
    leaked.contains_forgotten_source = true;
    privacy.candidates.push(leaked);
    let report = evaluate(&catalog, &run)?;
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::MetricExceededCeiling {
            metric_id: MetricId::DeletedSourceRecall,
            ..
        }
    )));
    Ok(())
}

// ---------------------------------------------------------------------------
// Missing and indeterminate labels
// ---------------------------------------------------------------------------

#[test]
fn all_missing_labels_are_indeterminate_not_zero() -> TestResult {
    let catalog = catalog()?;
    let mut run = passing_run(&catalog);
    let stale = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "stale_project_change")
        .ok_or("scenario")?;
    stale.candidates = vec![
        candidate(CandidateLabel::Missing),
        candidate(CandidateLabel::Missing),
        candidate(CandidateLabel::Indeterminate),
    ];
    let report = evaluate(&catalog, &run)?;
    let scenario = report.scenario("stale_project_change").ok_or("scenario")?;

    let precision = &scenario.metrics[&MetricId::UsefulRecallPrecision];
    assert!(
        matches!(precision.value, MetricValue::Indeterminate { .. }),
        "{precision:?}"
    );
    assert_ne!(precision.value.numeric(), Some(0.0));
    let counts = precision.label_counts.ok_or("counts")?;
    assert_eq!(
        (counts.labeled, counts.unlabeled, counts.indeterminate),
        (0, 2, 1)
    );

    let harmful = &scenario.metrics[&MetricId::HarmfulStaleRecallRate];
    assert!(
        matches!(harmful.value, MetricValue::Indeterminate { .. }),
        "{harmful:?}"
    );
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::MetricIndeterminate { metric_id: MetricId::HarmfulStaleRecallRate, scenario_id, .. }
            if scenario_id == "stale_project_change"
    )));

    // Mechanical metrics ignore labels and still compute.
    assert_eq!(
        scenario.metrics[&MetricId::ProvenanceCompleteness].value,
        MetricValue::Ratio {
            numerator: 3,
            denominator: 3,
            value: 1.0
        }
    );
    let pooled = &report.provider_metrics[&MetricId::UsefulRecallPrecision];
    assert!(matches!(pooled.value, MetricValue::Indeterminate { .. }));
    assert_eq!(pooled.label_counts.map(|c| c.unlabeled), Some(2));
    Ok(())
}

#[test]
fn mixed_labels_use_only_labeled_candidates_in_the_denominator() -> TestResult {
    let catalog = catalog()?;
    let mut run = passing_run(&catalog);
    let stale = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "stale_project_change")
        .ok_or("scenario")?;
    stale.candidates = vec![
        candidate(CandidateLabel::Useful),
        candidate(CandidateLabel::Useful),
        candidate(CandidateLabel::Irrelevant),
        candidate(CandidateLabel::Missing),
        candidate(CandidateLabel::Indeterminate),
    ];
    let report = evaluate(&catalog, &run)?;
    let scenario = report.scenario("stale_project_change").ok_or("scenario")?;
    let precision = &scenario.metrics[&MetricId::UsefulRecallPrecision];
    assert_eq!(
        precision.value,
        MetricValue::Ratio {
            numerator: 2,
            denominator: 3,
            value: 2.0 / 3.0
        }
    );
    let counts = precision.label_counts.ok_or("counts")?;
    assert_eq!(
        (counts.labeled, counts.unlabeled, counts.indeterminate),
        (3, 1, 1)
    );

    // One unresolved candidate makes the safety metric indeterminate.
    let harmful = &scenario.metrics[&MetricId::HarmfulStaleRecallRate];
    assert!(
        matches!(&harmful.value, MetricValue::Indeterminate { reason } if reason.contains("2 of 5"))
    );
    assert_eq!(report.verdict, Verdict::Fail);
    Ok(())
}

#[test]
fn fully_labeled_candidates_compute_harmful_stale_rate_and_gate_on_it() -> TestResult {
    let catalog = catalog()?;
    let mut run = passing_run(&catalog);
    let contradiction = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "contradiction")
        .ok_or("scenario")?;
    contradiction.candidates = vec![
        candidate(CandidateLabel::Useful),
        candidate(CandidateLabel::Stale),
        candidate(CandidateLabel::Harmful),
        candidate(CandidateLabel::Unverifiable),
    ];
    let report = evaluate(&catalog, &run)?;
    let scenario = report.scenario("contradiction").ok_or("scenario")?;
    assert_eq!(
        scenario.metrics[&MetricId::HarmfulStaleRecallRate].value,
        MetricValue::Ratio {
            numerator: 2,
            denominator: 4,
            value: 0.5
        }
    );
    assert_eq!(
        scenario.metrics[&MetricId::UsefulRecallPrecision].value,
        MetricValue::Ratio {
            numerator: 1,
            denominator: 4,
            value: 0.25
        }
    );
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::MetricExceededCeiling { metric_id: MetricId::HarmfulStaleRecallRate, value, .. } if *value == 0.5
    )));

    let contradiction = run
        .scenarios
        .iter_mut()
        .find(|s| s.scenario_id == "contradiction")
        .ok_or("scenario")?;
    contradiction.candidates = vec![
        candidate(CandidateLabel::Useful),
        candidate(CandidateLabel::Irrelevant),
    ];
    let report = evaluate(&catalog, &run)?;
    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(
        report.provider_metrics[&MetricId::HarmfulStaleRecallRate].value,
        MetricValue::Ratio {
            numerator: 0,
            denominator: 2,
            value: 0.0
        }
    );
    Ok(())
}

#[test]
fn indeterminate_task_outcomes_are_excluded_from_the_aggregate_with_coverage() -> TestResult {
    let catalog = catalog()?;
    let mut run = passing_run(&catalog);
    run.scenarios[0].task_outcome = TaskOutcome::Indeterminate {
        reason: "no evaluator pinned".to_owned(),
    };
    run.scenarios[1].task_outcome = TaskOutcome::Fail;
    let report = evaluate(&catalog, &run)?;
    let aggregate = report.aggregate_task_score.as_ref().ok_or("aggregate")?;
    assert_eq!(aggregate.resolved_scenarios, 8);
    assert_eq!(aggregate.indeterminate_scenarios, 1);
    assert_eq!(aggregate.value, 7.0 / 8.0);
    assert!(matches!(
        &report.scenarios[0].metrics[&MetricId::TaskOutcome].value,
        MetricValue::Indeterminate { reason } if reason == "no evaluator pinned"
    ));

    for scenario in &mut run.scenarios {
        scenario.task_outcome = TaskOutcome::Indeterminate {
            reason: "unknown".to_owned(),
        };
    }
    let report = evaluate(&catalog, &run)?;
    assert!(report.aggregate_task_score.is_none());
    assert!(matches!(
        report.provider_metrics[&MetricId::TaskOutcome].value,
        MetricValue::Indeterminate { .. }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Latency and cost
// ---------------------------------------------------------------------------

#[test]
fn latency_and_cost_are_never_fabricated_and_pool_over_raw_samples() -> TestResult {
    let catalog = catalog()?;
    let mut run = passing_run(&catalog);
    run.scenarios[0].recall_latency_micros = vec![300, 100, 200];
    run.scenarios[1].recall_latency_micros = vec![900];
    run.scenarios[0].context_tokens = Measured::Value { value: 40 };
    run.scenarios[1].context_tokens = Measured::Value { value: 2 };
    run.scenarios[2].context_tokens = Measured::Unmeasured {
        reason: "no_token_estimator_pinned".to_owned(),
    };
    run.scenarios[0].curation_seconds = Measured::Value { value: 30 };
    run.scenarios[0].discovery = DiscoveryEvidence::Enumerated {
        required_facts: 4,
        rediscovered_facts: 1,
    };
    let report = evaluate(&catalog, &run)?;

    let first = &report.scenarios[0].metrics;
    assert_eq!(
        first[&MetricId::RecallLatencyP50].value,
        MetricValue::Quantity {
            value: 200.0,
            samples: 3
        }
    );
    assert_eq!(
        first[&MetricId::RecallLatencyP95].value,
        MetricValue::Quantity {
            value: 300.0,
            samples: 3
        }
    );
    assert!(matches!(
        &report.scenarios[2].metrics[&MetricId::RecallLatencyP50].value,
        MetricValue::Indeterminate { reason } if reason == "no_samples"
    ));
    assert_eq!(
        report.provider_metrics[&MetricId::RecallLatencyP50].value,
        MetricValue::Quantity {
            value: 200.0,
            samples: 4
        }
    );
    assert_eq!(
        report.provider_metrics[&MetricId::RecallLatencyP95].value,
        MetricValue::Quantity {
            value: 900.0,
            samples: 4
        }
    );

    assert_eq!(
        first[&MetricId::ContextTokens].value,
        MetricValue::Quantity {
            value: 40.0,
            samples: 1
        }
    );
    // One unmeasured scenario makes the provider sum indeterminate, never a partial sum.
    assert!(matches!(
        &report.provider_metrics[&MetricId::ContextTokens].value,
        MetricValue::Indeterminate { reason } if reason.contains(&run.scenarios[2].scenario_id)
    ));
    assert_eq!(
        report.provider_metrics[&MetricId::HumanCurationTime]
            .value
            .numeric(),
        None
    );
    assert_eq!(
        first[&MetricId::RepeatedDiscoveryRate].value,
        MetricValue::Ratio {
            numerator: 1,
            denominator: 4,
            value: 0.25
        }
    );
    for metric in [
        MetricId::ContextTokens,
        MetricId::RecallLatencyP50,
        MetricId::RecallLatencyP95,
        MetricId::HumanCurationTime,
        MetricId::CorrectionLatency,
    ] {
        assert_eq!(
            first[&metric].determinism,
            tracedecay_memory_evaluation::Determinism::Nondeterministic,
            "{metric}"
        );
    }
    assert_eq!(report.verdict, Verdict::Pass);
    Ok(())
}

// ---------------------------------------------------------------------------
// Poisoned input
// ---------------------------------------------------------------------------

#[test]
fn poisoned_run_records_are_typed_errors() -> TestResult {
    let catalog = catalog()?;

    let empty = ProviderRunRecord {
        provider: provider(),
        scenarios: Vec::new(),
    };
    assert!(matches!(
        evaluate(&catalog, &empty),
        Err(EvaluationError::NoScenarios)
    ));

    let mut run = passing_run(&catalog);
    run.scenarios[0].scenario_id = "not_in_corpus".to_owned();
    assert!(matches!(
        evaluate(&catalog, &run),
        Err(EvaluationError::UnknownScenario { scenario_id }) if scenario_id == "not_in_corpus"
    ));

    let mut run = passing_run(&catalog);
    let duplicate = run.scenarios[0].clone();
    run.scenarios.push(duplicate);
    assert!(matches!(
        evaluate(&catalog, &run),
        Err(EvaluationError::DuplicateScenario { .. })
    ));

    let mut run = passing_run(&catalog);
    run.scenarios[0].terminal_gate.observed_terminal_codes = vec!["kaboom".to_owned()];
    assert!(matches!(
        evaluate(&catalog, &run),
        Err(EvaluationError::UnknownTerminalCode { terminal_code, .. }) if terminal_code == "kaboom"
    ));

    let mut run = passing_run(&catalog);
    let check = run.scenarios[0].rubric_checks[0].clone();
    run.scenarios[0].rubric_checks.push(check);
    assert!(matches!(
        evaluate(&catalog, &run),
        Err(EvaluationError::DuplicateCheck { .. })
    ));

    let mut run = passing_run(&catalog);
    run.scenarios[0].discovery = DiscoveryEvidence::Enumerated {
        required_facts: 1,
        rediscovered_facts: 2,
    };
    assert!(matches!(
        evaluate(&catalog, &run),
        Err(EvaluationError::DiscoveryExceedsRequired { .. })
    ));
    Ok(())
}

#[test]
fn report_round_trips_through_json() -> TestResult {
    let catalog = catalog()?;
    let mut run = passing_run(&catalog);
    run.scenarios[0].candidates = vec![
        candidate(CandidateLabel::Useful),
        candidate(CandidateLabel::Missing),
    ];
    run.scenarios[0].recall_latency_micros = vec![10, 20];
    let report = evaluate(&catalog, &run)?;
    let json = serde_json::to_string(&report)?;
    let back: MetricReport = serde_json::from_str(&json)?;
    assert_eq!(back, report);
    let value: Value = serde_json::from_str(&json)?;
    assert_eq!(value["verdict"], "fail");
    assert_eq!(value["safety_gate"]["passed"], false);
    assert!(value["aggregate_task_score"]["value"].is_number());
    assert_eq!(
        value["scenarios"][0]["metrics"]["useful_recall_precision"]["label_counts"]["unlabeled"],
        1
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Real baseline runner seam
// ---------------------------------------------------------------------------

struct ScratchRoot(PathBuf);

impl ScratchRoot {
    fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let ordinal = SCRATCH_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "tracedecay-metrics-{label}-{}-{ordinal}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(Self(root))
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn load_corpus() -> Result<ScenarioCorpus, Box<dyn Error>> {
    // Resolve against this run's directory, not a cached Bazel execroot.
    let path = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest directory")?)
        .join(CORPUS_PATH);
    Ok(ScenarioCorpus::from_json_bytes(&std::fs::read(path)?)?)
}

#[test]
fn no_memory_baseline_reports_honest_indeterminates_and_fails_the_gate() -> TestResult {
    let corpus = load_corpus()?;
    let scratch = ScratchRoot::create("no-memory")?;
    let runner = BaselineRunner::new(&corpus, BaselineRunConfig::new(scratch.0.join("ws")))?;
    let output = runner.run(&BaselineLane::NoMemory)?;

    let report = MetricReport::from_baseline_run(&output, &BaselineAnnotations::none())?;
    assert_eq!(report.provider.lane_id, "no_memory");
    assert_eq!(report.provider.provider_id, None);
    assert_eq!(
        report.provider.run_identity_sha256.as_deref(),
        Some(output.report.identity.run_identity_sha256.as_str())
    );
    assert_eq!(report.scenarios.len(), corpus.scenarios().len());
    for scenario in &report.scenarios {
        assert!(matches!(
            scenario.metrics[&MetricId::ScopeLeakage].value,
            MetricValue::NotApplicable { .. }
        ));
        assert!(matches!(
            &scenario.metrics[&MetricId::RecallLatencyP50].value,
            MetricValue::Indeterminate { reason } if reason == "no_samples"
        ));
        // The default config pins the o200k estimator, so zero admitted bytes is a real zero.
        assert_eq!(
            scenario.metrics[&MetricId::ContextTokens].value,
            MetricValue::Quantity {
                value: 0.0,
                samples: 1
            }
        );
    }
    // A lane that admits nothing earns no safety pass: its safety-critical
    // checks are indeterminate, and the report says so instead of scoring it.
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(
        report
            .safety_gate
            .failures
            .iter()
            .any(|f| matches!(f, SafetyFailure::SafetyCriticalCheckNotPassed { .. }))
    );
    let conformance_failed: BTreeSet<&str> = output
        .report
        .scenarios
        .iter()
        .filter(|s| !s.adjudication.safety_gate_passed)
        .map(|s| s.scenario_id.as_str())
        .collect();
    let metric_failed: BTreeSet<&str> = report
        .safety_gate
        .failures
        .iter()
        .map(SafetyFailure::scenario_id)
        .collect();
    assert!(
        metric_failed.is_subset(&conformance_failed),
        "{metric_failed:?} vs {conformance_failed:?}"
    );
    Ok(())
}

#[test]
fn explicit_documentation_baseline_is_unlabeled_until_annotated() -> TestResult {
    let corpus = load_corpus()?;
    let scratch = ScratchRoot::create("docs")?;
    let runner = BaselineRunner::new(&corpus, BaselineRunConfig::new(scratch.0.join("ws")))?;
    let output = runner.run(&BaselineLane::ExplicitDocumentation)?;
    let catalog = catalog()?;

    let unlabeled = provider_run_from_baseline(&catalog, &output, &BaselineAnnotations::none())?;
    let admitted: Vec<(String, String, String)> = unlabeled
        .scenarios
        .iter()
        .flat_map(|s| {
            s.candidates.iter().map(move |c| {
                (
                    s.scenario_id.clone(),
                    c.request_id.clone(),
                    c.candidate_ref.clone(),
                )
            })
        })
        .collect();
    assert!(
        !admitted.is_empty(),
        "the documentation lane admits fixture docs"
    );
    assert!(unlabeled
        .scenarios
        .iter()
        .flat_map(|s| s.candidates.iter())
        .all(|c| c.label == CandidateLabel::Missing && c.provenance == ProvenanceState::Missing));

    let report = evaluate(&catalog, &unlabeled)?;
    let pooled = &report.provider_metrics[&MetricId::UsefulRecallPrecision];
    assert!(
        matches!(pooled.value, MetricValue::Indeterminate { .. }),
        "{pooled:?}"
    );
    assert_eq!(
        pooled.label_counts.map(|c| c.unlabeled),
        Some(admitted.len() as u64)
    );
    assert_eq!(
        report.provider_metrics[&MetricId::ProvenanceCompleteness]
            .value
            .numeric(),
        Some(0.0)
    );
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::MetricIndeterminate {
            metric_id: MetricId::HarmfulStaleRecallRate,
            ..
        }
    )));

    let mut annotations = BaselineAnnotations::none();
    for (scenario_id, request_id, candidate_ref) in &admitted {
        annotations.annotate_candidate(
            scenario_id,
            request_id,
            candidate_ref,
            CandidateAnnotation {
                label: CandidateLabel::Useful,
                provenance: ProvenanceState::Available,
            },
        );
    }
    let labeled = provider_run_from_baseline(&catalog, &output, &annotations)?;
    let report = evaluate(&catalog, &labeled)?;
    assert_eq!(
        report.provider_metrics[&MetricId::UsefulRecallPrecision]
            .value
            .numeric(),
        Some(1.0)
    );
    assert_eq!(
        report.provider_metrics[&MetricId::ProvenanceCompleteness]
            .value
            .numeric(),
        Some(1.0)
    );
    assert_eq!(
        report.provider_metrics[&MetricId::HarmfulStaleRecallRate]
            .value
            .numeric(),
        Some(0.0)
    );
    assert!(!report.safety_gate.failures.iter().any(|f| matches!(
        f,
        SafetyFailure::MetricIndeterminate {
            metric_id: MetricId::HarmfulStaleRecallRate,
            ..
        }
    )));

    let mut stray = BaselineAnnotations::none();
    stray.annotate_candidate(
        &admitted[0].0,
        &admitted[0].1,
        "never_admitted",
        CandidateAnnotation {
            label: CandidateLabel::Useful,
            provenance: ProvenanceState::Available,
        },
    );
    assert!(matches!(
        provider_run_from_baseline(&catalog, &output, &stray),
        Err(EvaluationError::UnmatchedAnnotation { candidate_ref, .. }) if candidate_ref == "never_admitted"
    ));

    let mut stray_scenario = BaselineAnnotations::none();
    stray_scenario.record_curation_seconds("not_a_scenario", 5);
    assert!(matches!(
        provider_run_from_baseline(&catalog, &output, &stray_scenario),
        Err(EvaluationError::UnmatchedScenarioAnnotation { .. })
    ));
    Ok(())
}
