//! Explanation generation for derived facts.

use crate::dag::{Justification, JustificationDag};
use crate::types::{FactId, TrustScore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An explanation for why a fact is derived.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhyExplanation {
    /// The fact being explained.
    pub conclusion: String,
    /// How it was derived.
    pub derivation: DerivationExplanation,
}

/// Derivation explanation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DerivationExplanation {
    /// Base fact (axiom).
    Axiom {
        fact: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        trust: f64,
    },
    /// Derived via rule.
    Derived {
        fact: String,
        antecedents: Vec<DerivationExplanation>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
        trust: f64,
    },
}

/// An explanation for why a fact is NOT derived.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhyNotExplanation {
    /// The fact that is not derived.
    pub conclusion: String,
    /// What's missing to derive it.
    pub missing: Vec<String>,
    /// Message explaining the situation.
    pub message: String,
}

/// Generate a "Why" explanation for a derived fact.
///
/// # Arguments
/// * `fact_id` - The fact to explain
/// * `dag` - The justification DAG
/// * `fact_names` - Mapping from FactId to human-readable fact strings
/// * `trust` - Trust scores for facts
/// * `depth` - How deep to recurse (0 = just immediate antecedents)
pub fn explain_why(
    fact_id: &FactId,
    dag: &JustificationDag,
    fact_names: &HashMap<FactId, String>,
    trust: &HashMap<FactId, TrustScore>,
    depth: usize,
) -> Option<WhyExplanation> {
    let just = dag.get_best_for_fact(fact_id)?;
    let fact_name = fact_names
        .get(fact_id)
        .cloned()
        .unwrap_or_else(|| format!("{}", fact_id));

    let derivation = explain_justification(just, dag, fact_names, trust, depth);

    Some(WhyExplanation {
        conclusion: fact_name,
        derivation,
    })
}

fn explain_justification(
    just: &Justification,
    dag: &JustificationDag,
    fact_names: &HashMap<FactId, String>,
    trust: &HashMap<FactId, TrustScore>,
    depth: usize,
) -> DerivationExplanation {
    let fact_name = fact_names
        .get(&just.fact)
        .cloned()
        .unwrap_or_else(|| format!("{}", just.fact));
    let fact_trust = trust.get(&just.fact).map(|t| t.value()).unwrap_or(1.0);

    if just.is_axiom() {
        DerivationExplanation::Axiom {
            fact: fact_name,
            source: None,
            trust: fact_trust,
        }
    } else {
        let antecedents = if depth > 0 {
            just.deps
                .iter()
                .filter_map(|dep| dag.get_best_for_fact(dep))
                .map(|j| explain_justification(j, dag, fact_names, trust, depth - 1))
                .collect()
        } else {
            just.deps
                .iter()
                .map(|dep| {
                    let name = fact_names
                        .get(dep)
                        .cloned()
                        .unwrap_or_else(|| format!("{}", dep));
                    let t = trust.get(dep).map(|t| t.value()).unwrap_or(1.0);
                    DerivationExplanation::Axiom {
                        fact: name,
                        source: None,
                        trust: t,
                    }
                })
                .collect()
        };

        DerivationExplanation::Derived {
            fact: fact_name,
            antecedents,
            rule: None, // Rule names not available without TML instrumentation
            trust: fact_trust,
        }
    }
}

/// Render an explanation to human-readable text.
pub fn render_explanation(explanation: &WhyExplanation) -> String {
    let mut output = String::new();
    render_derivation(&explanation.derivation, &mut output, 0);
    output
}

fn render_derivation(d: &DerivationExplanation, output: &mut String, indent: usize) {
    let prefix = "  ".repeat(indent);

    match d {
        DerivationExplanation::Axiom {
            fact,
            source,
            trust,
        } => {
            if let Some(src) = source {
                output.push_str(&format!(
                    "{}{} is an axiom from {} (trust {:.2})\n",
                    prefix, fact, src, trust
                ));
            } else {
                output.push_str(&format!(
                    "{}{} is an axiom (trust {:.2})\n",
                    prefix, fact, trust
                ));
            }
        }
        DerivationExplanation::Derived {
            fact,
            antecedents,
            rule,
            trust,
        } => {
            let rule_str = rule.as_deref().unwrap_or("rule");
            let ant_names: Vec<_> = antecedents
                .iter()
                .map(|a| match a {
                    DerivationExplanation::Axiom { fact, .. } => fact.clone(),
                    DerivationExplanation::Derived { fact, .. } => fact.clone(),
                })
                .collect();

            output.push_str(&format!(
                "{}{} because {} (via {}, trust {:.2})\n",
                prefix,
                fact,
                ant_names.join(" and "),
                rule_str,
                trust
            ));

            for ant in antecedents {
                render_derivation(ant, output, indent + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::Justification;

    #[test]
    fn test_explain_axiom() {
        let mut dag = JustificationDag::new();
        let a = FactId::from_canonical("a(1)");
        dag.insert(Justification::axiom(a));

        let mut names = HashMap::new();
        names.insert(a, "a(1)".to_string());

        let mut trust = HashMap::new();
        trust.insert(a, TrustScore::new(0.9).unwrap());

        let explanation = explain_why(&a, &dag, &names, &trust, 0).unwrap();
        assert_eq!(explanation.conclusion, "a(1)");

        let text = render_explanation(&explanation);
        assert!(text.contains("a(1) is an axiom"));
    }

    #[test]
    fn test_explain_derived() {
        let mut dag = JustificationDag::new();

        let a = FactId::from_canonical("a(1)");
        let b = FactId::from_canonical("b(1)");
        let c = FactId::from_canonical("c(1)");

        let just_a = Justification::axiom(a);
        let just_b = Justification::axiom(b);
        dag.insert(just_a.clone());
        dag.insert(just_b.clone());

        let just_c = Justification::derived(c, vec![a, b], &[just_a.hash, just_b.hash]);
        dag.insert(just_c);

        let mut names = HashMap::new();
        names.insert(a, "a(1)".to_string());
        names.insert(b, "b(1)".to_string());
        names.insert(c, "c(1)".to_string());

        let mut trust = HashMap::new();
        trust.insert(a, TrustScore::new(0.9).unwrap());
        trust.insert(b, TrustScore::new(0.8).unwrap());
        trust.insert(c, TrustScore::new(0.8).unwrap());

        let explanation = explain_why(&c, &dag, &names, &trust, 1).unwrap();
        let text = render_explanation(&explanation);

        assert!(text.contains("c(1) because"));
        assert!(text.contains("a(1)"));
        assert!(text.contains("b(1)"));
    }
}
