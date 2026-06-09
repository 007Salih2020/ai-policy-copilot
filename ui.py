from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from soc2_copilot.attestation import AttestationError, AttestationStore
from soc2_copilot.clients.openai_client import AzureOpenAIClient
from soc2_copilot.config import AppConfig
from soc2_copilot.crosswalk import CrosswalkRepository
from soc2_copilot.discovery.collector import DiscoveryCollector
from soc2_copilot.exporters.excel_exporter import ExcelExporter
from soc2_copilot.generators.audit_narratives import AuditNarrativeGenerator
from soc2_copilot.generators.control_gen import ControlGenerator
from soc2_copilot.generators.policy_gen import POLICY_SPECS, PolicyGenerator
from soc2_copilot.models import Attestation, DiscoveredFacts
from soc2_copilot.state import ensure_directory, load_discovered_facts, save_discovered_facts, save_generated_policy

st.set_page_config(
    page_title="AI SOC 2 Policy Copilot",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

OUTPUT_DIR = ROOT / "output"
POLICIES_DIR = OUTPUT_DIR / "policies"
DISCOVERED_FACTS_PATH = OUTPUT_DIR / "discovered_facts.json"
CONTROLS_PATH = OUTPUT_DIR / "controls.json"
AUDIT_PATH = OUTPUT_DIR / "audit_narratives.md"
CROSSWALK_JSON_PATH = OUTPUT_DIR / "crosswalk.json"
CROSSWALK_MD_PATH = OUTPUT_DIR / "crosswalk.md"
CROSSWALK_XLSX_PATH = OUTPUT_DIR / "crosswalk.xlsx"


def _load_config(org: str | None = None, project: str | None = None) -> AppConfig:
    config = AppConfig.from_env()
    updates: dict[str, Any] = {}
    if org:
        updates["azure_devops_org"] = org
    if project:
        updates["azure_devops_project"] = project
    return config.model_copy(update=updates)


def _optional_llm_client(config: AppConfig, use_ai: bool) -> AzureOpenAIClient | None:
    if not use_ai:
        return None
    try:
        return AzureOpenAIClient.from_config(config)
    except RuntimeError:
        st.warning("Azure OpenAI is not configured. The app will use deterministic generation.")
        return None


def _load_current_facts() -> DiscoveredFacts | None:
    if DISCOVERED_FACTS_PATH.exists():
        return load_discovered_facts(DISCOVERED_FACTS_PATH)
    return None


def _load_json_file(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _policy_files() -> list[Path]:
    if not POLICIES_DIR.exists():
        return []
    return sorted(POLICIES_DIR.glob("*.md"))


def _attested_policy_count(store: AttestationStore, paths: list[Path]) -> int:
    count = 0
    for path in paths:
        try:
            record = store.get_policy_by_identifier(str(path.resolve()))
            latest = store.get_latest_attestation(int(record["id"]))
            if latest and latest.approved:
                count += 1
        except AttestationError:
            continue
    return count


def _facts_summary(facts: DiscoveredFacts) -> dict[str, int]:
    repositories = {
        policy.repository for policy in facts.branch_policies
    } | {stat.repository for stat in facts.pr_statistics} | {scan.repository for scan in facts.scanning_statuses}
    return {
        "repositories": len(repositories),
        "branch_policies": len(facts.branch_policies),
        "manual_gates": sum(1 for gate in facts.pipeline_gates if gate.manual_approval_required is True),
        "security_groups": len(facts.security_groups),
        "service_hooks": len(facts.service_hooks),
    }


def _run_discovery(
    *,
    org: str,
    project: str,
    mode: str,
    audit_period: str,
    allow_fallback: bool,
) -> DiscoveredFacts:
    config = _load_config(org=org, project=project)
    collector = DiscoveryCollector(config)
    facts = collector.collect(
        project=project,
        mode=mode,
        audit_period=audit_period or None,
        allow_fallback=allow_fallback,
    )
    ensure_directory(OUTPUT_DIR)
    save_discovered_facts(facts, DISCOVERED_FACTS_PATH)
    return facts


def _generate_policies(facts: DiscoveredFacts, policy_types: list[str], use_ai: bool) -> list[Path]:
    config = _load_config()
    generator = PolicyGenerator(llm_client=_optional_llm_client(config, use_ai))
    store = AttestationStore(config.db_path)
    ensure_directory(POLICIES_DIR)
    generated_paths: list[Path] = []
    for policy in generator.generate_many(policy_types, facts, use_ai=use_ai):
        path = save_generated_policy(policy, POLICIES_DIR)
        policy.file_path = str(path.resolve())
        store.register_generated_policy(policy)
        generated_paths.append(path)
    return generated_paths


def _generate_controls(facts: DiscoveredFacts, criteria_ids: list[str], use_ai: bool) -> list[dict[str, Any]]:
    config = _load_config()
    generator = ControlGenerator(llm_client=_optional_llm_client(config, use_ai))
    controls = generator.generate(facts, criteria_ids, use_ai=use_ai)
    ensure_directory(CONTROLS_PATH.parent)
    payload = [control.model_dump(mode="json") for control in controls]
    CONTROLS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _generate_audit_narrative(facts: DiscoveredFacts, period: str, use_ai: bool) -> str:
    config = _load_config()
    generator = AuditNarrativeGenerator(llm_client=_optional_llm_client(config, use_ai))
    narrative = generator.generate(facts, period, use_ai=use_ai)
    AUDIT_PATH.write_text(narrative, encoding="utf-8")
    return narrative


def _export_crosswalk(export_format: str) -> Path:
    repository = CrosswalkRepository()
    if export_format == "json":
        return repository.export_json(CROSSWALK_JSON_PATH)
    if export_format == "markdown":
        return repository.export_markdown(CROSSWALK_MD_PATH)
    return ExcelExporter().export_crosswalk(repository.export_rows(), CROSSWALK_XLSX_PATH)


def _attest_policy(
    *,
    policy_path: Path,
    attested_by: str,
    role: str,
    approved: bool,
    comments: str,
    next_review_date: str,
) -> Attestation:
    store = AttestationStore(_load_config().db_path)
    return store.attest_policy_file(
        policy_path.resolve(),
        attested_by=attested_by,
        role=role,
        approved=approved,
        comments=comments or None,
        next_review_date=next_review_date or None,
    )


def _render_overview() -> None:
    facts = _load_current_facts()
    policy_paths = _policy_files()
    store = AttestationStore(_load_config().db_path)

    st.title("AI SOC 2 Policy Copilot")
    st.caption(
        "Grounded compliance drafting for Azure DevOps evidence, human attestation, and audit-ready reporting."
    )

    metric_columns = st.columns(5)
    if facts:
        summary = _facts_summary(facts)
        metric_columns[0].metric("Repositories", summary["repositories"])
        metric_columns[1].metric("Branch Policies", summary["branch_policies"])
        metric_columns[2].metric("Manual Gates", summary["manual_gates"])
        metric_columns[3].metric("Security Groups", summary["security_groups"])
        metric_columns[4].metric("Service Hooks", summary["service_hooks"])
    else:
        for column, label in zip(metric_columns, ["Repositories", "Branch Policies", "Manual Gates", "Security Groups", "Service Hooks"]):
            column.metric(label, 0)

    status_columns = st.columns(3)
    status_columns[0].metric("Policies Generated", len(policy_paths))
    status_columns[1].metric("Policies Attested", _attested_policy_count(store, policy_paths))
    status_columns[2].metric("Controls Exported", len(_load_json_file(CONTROLS_PATH) or []))

    st.subheader("Available Outputs")
    outputs = [
        DISCOVERED_FACTS_PATH,
        CONTROLS_PATH,
        AUDIT_PATH,
        CROSSWALK_JSON_PATH,
        CROSSWALK_MD_PATH,
        CROSSWALK_XLSX_PATH,
        *policy_paths,
    ]
    for path in outputs:
        if path.exists():
            with st.expander(path.relative_to(ROOT).as_posix(), expanded=False):
                st.download_button(
                    label=f"Download {path.name}",
                    data=path.read_bytes(),
                    file_name=path.name,
                    mime="application/octet-stream",
                    key=f"download-{path}",
                )
                if path.suffix in {".md", ".json"}:
                    preview = path.read_text(encoding="utf-8")
                    st.code(preview[:6000], language="markdown" if path.suffix == ".md" else "json")


def _render_discovery_tab() -> None:
    st.subheader("Discovery")
    config = _load_config()
    with st.form("discovery-form"):
        col1, col2, col3 = st.columns(3)
        org = col1.text_input("Azure DevOps Org", value=config.azure_devops_org)
        project = col2.text_input("Project", value=config.azure_devops_project)
        mode = col3.selectbox("Mode", options=["mock", "real"], index=0)
        audit_period = st.text_input("Audit Period", value="Q2 2025")
        allow_fallback = st.checkbox("Allow mock fallback when real discovery fails", value=True)
        submitted = st.form_submit_button("Run Discovery")
    if submitted:
        with st.spinner("Collecting Azure DevOps facts..."):
            facts = _run_discovery(
                org=org,
                project=project,
                mode=mode,
                audit_period=audit_period,
                allow_fallback=allow_fallback,
            )
        st.success(f"Saved discovered facts to {DISCOVERED_FACTS_PATH.relative_to(ROOT)}")
        st.json(facts.model_dump(mode="json"))
    facts = _load_current_facts()
    if facts:
        st.markdown("### Evidence Summary")
        summary_rows = [
            {"repository": policy.repository, "branch": policy.branch, "minimum_reviewers": policy.minimum_reviewers, "build_validation": policy.build_validation_enabled}
            for policy in facts.branch_policies
        ]
        if summary_rows:
            st.dataframe(summary_rows, use_container_width=True)
        st.markdown("### Discovery Notes")
        if facts.discovery_notes:
            for note in facts.discovery_notes:
                st.write(f"- `{note.category}`: {note.message}")
        else:
            st.write("No discovery notes recorded.")


def _render_policies_tab() -> None:
    st.subheader("Policies")
    facts = _load_current_facts()
    if facts is None:
        st.info("Run discovery first to generate grounded policies.")
        return
    all_policy_types = list(POLICY_SPECS.keys())
    default_types = all_policy_types
    with st.form("policy-form"):
        selected_types = st.multiselect("Policy Types", options=all_policy_types, default=default_types)
        use_ai = st.checkbox("Use Azure OpenAI if configured", value=False)
        submitted = st.form_submit_button("Generate Policies")
    if submitted and selected_types:
        with st.spinner("Generating policy drafts..."):
            generated_paths = _generate_policies(facts, selected_types, use_ai)
        st.success(f"Generated {len(generated_paths)} policy file(s).")
    for path in _policy_files():
        with st.expander(path.stem.replace("_", " ").title(), expanded=False):
            st.markdown(path.read_text(encoding="utf-8"))


def _render_controls_tab() -> None:
    st.subheader("Controls")
    facts = _load_current_facts()
    if facts is None:
        st.info("Run discovery first to generate control statements.")
        return
    criteria_ids = list(CrosswalkRepository().load_criteria().keys())
    with st.form("controls-form"):
        selected = st.multiselect("Criteria", options=criteria_ids, default=criteria_ids)
        use_ai = st.checkbox("Use Azure OpenAI for control wording", value=False)
        submitted = st.form_submit_button("Generate Controls")
    if submitted and selected:
        with st.spinner("Generating control statements..."):
            payload = _generate_controls(facts, selected, use_ai)
        st.success(f"Saved controls to {CONTROLS_PATH.relative_to(ROOT)}")
        st.dataframe(payload, use_container_width=True)
    elif CONTROLS_PATH.exists():
        st.dataframe(_load_json_file(CONTROLS_PATH), use_container_width=True)


def _render_reporting_tab() -> None:
    st.subheader("Audit Narrative and Crosswalk")
    facts = _load_current_facts()
    left, right = st.columns(2)
    with left:
        st.markdown("### Audit Narrative")
        if facts is None:
            st.info("Run discovery first to generate an audit narrative.")
        else:
            with st.form("narrative-form"):
                period = st.text_input("Reporting Period", value="Q2 2025")
                use_ai = st.checkbox("Use Azure OpenAI for narrative drafting", value=False)
                submitted = st.form_submit_button("Generate Narrative")
            if submitted:
                with st.spinner("Generating audit narrative..."):
                    narrative = _generate_audit_narrative(facts, period, use_ai)
                st.success(f"Saved narrative to {AUDIT_PATH.relative_to(ROOT)}")
                st.markdown(narrative)
            elif AUDIT_PATH.exists():
                st.markdown(AUDIT_PATH.read_text(encoding="utf-8"))
    with right:
        st.markdown("### Curated Crosswalk Export")
        export_format = st.selectbox("Format", options=["json", "markdown", "excel"], index=2)
        if st.button("Export Crosswalk"):
            output_path = _export_crosswalk(export_format)
            st.success(f"Saved crosswalk to {output_path.relative_to(ROOT)}")
        for path in [CROSSWALK_JSON_PATH, CROSSWALK_MD_PATH, CROSSWALK_XLSX_PATH]:
            if path.exists():
                st.write(path.relative_to(ROOT).as_posix())
                st.download_button(
                    label=f"Download {path.name}",
                    data=path.read_bytes(),
                    file_name=path.name,
                    mime="application/octet-stream",
                    key=f"crosswalk-{path.name}",
                )


def _render_attestation_tab() -> None:
    st.subheader("Attestation")
    policy_paths = _policy_files()
    if not policy_paths:
        st.info("Generate policies before recording attestation.")
        return
    selected_path = st.selectbox("Policy", options=policy_paths, format_func=lambda path: path.name)
    with st.form("attestation-form"):
        attested_by = st.text_input("Attested By", value="Jane Smith")
        role = st.text_input("Role", value="Security Manager")
        approved = st.checkbox("Approved", value=True)
        comments = st.text_area("Comments", value="")
        next_review_date = st.text_input("Next Review Date", value="2025-12-31")
        submitted = st.form_submit_button("Record Attestation")
    if submitted:
        with st.spinner("Recording attestation..."):
            attestation = _attest_policy(
                policy_path=selected_path,
                attested_by=attested_by,
                role=role,
                approved=approved,
                comments=comments,
                next_review_date=next_review_date,
            )
        st.success(f"Recorded attestation {attestation.id} for {selected_path.name}")

    store = AttestationStore(_load_config().db_path)
    try:
        record = store.get_policy_by_identifier(str(selected_path.resolve()))
        latest = store.get_latest_attestation(int(record["id"]))
    except AttestationError:
        latest = None
    if latest:
        st.markdown("### Latest Attestation")
        st.json(latest.model_dump(mode="json"))
    else:
        st.write("No attestation recorded yet for this policy.")


def main() -> None:
    st.sidebar.title("Runbook")
    st.sidebar.write("Use discovery first, then generate artifacts, then attest approved policies.")
    st.sidebar.write("The Streamlit app reuses the same service modules as the CLI.")

    overview_tab, discovery_tab, policies_tab, controls_tab, reporting_tab, attestation_tab = st.tabs(
        [
            "Overview",
            "Discovery",
            "Policies",
            "Controls",
            "Reporting",
            "Attestation",
        ]
    )

    with overview_tab:
        _render_overview()
    with discovery_tab:
        _render_discovery_tab()
    with policies_tab:
        _render_policies_tab()
    with controls_tab:
        _render_controls_tab()
    with reporting_tab:
        _render_reporting_tab()
    with attestation_tab:
        _render_attestation_tab()


if __name__ == "__main__":
    main()

