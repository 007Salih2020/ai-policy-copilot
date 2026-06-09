from __future__ import annotations

import json
from pathlib import Path

import typer

from soc2_copilot.attestation import AttestationStore
from soc2_copilot.clients.ciso_client import CISOAssistantClient
from soc2_copilot.clients.openai_client import AzureOpenAIClient
from soc2_copilot.config import AppConfig
from soc2_copilot.crosswalk import CrosswalkRepository
from soc2_copilot.discovery.collector import DiscoveryCollector
from soc2_copilot.exporters.excel_exporter import ExcelExporter
from soc2_copilot.exporters.wiki import AzureDevOpsWikiPublisher
from soc2_copilot.generators.audit_narratives import AuditNarrativeGenerator
from soc2_copilot.generators.control_gen import ControlGenerator
from soc2_copilot.generators.policy_gen import POLICY_SPECS, PolicyGenerator
from soc2_copilot.state import ensure_directory, load_discovered_facts, save_discovered_facts, save_generated_policy

app = typer.Typer(help="Grounded SOC 2 policy copilot for Azure DevOps evidence.")


def _config_with_overrides(*, org: str | None = None, project: str | None = None) -> AppConfig:
    config = AppConfig.from_env()
    updates = {}
    if org:
        updates["azure_devops_org"] = org
    if project:
        updates["azure_devops_project"] = project
    return config.model_copy(update=updates)


def _parse_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _optional_llm_client(config: AppConfig, use_ai: bool) -> AzureOpenAIClient | None:
    if not use_ai:
        return None
    try:
        return AzureOpenAIClient.from_config(config)
    except RuntimeError:
        typer.echo("Azure OpenAI is not configured; using deterministic generation.")
        return None


@app.command("discover")
def discover(
    org: str | None = typer.Option(None, "--org", help="Azure DevOps organization URL."),
    project: str | None = typer.Option(None, "--project", help="Azure DevOps project name."),
    output: Path = typer.Option(Path("./output/discovered_facts.json"), "--output", help="Output JSON path."),
    mode: str = typer.Option("mock", "--mode", help="Discovery mode: mock or real."),
    audit_period: str = typer.Option(None, "--audit-period", help="Optional reporting period context."),
    allow_fallback: bool = typer.Option(True, "--allow-fallback/--no-allow-fallback", help="Fall back to mock data if real discovery fails."),
) -> None:
    config = _config_with_overrides(org=org, project=project)
    collector = DiscoveryCollector(config)
    facts = collector.collect(
        project=config.azure_devops_project,
        mode=mode,
        audit_period=audit_period,
        allow_fallback=allow_fallback,
    )
    save_discovered_facts(facts, output)
    typer.echo(f"Saved discovered facts to {output}")


@app.command("generate-policies")
def generate_policies(
    facts: Path = typer.Option(..., "--facts", help="Path to discovered facts JSON."),
    types: str = typer.Option("all", "--types", help="Comma-separated policy types or 'all'."),
    output: Path = typer.Option(Path("./output/policies"), "--output", help="Output directory for Markdown policies."),
    use_ai: bool = typer.Option(False, "--use-ai/--no-use-ai", help="Use Azure OpenAI when configured."),
) -> None:
    config = AppConfig.from_env()
    facts_model = load_discovered_facts(facts)
    generator = PolicyGenerator(llm_client=_optional_llm_client(config, use_ai))
    requested_types = _parse_csv(types)
    policies = generator.generate_many(requested_types, facts_model, use_ai=use_ai)
    store = AttestationStore(config.db_path)
    ensure_directory(output)
    for policy in policies:
        path = save_generated_policy(policy, output)
        policy.file_path = str(path.resolve())
        policy_id = store.register_generated_policy(policy)
        typer.echo(f"{policy.policy_type}: {path} (policy_id={policy_id})")


@app.command("generate-controls")
def generate_controls(
    facts: Path = typer.Option(..., "--facts", help="Path to discovered facts JSON."),
    criteria: str = typer.Option("all", "--criteria", help="Comma-separated criteria ids or 'all'."),
    output: Path = typer.Option(Path("./output/controls.json"), "--output", help="Output JSON path."),
    push_ciso: bool = typer.Option(False, "--push-ciso/--no-push-ciso", help="Push generated controls to CISO Assistant."),
    use_ai: bool = typer.Option(False, "--use-ai/--no-use-ai", help="Use Azure OpenAI when configured."),
) -> None:
    config = AppConfig.from_env()
    facts_model = load_discovered_facts(facts)
    generator = ControlGenerator(llm_client=_optional_llm_client(config, use_ai))
    criteria_ids = _parse_csv(criteria)
    controls = generator.generate(facts_model, criteria_ids, use_ai=use_ai)
    ensure_directory(output.parent)
    output.write_text(
        json.dumps([control.model_dump(mode="json") for control in controls], indent=2),
        encoding="utf-8",
    )
    typer.echo(f"Saved controls to {output}")
    if push_ciso:
        client = CISOAssistantClient.from_config(config)
        client.push_controls(controls)
        typer.echo("Pushed controls to CISO Assistant.")


@app.command("crosswalk")
def crosswalk(
    format: str = typer.Option("excel", "--format", help="Export format: excel, json, or markdown."),
    output: Path = typer.Option(Path("./output/crosswalk.xlsx"), "--output", help="Crosswalk output path."),
) -> None:
    repository = CrosswalkRepository()
    if format == "excel":
        ExcelExporter().export_crosswalk(repository.export_rows(), output)
    elif format == "json":
        repository.export_json(output)
    elif format == "markdown":
        repository.export_markdown(output)
    else:
        raise typer.BadParameter("Format must be one of: excel, json, markdown.")
    typer.echo(f"Saved crosswalk to {output}")


@app.command("attest")
def attest(
    policy: Path = typer.Option(..., "--policy", help="Path to the policy Markdown file."),
    attested_by: str = typer.Option(..., "--attested-by", help="Named approver."),
    role: str = typer.Option(..., "--role", help="Approver role."),
    approved: bool = typer.Option(True, "--approved/--rejected", help="Approval decision."),
    comments: str | None = typer.Option(None, "--comments", help="Optional reviewer comments."),
    next_review_date: str | None = typer.Option(None, "--next-review-date", help="Next review date in YYYY-MM-DD format."),
) -> None:
    config = AppConfig.from_env()
    store = AttestationStore(config.db_path)
    attestation = store.attest_policy_file(
        policy.resolve(),
        attested_by=attested_by,
        role=role,
        approved=approved,
        comments=comments,
        next_review_date=next_review_date,
    )
    diff = store.get_previous_version_diff(attestation.policy_id)
    typer.echo(f"Recorded attestation {attestation.id} for policy_id={attestation.policy_id}")
    if diff:
        typer.echo(diff)


@app.command("publish-wiki")
def publish_wiki(
    policy: str = typer.Option(..., "--policy", help="Policy type or file path."),
    wiki_id: str | None = typer.Option(None, "--wiki-id", help="Azure DevOps wiki identifier."),
    project: str | None = typer.Option(None, "--project", help="Azure DevOps project name."),
) -> None:
    config = _config_with_overrides(project=project)
    target_wiki_id = wiki_id or config.azure_devops_wiki_id
    if not target_wiki_id:
        raise typer.BadParameter("A wiki id is required either via --wiki-id or AZURE_DEVOPS_WIKI_ID.")
    publisher = AzureDevOpsWikiPublisher(
        org_url=config.azure_devops_org,
        pat=config.azure_devops_pat or "",
        project=config.azure_devops_project,
    )
    store = AttestationStore(config.db_path)
    publisher.publish_attested_policy(policy_identifier=policy, wiki_id=target_wiki_id, store=store)
    typer.echo(f"Published {policy} to wiki {target_wiki_id}")


@app.command("audit-narratives")
def audit_narratives(
    facts: Path = typer.Option(..., "--facts", help="Path to discovered facts JSON."),
    period: str = typer.Option(..., "--period", help="Reporting period label."),
    output: Path = typer.Option(Path("./output/audit_narratives.md"), "--output", help="Output Markdown path."),
    use_ai: bool = typer.Option(False, "--use-ai/--no-use-ai", help="Use Azure OpenAI when configured."),
) -> None:
    config = AppConfig.from_env()
    narrative = AuditNarrativeGenerator(llm_client=_optional_llm_client(config, use_ai)).generate(
        load_discovered_facts(facts),
        period,
        use_ai=use_ai,
    )
    ensure_directory(output.parent)
    output.write_text(narrative, encoding="utf-8")
    typer.echo(f"Saved audit narrative to {output}")


@app.command("list-policy-types")
def list_policy_types() -> None:
    typer.echo("\n".join(POLICY_SPECS.keys()))


if __name__ == "__main__":
    app()
