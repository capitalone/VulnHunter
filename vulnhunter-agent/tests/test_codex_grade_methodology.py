from __future__ import annotations

import json
from pathlib import Path

from vulnhunter.config import parse_engine_config
from vulnhunter.engine import ScanEngine, _candidate_is_dormant
from vulnhunter.inventory import build_inventory, partition_inventory
from vulnhunter.methodology import (
    baseline_threat_model,
    initial_surface_ledger,
    scan_native_seeds,
)
from vulnhunter.models import AssignmentKind, Candidate


def test_momentum_mutable_installer_seed_survives_static_analysis(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "deploy.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
jobs:
  deploy:
    steps:
      - run: curl -fsSL https://example.invalid/install.sh | bash
      - run: supabase login --token "${{ secrets.SUPABASE_ACCESS_TOKEN }}"
      - run: supabase functions deploy
""",
        encoding="utf-8",
    )

    inventory = build_inventory(tmp_path)
    seeds = scan_native_seeds(inventory)

    assert ".github/workflows/deploy.yml" in inventory.files
    seed = next(row for row in seeds if row.rule_id == "VH-CI-001")
    assert seed.confidence == 0.9
    assert seed.severity == "Medium"
    assert len(seed.evidence) == 3


def test_verified_immutable_installer_does_not_match_pipe_to_shell_rule(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "deploy.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
steps:
  - run: curl -o /tmp/tool https://example.invalid/tool-v1.2.3
  - run: echo "f00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabe  /tmp/tool" | sha256sum --check -
  - run: chmod +x /tmp/tool && /tmp/tool deploy
""",
        encoding="utf-8",
    )

    seeds = scan_native_seeds(build_inventory(tmp_path))

    assert not any(row.rule_id == "VH-CI-001" for row in seeds)
    assert not any(row.rule_id == "VH-CI-003" for row in seeds)


def test_same_origin_checksum_does_not_authenticate_downloaded_executable(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "deploy.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
steps:
  - run: curl -o /tmp/tool https://mutable.invalid/tool
  - run: curl -o /tmp/tool.sha256 https://mutable.invalid/tool.sha256
  - run: sha256sum -c /tmp/tool.sha256 && chmod +x /tmp/tool && /tmp/tool --version
  - run: /tmp/tool deploy --token "${{ secrets.DEPLOY_TOKEN }}"
""",
        encoding="utf-8",
    )

    seeds = scan_native_seeds(build_inventory(tmp_path))
    seed = next(row for row in seeds if row.rule_id == "VH-CI-003")

    assert "same mutable workflow origin" in seed.closest_control
    assert seed.severity == "Medium"


def test_version_output_is_not_integrity_verification(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "version.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
steps:
  - run: curl -o /tmp/tool https://mutable.invalid/tool
  - run: chmod +x /tmp/tool && /tmp/tool --version
  - run: /tmp/tool deploy
""",
        encoding="utf-8",
    )

    seed = next(
        row
        for row in scan_native_seeds(build_inventory(tmp_path))
        if row.rule_id == "VH-CI-003"
    )

    assert "Version output" in seed.closest_control


def test_installer_without_later_privileged_action_has_lower_impact(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "lint.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "steps:\n  - run: curl -fsSL https://mutable.invalid/lint | bash\n",
        encoding="utf-8",
    )

    seed = next(
        row
        for row in scan_native_seeds(build_inventory(tmp_path))
        if row.rule_id == "VH-CI-001"
    )

    assert seed.severity == "Low"


def test_inventory_classifies_dormant_support_and_excludes_prior_results(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("print('production')\n", encoding="utf-8")
    (tmp_path / "legacy.py.bak").write_text("eval(data)\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("pass\n", encoding="utf-8")
    prior = tmp_path / "app_VULNHUNT_RESULTS_multi_2026"
    prior.mkdir()
    (prior / "leak.py").write_text("eval(data)\n", encoding="utf-8")

    inventory = build_inventory(tmp_path)

    assert inventory.production_files == ["app.py"]
    assert inventory.dormant_files == ["legacy.py.bak"]
    assert inventory.support_files == ["tests/test_app.py"]
    assert "app_VULNHUNT_RESULTS_multi_2026/leak.py" in inventory.excluded_files
    assert inventory.files == ["app.py"]


def test_inventory_excludes_temporary_and_generated_mobile_bundles(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "app.ts"
    temporary = tmp_path / "backend" / "tmp" / "benchmark.json"
    generated = (
        tmp_path
        / "android"
        / "app"
        / "src"
        / "main"
        / "assets"
        / "public"
        / "assets"
        / "main-deadbeef.js"
    )
    for path in (source, temporary, generated):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("eval(input)\n", encoding="utf-8")

    inventory = build_inventory(tmp_path)

    assert inventory.production_files == ["src/app.ts"]
    assert "backend/tmp/benchmark.json" in inventory.excluded_files
    assert (
        "android/app/src/main/assets/public/assets/main-deadbeef.js"
        in inventory.excluded_files
    )


def test_boundary_partitions_enforce_file_limit(tmp_path: Path) -> None:
    api = tmp_path / "controllers"
    api.mkdir()
    for index in range(34):
        (api / f"handler_{index}.py").write_text("def handle(): pass\n")

    partitions = partition_inventory(build_inventory(tmp_path))

    assert len(partitions) == 3
    assert all(len(partition.files) <= 15 for partition in partitions)
    assert all(partition.boundary == "public-api-parser" for partition in partitions)


def test_native_exec_rule_ignores_method_exec_but_keeps_global_eval(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "parser.ts"
    source.parent.mkdir()
    source.write_text(
        "const match = expression.exec(value);\nconst result = eval(value);\n",
        encoding="utf-8",
    )

    seeds = [
        row
        for row in scan_native_seeds(build_inventory(tmp_path))
        if row.rule_id == "VH-EXEC-001"
    ]

    assert [(row.file, row.line) for row in seeds] == [("src/parser.ts", 2)]


def test_authz_seed_ignores_android_service_device_ids(
    tmp_path: Path,
) -> None:
    android = (
        tmp_path
        / "android"
        / "app"
        / "src"
        / "main"
        / "java"
        / "ForegroundService.java"
    )
    android.parent.mkdir(parents=True)
    android.write_text("return device.getId();\n", encoding="utf-8")
    backend = tmp_path / "backend" / "src" / "services" / "prospects.service.ts"
    backend.parent.mkdir(parents=True)
    backend.write_text("return getProspectById(prospectId);\n", encoding="utf-8")

    seeds = scan_native_seeds(build_inventory(tmp_path))
    authz_paths = {
        row.file for row in seeds if row.rule_id == "VH-AUTHZ-001"
    }

    assert str(android.relative_to(tmp_path)).replace("\\", "/") not in authz_paths
    assert "backend/src/services/prospects.service.ts" in authz_paths


def test_native_rules_cover_high_signal_security_surfaces(tmp_path: Path) -> None:
    (tmp_path / "danger.py").write_text(
        "\n".join(
            [
                "subprocess.run(user_command, shell=True)",
                "archive.extractall(destination)",
                "requests.get(request.args['url'])",
                "password = 'hardcoded-administrator-secret'",
            ]
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<activity android:exported="true"></activity>\n', encoding="utf-8"
    )

    rules = {row.rule_id for row in scan_native_seeds(build_inventory(tmp_path))}

    assert {
        "VH-EXEC-002",
        "VH-ARCHIVE-001",
        "VH-NET-001",
        "VH-SECRET-001",
        "VH-MOBILE-001",
    } <= rules


def test_multiline_shell_and_custom_archive_rules_are_relationship_aware(
    tmp_path: Path,
) -> None:
    source = tmp_path / "backend" / "handlers" / "imports.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
def run_job(user_command):
    subprocess.run(
        user_command,
        cwd="/work",
        shell=True,
    )

def unpack(archive, root):
    for member in archive.infolist():
        target = root / member.filename
        target.write_bytes(archive.read(member))
""",
        encoding="utf-8",
    )

    rules = {row.rule_id for row in scan_native_seeds(build_inventory(tmp_path))}

    assert "VH-EXEC-002" in rules
    assert "VH-ARCHIVE-002" in rules


def test_custom_archive_rule_respects_visible_canonical_containment(
    tmp_path: Path,
) -> None:
    source = tmp_path / "backend" / "handlers" / "safe_import.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
def unpack(archive, root):
    root = root.resolve()
    for member in archive.infolist():
        target = (root / member.filename).resolve()
        if not target.is_relative_to(root):
            raise ValueError("escape")
        target.write_bytes(archive.read(member))
""",
        encoding="utf-8",
    )

    rules = {row.rule_id for row in scan_native_seeds(build_inventory(tmp_path))}

    assert "VH-ARCHIVE-002" not in rules


def test_shared_request_cache_gets_identity_and_terminal_path_review(
    tmp_path: Path,
) -> None:
    route = tmp_path / "server" / "routes" / "jobs.ts"
    route.parent.mkdir(parents=True)
    route.write_text(
        """
const requestResults = new Map<string, Promise<object>>();
router.post("/jobs", async (req, res) => {
  const key = req.body.idempotency_key;
  const prior = requestResults.get(key);
  if (prior) return res.json(await prior);
  const pending = processJob(req.body);
  requestResults.set(key, pending);
  const result = await pending;
  if (!result) return;
  setTimeout(() => requestResults.delete(key), 60_000);
  return res.json(result);
});
""",
        encoding="utf-8",
    )

    seed = next(
        row
        for row in scan_native_seeds(build_inventory(tmp_path))
        if row.rule_id == "VH-CACHE-001"
    )

    assert "identity and lifecycle" in seed.title
    assert "early return" in seed.closest_control


def test_function_local_aggregation_map_is_not_a_shared_cache_seed(
    tmp_path: Path,
) -> None:
    source = tmp_path / "server" / "services" / "totals.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
export function totals(rows) {
  const valuesById = new Map();
  for (const row of rows) valuesById.set(row.id, row.value);
  return valuesById;
}
""",
        encoding="utf-8",
    )

    rules = {row.rule_id for row in scan_native_seeds(build_inventory(tmp_path))}

    assert "VH-CACHE-001" not in rules


def test_privileged_external_identity_join_gets_cross_tenant_review(
    tmp_path: Path,
) -> None:
    config = tmp_path / "server" / "config" / "database.ts"
    service = tmp_path / "server" / "services" / "contacts.ts"
    config.parent.mkdir(parents=True)
    service.parent.mkdir(parents=True)
    config.write_text(
        """
const endpoint = process.env.DB_URL;
export const systemDb = createClient(endpoint, process.env.SERVICE_ROLE_KEY);
""",
        encoding="utf-8",
    )
    service.write_text(
        """
import { systemDb } from "../config/database";
export async function claimHistory(userId, data) {
  const phoneNumber = data.phone_number;
  const rows = await systemDb.from("pending").select("*").eq("phone", phoneNumber);
  return systemDb.from("history").insert(
    rows.map(row => ({ user_id: userId, body: row.body }))
  );
}
""",
        encoding="utf-8",
    )

    seeds = scan_native_seeds(build_inventory(tmp_path))
    seed = next(row for row in seeds if row.rule_id == "VH-AUTHZ-003")

    assert seed.file == "server/services/contacts.ts"
    assert "source records" not in seed.title  # No product-specific terminology.
    assert "caller-selected identifier" in seed.impact


def test_buffered_upload_without_limit_gets_resource_seed(
    tmp_path: Path,
) -> None:
    route = tmp_path / "api" / "routes" / "media.ts"
    route.parent.mkdir(parents=True)
    route.write_text(
        """
const upload = multer({ storage: multer.memoryStorage() });
router.post("/audio", upload.single("audio"), async (req, res) => {
  await transcribe(req.file.buffer);
  res.sendStatus(204);
});
""",
        encoding="utf-8",
    )

    rules = {row.rule_id for row in scan_native_seeds(build_inventory(tmp_path))}

    assert "VH-RESOURCE-001" in rules


def test_buffered_upload_with_explicit_file_limit_avoids_resource_seed(
    tmp_path: Path,
) -> None:
    route = tmp_path / "api" / "routes" / "media.ts"
    route.parent.mkdir(parents=True)
    route.write_text(
        """
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});
router.post("/audio", upload.single("audio"), handler);
""",
        encoding="utf-8",
    )

    rules = {row.rule_id for row in scan_native_seeds(build_inventory(tmp_path))}

    assert "VH-RESOURCE-001" not in rules


def test_snapshot_digest_changes_when_support_evidence_changes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('app')\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    evidence = tests / "test_security.py"
    evidence.write_text("def test_control(): pass\n", encoding="utf-8")
    before = build_inventory(tmp_path).snapshot_digest

    evidence.write_text("def test_control(): assert False\n", encoding="utf-8")
    after = build_inventory(tmp_path).snapshot_digest

    assert before != after


def test_v2_manifest_is_machine_readable_from_team_scan_artifacts(
    tmp_path: Path,
) -> None:
    # Fixture assertion used by packaging tests: the v2 schema itself remains
    # valid JSON and advertises the exact new contract version.
    schema = (
        Path(__file__).resolve().parents[1]
        / "vulnhunter"
        / "schemas"
        / "run_manifest.schema.json"
    )
    payload = json.loads(schema.read_text(encoding="utf-8"))
    assert payload["properties"]["schema_version"]["const"] == "2"


def test_every_uncovered_critical_surface_gets_a_clean_challenger(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "safe.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("steps:\n  - run: echo safe\n", encoding="utf-8")
    inventory = build_inventory(tmp_path)
    config = parse_engine_config(
        {
            "providers": {
                "local": {
                    "kind": "openai_compatible",
                    "base_url": "http://local",
                    "remote": False,
                }
            },
            "models": {
                "model": {"provider": "local", "model": "test"}
            },
        }
    )
    engine = ScanEngine(config, providers={})
    models = [config.models["model"]]
    rows = initial_surface_ledger(inventory.surfaces, ["model"])

    assignments = engine._clean_challenge_assignments(
        rows, [], models, baseline_threat_model(inventory)
    )

    assert len(assignments) == 1
    assert assignments[0].kind == AssignmentKind.CLEAN_CHALLENGE
    assert assignments[0].files == [".github/workflows/safe.yml"]


def test_dormant_candidate_is_detected_for_deferred_disposition(
    tmp_path: Path,
) -> None:
    (tmp_path / "integration.py.bak").write_text(
        "eval(payload)\n", encoding="utf-8"
    )
    inventory = build_inventory(tmp_path, include_dormant=True)
    candidate = Candidate(
        candidate_id="CAND-1",
        title="Dormant integration execution",
        classification="code execution",
        severity="High",
        cwe="CWE-94",
        source={"file": "integration.py.bak", "line": 1},
        sink={"file": "integration.py.bak", "line": 1},
        trace=[],
        root_cause="eval",
        attacker_prerequisites=[],
        new_capability="execute code",
        contradicting_evidence=[],
        fix_strategy="remove it",
    )

    assert _candidate_is_dormant(candidate, inventory) is True
