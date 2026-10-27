# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

"""Behavioral regressions using synthetic local process/shell boundaries only."""

import csv
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import unittest
import uuid


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[5]
LINUX_SETUP = REPO / "TestSuites/FileServer/Setup/Scripts/Create-SMB2Env-Linux.sh"
WRAPPER = HERE.parent / "Run-FileServerWithSutLogs.ps1"
SSH = REPO / "TestSuites/MS-SMBD/src/Batch/SutDebug/Invoke-SutSsh.ps1"


def executable(name, override):
    value = os.environ.get(override) or shutil.which(name)
    if not value:
        raise RuntimeError(f"Existing {name} runtime required; set {override}.")
    return value


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


class SyntheticCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = HERE / ".test-output" / (cls.__name__ + "-" + uuid.uuid4().hex)
        cls.output.mkdir(parents=True)

    def run_process(self, arguments, directory, stdin=None):
        result = subprocess.run(
            arguments, input=stdin, cwd=directory, text=True,
            capture_output=True, timeout=30,
        )
        (directory / "stdout.txt").write_text(result.stdout, encoding="utf-8")
        (directory / "stderr.txt").write_text(result.stderr, encoding="utf-8")
        (directory / "exit.json").write_text(
            json.dumps({"exit_code": result.returncode}), encoding="utf-8"
        )
        return result

    def case_directory(self, label):
        directory = self.output / label
        directory.mkdir()
        return directory


class LinuxShareAccessTests(SyntheticCase):
    def run_permissions(self, second_user, fail_acl=False):
        text = LINUX_SETUP.read_text(encoding="utf-8")
        start = text.index("for d in FileShare ")
        body = text[start:text.index("\nshare_block()", start)]
        helper = re.search(r"(?ms)^prepare_share_directory\(\) \{.*?^\}", text)
        if helper:
            body = helper.group(0) + "\n" + body
        directory = self.case_directory(uuid.uuid4().hex)
        bootstrap = r"""
set -euo pipefail
USER_NAME=primary_fixture
SECOND_USER=SECOND_USER_VALUE
ROOT='/synthetic share root'
mkdir() { printf 'mkdir|%s\n' "$*"; }
chown() { printf 'chown|%s|%s\n' "$1" "$2"; }
chmod() { printf 'chmod|%s|%s\n' "$1" "$2"; }
ln() { :; }
setfacl() {
    printf 'acl|%s|%s\n' "$2" "$3"
    return ACL_RESULT
}
"""
        bootstrap = bootstrap.replace("SECOND_USER_VALUE", shlex.quote(second_user))
        bootstrap = bootstrap.replace("ACL_RESULT", "17" if fail_acl else "0")
        result = self.run_process(
            [executable("bash", "WPTS_TEST_BASH"), "--noprofile", "--norc", "-c", bootstrap + body],
            directory,
        )
        return result, [line.split("|") for line in result.stdout.splitlines()]

    def test_second_user_gets_narrow_access_and_default_acl_without_owner_collapse(self):
        result, calls = self.run_permissions("secondary_fixture")
        self.assertEqual(0, result.returncode, result.stderr)
        acl_calls = [call for call in calls if call[0] == "acl"]
        self.assertEqual(8, len(acl_calls), "Every managed directory, including SMBBasic/sub.")
        for _, acl, path in acl_calls:
            self.assertIn("u:secondary_fixture:rwx", acl.split(","))
            self.assertIn("d:u:primary_fixture:rwx", acl.split(","))
            self.assertIn("d:u:secondary_fixture:rwx", acl.split(","))
            self.assertIn("d:o::---", acl.split(","))
            self.assertTrue(path.startswith("/synthetic share root/"))
        owners = [call[1] for call in calls if call[0] == "chown"]
        self.assertEqual(["primary_fixture"] * 8, owners)

    def test_no_second_user_preserves_existing_mode_and_needs_no_acl_operation(self):
        result, calls = self.run_permissions("")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(any(call[0] == "acl" for call in calls))
        modes = [call[1] for call in calls if call[0] == "chmod"]
        self.assertTrue(modes)
        self.assertEqual({"0770"}, set(modes))

    def test_acl_failure_is_not_reported_as_success(self):
        result, calls = self.run_permissions("secondary_fixture", fail_acl=True)
        self.assertEqual(17, result.returncode)
        self.assertEqual(1, sum(call[0] == "acl" for call in calls))

    def test_repeated_preparation_has_the_same_permission_operations(self):
        first, first_calls = self.run_permissions("secondary_fixture")
        second, second_calls = self.run_permissions("secondary_fixture")
        self.assertEqual((0, 0), (first.returncode, second.returncode))
        self.assertEqual(first_calls, second_calls)

    def test_missing_acl_tool_fails_before_creating_a_second_account(self):
        text = LINUX_SETUP.read_text(encoding="utf-8")
        start = text.index("VALID_USERS=$USER_NAME")
        body = text[start:text.index('\nif [ "$SERVER" = auto ];', start)]
        directory = self.case_directory(uuid.uuid4().hex)
        bootstrap = """
set -euo pipefail
USER_NAME=primary_fixture
SECOND_USER=secondary_fixture
command() { return 1; }
id() { return 1; }
useradd() { printf 'unexpected-account-mutation'; }
"""
        result = self.run_process(
            [executable("bash", "WPTS_TEST_BASH"), "--noprofile", "--norc", "-c", bootstrap + body],
            directory,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("unexpected-account-mutation", result.stdout)
        self.assertIn("requires setfacl", result.stderr)


class WrapperOutcomeTests(SyntheticCase):
    def run_wrapper(self, code, evidence_failure=False, stop_failure=False, start_failure=False, launch_failure=False, native_error_preference=False):
        directory = self.case_directory(uuid.uuid4().hex)
        result_dir = directory / "results"
        result_dir.mkdir()
        dll = directory / "synthetic.dll"
        dll.write_text("not a real test assembly", encoding="utf-8")
        ssh_double = directory / "synthetic-ssh.ps1"
        ssh_double.write_text(
            r"""
param([string]$Command, [switch]$Sudo)
if ($Command -like 'dmesg*' -and $global:DebugFixture.EvidenceFailure) {
    throw 'Synthetic evidence failure'
}
if ($Command -like 'date*') { '2026-01-01T00:00:00+00:00' }
if ($Command -like 'dmesg*') { '2026-01-01T00:00:01,000000+00:00 synthetic kernel line' }
exit 0
""", encoding="utf-8"
        )
        native_double = directory / "synthetic-dotnet.ps1"
        native_double.write_text(
            r"""
param([int]$ExitCode, [string]$OutputDir)
$outcome = if ($ExitCode -eq 0) { 'Passed' } else { 'Failed' }
@"
<TestRun><Results><UnitTestResult testName="SyntheticCase" outcome="$outcome"
 startTime="2026-01-01T00:00:00+00:00" endTime="2026-01-01T00:00:02+00:00" /></Results></TestRun>
"@ | Set-Content -LiteralPath (Join-Path $OutputDir 'results.trx')
'  ' + $outcome + ' SyntheticCase'
exit $ExitCode
""", encoding="utf-8"
        )
        driver = directory / "driver.ps1"
        state = {
            "Code": code, "Output": str(result_dir), "Native": str(native_double),
            "Events": str(directory / "capture-events.txt"),
            "EvidenceFailure": evidence_failure, "StopFailure": stop_failure,
            "StartFailure": start_failure, "LaunchFailure": launch_failure,
            "NativeErrorPreference": native_error_preference,
            "Stops": 0, "Pwsh": executable("pwsh", "WPTS_TEST_PWSH"),
        }
        driver.write_text(
            "$global:DebugFixture = " + ps_literal(json.dumps(state)) + " | ConvertFrom-Json\n"
            + r"""
$PSNativeCommandUseErrorActionPreference = $global:DebugFixture.NativeErrorPreference
function global:dotnet {
    if ($global:DebugFixture.LaunchFailure) { throw 'Synthetic launch failure' }
    & $global:DebugFixture.Pwsh -NoLogo -NoProfile -File $global:DebugFixture.Native `
        -ExitCode $global:DebugFixture.Code -OutputDir $global:DebugFixture.Output
}
function global:pktmon {
    [IO.File]::AppendAllText($global:DebugFixture.Events, ($args -join ' ') + "`n")
    if ($args[0] -eq 'stop') {
        $global:DebugFixture.Stops++
        if ($global:DebugFixture.Stops -gt 1 -and $global:DebugFixture.StopFailure) {
            throw 'Synthetic stop failure'
        }
    }
    $global:LASTEXITCODE = if ($args[0] -eq 'start' -and $global:DebugFixture.StartFailure) { 19 } else { 0 }
}
"""
            + f"& {ps_literal(WRAPPER)} -TestDll {ps_literal(dll)} -OutDir {ps_literal(result_dir)} -SshScript {ps_literal(ssh_double)}\n"
            + "exit $LASTEXITCODE\n", encoding="utf-8"
        )
        result = self.run_process(
            [executable("pwsh", "WPTS_TEST_PWSH"), "-NoLogo", "-NoProfile", "-File", str(driver)],
            directory,
        )
        events = (directory / "capture-events.txt").read_text().splitlines()
        return result, events, result_dir

    def test_completed_success_and_nonzero_test_outcomes_are_authoritative(self):
        for code in (0, 23):
            with self.subTest(code=code):
                result, events, output = self.run_wrapper(code)
                self.assertEqual(code, result.returncode, result.stdout + result.stderr)
                with (output / "summary.csv").open(encoding="utf-8-sig", newline="") as summary:
                    rows = list(csv.DictReader(summary))
                self.assertEqual(1, len(rows))
                self.assertEqual("SyntheticCase", rows[0]["Test"])
                self.assertEqual("Passed" if code == 0 else "Failed", rows[0]["Outcome"])
                self.assertEqual("1", rows[0]["SutLines"])
                self.assertEqual(2, events.count("stop"))
                self.assertEqual(1, sum(event.startswith("etl2pcap ") for event in events))

    def test_evidence_failure_cannot_replace_success_or_test_failure(self):
        for code in (0, 23):
            with self.subTest(code=code):
                result, events, _ = self.run_wrapper(code, evidence_failure=True)
                self.assertEqual(code, result.returncode, result.stdout + result.stderr)
                self.assertEqual(2, events.count("stop"))

    def test_capture_cleanup_failure_cannot_replace_success_or_test_failure(self):
        for code in (0, 23):
            with self.subTest(code=code):
                result, events, _ = self.run_wrapper(code, stop_failure=True)
                self.assertEqual(code, result.returncode, result.stdout + result.stderr)
                self.assertEqual(2, events.count("stop"))

    def test_failed_capture_start_does_not_claim_an_owned_session(self):
        result, events, _ = self.run_wrapper(0, start_failure=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(1, events.count("stop"))
        self.assertFalse(any(event.startswith("etl2pcap ") for event in events))

    def test_launch_failure_still_stops_the_owned_capture(self):
        result, events, _ = self.run_wrapper(0, launch_failure=True)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(2, events.count("stop"))

    def test_inherited_native_error_preference_preserves_completed_test_status(self):
        result, events, _ = self.run_wrapper(23, native_error_preference=True)
        self.assertEqual(23, result.returncode, result.stdout + result.stderr)
        self.assertEqual(2, events.count("stop"))


class SudoShellQuotingTests(SyntheticCase):
    def build_command(self, command, sudo=True, password="synthetic-only"):
        directory = self.case_directory(uuid.uuid4().hex)
        fixture = directory / "input.json"
        fixture.write_text(json.dumps({"command": command, "sudo": sudo, "password": password}), encoding="utf-8")
        driver = directory / "build-command.ps1"
        driver.write_text(
            f"$inputFixture = Get-Content -LiteralPath {ps_literal(fixture)} -Raw | ConvertFrom-Json\n"
            f"$ast = [System.Management.Automation.Language.Parser]::ParseFile({ps_literal(SSH)}, [ref]$null, [ref]$null)\n"
            + r"""
$block = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -eq '$Sudo'
}, $true)
if (-not $block) { throw 'Sudo command construction block was not found' }
$Command = $inputFixture.command
$password = $inputFixture.password
$Sudo = $inputFixture.sudo
. ([scriptblock]::Create($block.Extent.Text))
$Command | ConvertTo-Json -Compress
""", encoding="utf-8"
        )
        result = self.run_process(
            [executable("pwsh", "WPTS_TEST_PWSH"), "-NoLogo", "-NoProfile", "-File", str(driver)], directory
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout), directory

    def execute_fake_sudo(self, command, directory, password="synthetic-only"):
        bootstrap = r"""
set -euo pipefail
sudo() {
    local supplied
    IFS= read -r supplied
    [ "$supplied" = EXPECTED_PASSWORD ]
    [ "$1" = -S ]; shift
    [ "$1" = -p ]; shift
    [ "$1" = '' ]; shift
    export SYNTHETIC_ELEVATED=yes
    "$@"
}
"""
        bootstrap = bootstrap.replace("EXPECTED_PASSWORD", shlex.quote(password))
        return self.run_process(
            [executable("bash", "WPTS_TEST_BASH"), "--noprofile", "--norc", "-c", bootstrap + command],
            directory,
        )

    def test_redirection_and_pipeline_execute_inside_the_elevated_shell(self):
        command = """printf '%s' "${SYNTHETIC_ELEVATED:-no}" | tr a-z A-Z > marker.txt"""
        built, directory = self.build_command(command)
        result = self.execute_fake_sudo(built, directory)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("YES", (directory / "marker.txt").read_text())

    def test_quotes_newlines_and_empty_output_remain_literal(self):
        command = """printf '%s' "literal 'quote' \\"double\\" ; $SYNTHETIC_ELEVATED" > quoted.txt
printf '%s' '' > empty.txt"""
        built, directory = self.build_command(command)
        result = self.execute_fake_sudo(built, directory)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("literal 'quote' \"double\" ; yes", (directory / "quoted.txt").read_text())
        self.assertEqual("", (directory / "empty.txt").read_text())

    def test_synthetic_password_shell_characters_cannot_change_the_command(self):
        password = "synthetic' ; printf injected > unexpected.txt ; echo '"
        built, directory = self.build_command("printf '%s' \"$SYNTHETIC_ELEVATED\" > marker.txt", password=password)
        result = self.execute_fake_sudo(built, directory, password=password)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("yes", (directory / "marker.txt").read_text())
        self.assertFalse((directory / "unexpected.txt").exists())

    def test_without_sudo_the_operator_command_is_unchanged(self):
        command = """printf '%s' 'literal command' | cat"""
        built, _ = self.build_command(command, sudo=False)
        self.assertEqual(command, built)

    def test_elevated_command_failure_is_not_reported_as_success(self):
        built, directory = self.build_command("exit 29")
        result = self.execute_fake_sudo(built, directory)
        self.assertEqual(29, result.returncode)


if __name__ == "__main__":
    unittest.main()
