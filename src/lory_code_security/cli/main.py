"""Root command group for the ``lory`` CLI."""

from __future__ import annotations

import click

from lory_code_security import __version__
from lory_code_security.cli.chat import ask, chat
from lory_code_security.cli.findings import findings, retest, trace, triage
from lory_code_security.cli.fix import fix
from lory_code_security.cli.harness import harness
from lory_code_security.cli.mcp import mcp, portal
from lory_code_security.cli.setup import doctor, init
from lory_code_security.cli.tui import tui


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="lory",
                      message=f"lory-code-security v{__version__}")
def main() -> None:
    """Triage Lorikeet Security findings and fix them with Lory, from a terminal.

    Findings are produced by Lory's pentest engine and by Lorikeet's testers,
    reviewed by a human, and published to your portal. This tool is the half
    that comes after: pull those findings down, locate the code responsible,
    ask Lory how to fix it, and request a retest. It does not scan anything
    itself.

    \b
    ──────────────────────────────────────────────────────────────────────────
    GETTING STARTED
    ──────────────────────────────────────────────────────────────────────────
      1.  lory init            Set up from your Lorikeet portal (one time).
      2.  lory doctor          Confirm the connection and your token's scopes.
      3.  lory tui             Open the findings cockpit.

    \b
    ──────────────────────────────────────────────────────────────────────────
    COMMANDS
    ──────────────────────────────────────────────────────────────────────────
      init       Set up credentials from the portal, or import an existing one.
      doctor     Check config, connectivity, scopes, and repo detection.
      tui        Full-screen findings and remediation cockpit.
      findings   list / show / export the findings on your account.
      trace      Show local source that may be responsible for a finding.
      fix        Ask Lory for a code-level fix for one finding.
      triage     Set your local workflow state on a finding.
      retest     Ask the Lorikeet team to re-test a finding you have fixed.
      ask        One-shot question to Lory.
      chat       Interactive chat with Lory.
      mcp        Raw MCP access: list tools, call one.
      portal     Portal PHP endpoints: SARIF export, attestation, review queue.
      harness    Run YAML scenarios against Lory (regression + guardrail tests).

    \b
    ──────────────────────────────────────────────────────────────────────────
    HOW IT READS YOUR FINDINGS
    ──────────────────────────────────────────────────────────────────────────
    Two paths, both scoped to your company by the platform:

      mcp      findings.list / findings.get over a lkmcp_ bearer token. This
               is all you need: it works headless and drives every command.
      portal   findings-export.php over a dashboard session cookie. OPTIONAL.
               Adds full bodies in one call, SARIF export, and attestation
               letters. Used automatically when a cookie is configured.

    \b
    ──────────────────────────────────────────────────────────────────────────
    WHAT LEAVES YOUR MACHINE
    ──────────────────────────────────────────────────────────────────────────
    Source code is never sent unless you ask for it, with `fix --code` or by
    setting `send_code_context: true`. Use `fix --dry-run` to print the exact
    prompt without sending anything.
    """


main.add_command(init)
main.add_command(doctor)
main.add_command(tui)
main.add_command(findings)
main.add_command(trace)
main.add_command(fix)
main.add_command(triage)
main.add_command(retest)
main.add_command(ask)
main.add_command(chat)
main.add_command(mcp)
main.add_command(portal)
main.add_command(harness)


if __name__ == "__main__":  # pragma: no cover
    main()
