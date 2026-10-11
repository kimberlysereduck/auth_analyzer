# Authentication Log Analyzer

A dependency-free Python CLI that parses common SSH `sshd` authentication lines and a simple generic format, then flags explainable suspicious activity.

## Usage

```bash
python3 auth_analyzer.py sample_auth.log
python3 auth_analyzer.py /var/log/auth.log --threshold 5 --window 10
cat auth.log | python3 auth_analyzer.py - --json
```

Supported SSH examples include `Failed password`, `Invalid user`, and `Accepted password`. Generic lines use this shape:

```text
2026-08-10T09:00:00 LOGIN_FAILED user=alice ip=203.0.113.10
```

Detections:

- `multiple_failed_login_attempts`: a burst of failed logins from one source or toward one account in the configured window.
- `brute_force_source`: repeated failures from one source in the configured window.
- `targeted_account_attack`: repeated failures against one account in the configured window.
- `success_after_failures`: a successful login after recent failures for the same account.
- `successful_login_from_new_source`: an account succeeds from a different source than its prior success.

The tool reports findings; it does not block accounts or make a final determination of compromise. Treat alerts as triage signals and tune thresholds for your environment.
