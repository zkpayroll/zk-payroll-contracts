# Company lifecycle states (#106)

Company records in `payroll_registry` carry an explicit `CompanyStatus` value so
client code and downstream contracts can distinguish setup, normal operation,
temporary suspension, and terminal shutdown.

## States

| State | Meaning | Allowed actions |
| --- | --- | --- |
| `Onboarding` | The company has been registered and is still being prepared for payroll. | Employee registry setup is allowed. Payroll periods and payments are blocked. |
| `Active` | The company is ready for normal payroll operations. | Employee registry updates, payroll period management, and payment execution are allowed. |
| `Paused` | The company is temporarily suspended. | Employee registry mutations, payroll period management, and payments are blocked until resumed. |
| `Archived` | The company has been retired. | Terminal state; employee mutations, payroll periods, payments, and further status changes are blocked. |

## Transitions

The registry exposes explicit transition functions and rejects any transition not
listed here:

- `activate_company`: `Onboarding` -> `Active`
- `pause_company`: `Active` -> `Paused`
- `resume_company`: `Paused` -> `Active`
- `archive_company`: `Onboarding` -> `Archived`, `Active` -> `Archived`, or `Paused` -> `Archived`

`Archived` has no outgoing transitions.

## Enforcement

- New companies start in `Onboarding`.
- Company admins must authorize every lifecycle transition.
- Registry employee mutations are allowed only while a company is `Onboarding` or `Active`.
- The payment executor requires `Active` companies before opening or closing periods and before executing payments.
