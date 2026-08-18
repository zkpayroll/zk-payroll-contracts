#220 Add contract validation for employee wallet format
Repo Avatar
zkpayroll/zk-payroll-contracts
﻿## Summary
Validate employee wallet formats before they are accepted into contract state.

Priority: High

Why This Matters
Invalid wallet data should fail early rather than causing later payroll errors.

Suggested Files
System.Object[]

Tasks
System.Object[]

Acceptance Criteria
System.Object[]

Coordination
Join the Telegram channel for proper coordination: https://t.me/zkpayroll


#61 [Contract] Implement employee deactivation and payroll access revocation
Repo Avatar
zkpayroll/zk-payroll-contracts
Summary
Add support for deactivating employees so they can no longer participate in future payroll runs.

Why
Employee lifecycle management needs an explicit offboarding path in addition to onboarding.

Scope
Add an employee deactivation operation
Prevent deactivated employees from receiving new payroll executions
Preserve historical payroll records for audits
Acceptance Criteria
Admins can deactivate an employee
Deactivated employees are excluded from future payroll processing
Tests cover reactivation or rejection behavior, whichever design is chosen

#218 Add contract checks for cancel-after-submit behavior
Repo Avatar
zkpayroll/zk-payroll-contracts
﻿## Summary
Verify what happens when a payroll run is cancelled after submission or during pending confirmation.

Priority: High

Why This Matters
Cancellation semantics are high-priority for operational safety and rollback planning.

Suggested Files
System.Object[]

Tasks
System.Object[]

Acceptance Criteria
System.Object[]

Coordination
Join the Telegram channel for proper coordination: https://t.me/zkpayroll

#217 Add contract validation for treasury asset mapping
Repo Avatar
zkpayroll/zk-payroll-contracts
﻿## Summary
Validate that treasury asset mappings match supported payroll assets before execution.

Priority: High

Why This Matters
Bad treasury mapping can break payroll execution or send funds into the wrong path.

Suggested Files
System.Object[]

Tasks
System.Object[]

Acceptance Criteria
System.Object[]

Coordination
Join the Telegram channel for proper coordination: https://t.me/zkpayroll


