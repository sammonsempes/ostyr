use crate::error::ComplianceError;
use crate::evaluate::find_exception;
use crate::model::{Baseline, Control, CorrectionRequest, DeferReason, DeferredCorrection, DeviceVerdicts, Exception, Plan, Policy, Verdict};
use std::collections::HashSet;
use time::OffsetDateTime;


fn check_tenant(expected: &str, found: &str) -> Result<(), ComplianceError> {
    if expected == found {
        Ok(())
    } else {
        Err(ComplianceError::TenantMismatch {
            expected: expected.to_string(),
            found: found.to_string(),
        })
    }
}


fn check_controls_unique(device: &DeviceVerdicts) -> Result<(), ComplianceError> {
    let mut controls = HashSet::new();
    device.verdicts.iter().try_for_each(|(control, _)| {
        if controls.insert(control.as_str()) {
            Ok(())
        } else {
            Err(ComplianceError::DuplicateControl {
                device: device.target.device.clone(),
                control: control.clone(),
            })
        }
    })
}


fn check_unique(verdicts: &[DeviceVerdicts]) -> Result<(), ComplianceError> {
    let mut devices = HashSet::new();
    verdicts.iter().try_for_each(|device| {
        if devices.insert(device.target.device.as_str()) {
            check_controls_unique(device)
        } else {
            Err(ComplianceError::DuplicateDevice {
                device: device.target.device.clone(),
            })
        }
    })
}


fn find_control<'a>(baseline: &'a Baseline, id: &str) -> Result<&'a Control, ComplianceError> {
    baseline
        .controls
        .iter()
        .find(|control| control.id == id)
        .ok_or_else(|| ComplianceError::UnknownControl { control: id.to_string() })
}


fn eligible_requests(
    baseline: &Baseline,
    exceptions: &[Exception],
    device: &DeviceVerdicts,
    now: OffsetDateTime,
) -> Result<Vec<CorrectionRequest>, ComplianceError> {
    device.verdicts.iter().try_fold(Vec::new(), |mut requests, (control_id, verdict)| {
        let control = find_control(baseline, control_id)?;
        let enabled_action = control
            .correction
            .as_ref()
            .filter(|correction| correction.enabled)
            .map(|correction| &correction.action);
        if let (Verdict::Fail { .. }, Some(action)) = (verdict, enabled_action) {
            if find_exception(control, exceptions, &device.target, now).is_none() {
                requests.push(CorrectionRequest {
                    control: control.id.clone(),
                    device: device.target.device.clone(),
                    action: action.clone(),
                });
            }
        }
        Ok(requests)
    })
}


fn defer(plan: &mut Plan, requests: Vec<CorrectionRequest>, reason: DeferReason) {
    plan.deferred
        .extend(requests.into_iter().map(|request| DeferredCorrection { request, reason }));
}


/// Builds the correction plan: only `Fail` verdicts of enabled, non-excepted controls, within the policy caps; a dry run requests nothing.
pub fn plan_corrections(
    verdicts: &[DeviceVerdicts],
    baseline: &Baseline,
    exceptions: &[Exception],
    policy: &Policy,
    now: OffsetDateTime,
) -> Result<Plan, ComplianceError> {
    check_tenant(&policy.tenant, &baseline.tenant)?;
    verdicts.iter().try_for_each(|device| check_tenant(&policy.tenant, &device.tenant))?;
    check_unique(verdicts)?;
    let mut plan = Plan {
        tenant: policy.tenant.clone(),
        dry_run: policy.dry_run,
        requests: Vec::new(),
        would_run: Vec::new(),
        deferred: Vec::new(),
    };
    let mut admitted_devices = 0;
    for device in verdicts {
        let mut requests = eligible_requests(baseline, exceptions, device, now)?;
        if !requests.is_empty() {
            if admitted_devices < policy.max_devices {
                admitted_devices += 1;
                let overflow = requests.split_off(requests.len().min(policy.max_corrections_per_device));
                defer(&mut plan, overflow, DeferReason::DeviceCorrectionCapReached);
                if policy.dry_run {
                    plan.would_run.extend(requests);
                } else {
                    plan.requests.extend(requests);
                }
            } else {
                defer(&mut plan, requests, DeferReason::DeviceCapReached);
            }
        }
    }
    Ok(plan)
}
