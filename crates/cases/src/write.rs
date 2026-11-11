use crate::error::CaseStoreError;
use crate::store::apply_case_action;
use crate::stored::CaseDetail;
use crate::summary::get_case_detail;
use crate::transition::CaseAction;
use alerts::types::Executor;
use core_pg::scope::TenantScope;


/// Applies the action, then reads the case back in the same scope; a version moved in between is `Conflict`, never a lost update.
pub async fn act_on_case(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    id: &str,
    action: CaseAction,
    actor: &str,
    now: i64,
) -> Result<CaseDetail, CaseStoreError> {
    apply_case_action(exec, scope, id, action, actor, now).await?;
    get_case_detail(exec, scope, id).await?.ok_or(CaseStoreError::NotFound)
}
