use crate::model::Language;
use crate::types::TextTable;


pub const TEXT_COUNT: usize = 129;


pub const MISSING_TEXT: &str = "???";


pub const ENGLISH: [(&str, &str); TEXT_COUNT] = [
    ("app_name", "Ostyr"),
    ("title_login", "Sign in"),
    ("title_alerts", "Alerts"),
    ("title_alert", "Alert"),
    ("title_error", "Error"),
    ("login_username", "User name"),
    ("login_password", "Password"),
    ("login_totp", "Second factor code (if enrolled)"),
    ("login_submit", "Sign in"),
    ("login_failed", "Sign-in failed. Check the credentials and the second factor."),
    ("nav_logout", "Sign out"),
    ("nav_alerts", "Alerts"),
    ("nav_language_en", "English"),
    ("nav_language_fr", "Français"),
    ("alerts_empty", "No alert."),
    ("alerts_next", "Older alerts"),
    ("col_severity", "Severity"),
    ("col_rule", "Rule"),
    ("col_host", "Host"),
    ("col_user", "User"),
    ("col_time", "Event time"),
    ("sev_low", "Low"),
    ("sev_medium", "Medium"),
    ("sev_high", "High"),
    ("sev_critical", "Critical"),
    ("alert_rule_id", "Rule identifier"),
    ("alert_created", "Raised at"),
    ("alert_events", "Events"),
    ("alert_summary", "Summary"),
    ("alert_summary_truncated", "The summary was cut by the server."),
    ("alert_back", "Back to the alerts"),
    ("none", "none"),
    ("omitted", "omitted"),
    ("cut", "cut"),
    ("nav_cases", "Cases"),
    ("title_cases", "Cases"),
    ("title_case", "Case"),
    ("cases_empty", "No case."),
    ("cases_next", "Older cases"),
    ("col_case_title", "Title"),
    ("col_status", "Status"),
    ("col_assignee", "Assignee"),
    ("col_updated", "Updated"),
    ("col_created", "Created"),
    ("col_type", "Type"),
    ("status_new", "New"),
    ("status_in_progress", "In progress"),
    ("status_closed", "Closed"),
    ("res_true_positive", "True positive"),
    ("res_false_positive", "False positive"),
    ("res_benign", "Benign"),
    ("res_duplicate", "Duplicate"),
    ("res_other", "Other"),
    ("task_todo", "To do"),
    ("task_done", "Done"),
    ("unknown", "unknown"),
    ("not_linkable", "not linkable"),
    ("case_description", "Description"),
    ("case_resolution", "Resolution"),
    ("case_template", "Template"),
    ("case_tasks", "Tasks"),
    ("case_counts", "Counts"),
    ("count_tasks", "Tasks"),
    ("count_observables", "Observables"),
    ("count_comments", "Comments"),
    ("count_history", "History"),
    ("count_alerts", "Alerts"),
    ("case_due", "due"),
    ("case_back", "Back to the cases"),
    ("error_generic", "The request could not be completed. Try again later."),
    ("error_forbidden", "You do not have the permission to see this page."),
    ("error_not_found", "This page does not exist."),
    ("error_csrf", "The form is no longer valid. Reload the page and try again."),
    ("error_throttled", "Too many requests. Try again in a moment."),
    ("error_bad_request", "The request is not valid."),
    ("error_unavailable", "The service is not available. Try again later."),
    ("error_full", "The service is busy. Try again later."),
    ("case_actions", "Actions"),
    ("action_start", "Start"),
    ("action_close", "Close"),
    ("action_reopen", "Reopen"),
    ("comment_label", "Add a comment"),
    ("comment_submit", "Add comment"),
    ("comment_added", "Comment added"),
    ("comment_unloaded", "Comment stored; the case could not be reloaded."),
    ("comment_signin", "Comment stored; sign in again to continue."),
    ("case_reload", "Reload the case"),
    (
        "error_transition_not_allowed",
        "This action is not allowed in the current status of the case.",
    ),
    ("error_resolution_required", "Choose a resolution to close the case."),
    ("error_case_changed", "The case changed meanwhile. Reload the page and try again."),
    ("error_comment_full", "The case holds the maximum number of comments."),
    ("nav_assets", "Assets"),
    ("title_assets", "Assets"),
    ("title_asset", "Asset"),
    ("assets_empty", "No asset."),
    ("assets_next", "Next assets"),
    ("col_asset_id", "Identifier"),
    ("col_kind", "Kind"),
    ("col_lifecycle", "Life cycle"),
    ("col_name", "Name"),
    ("col_value", "Value"),
    ("col_source", "Source"),
    ("count_keys", "Identity keys"),
    ("count_attributes", "Attributes"),
    ("count_conflicts", "Open conflicts"),
    ("asset_keys", "Identity keys"),
    ("asset_attributes", "Attributes"),
    ("asset_truncated", "Some attributes are not shown."),
    ("asset_unreadable", "Unreadable asset."),
    ("asset_back", "Back to the assets"),
    ("nav_risk", "Risk"),
    ("title_risk", "Entity risk"),
    ("title_risk_entity", "Risk of"),
    ("risk_empty", "No scored entity."),
    ("risk_unreadable", "Unreadable entity."),
    ("risk_busy", "Scores are being computed. Retry in a moment."),
    ("risk_back", "Back to the risk list"),
    ("risk_truncated", "Scores are partial. Bound reached: {limit}. Read: {read}. Cap: {cap}."),
    ("risk_limit_alerts", "alerts"),
    ("risk_limit_contributions", "contributions"),
    ("risk_limit_entities", "entities"),
    ("col_risk_entity", "Entity"),
    ("col_risk_value", "Score"),
    ("col_risk_used", "Contributions used"),
    ("col_risk_dropped", "Contributions dropped"),
    ("risk_kind_all", "All"),
    ("risk_kind_host", "Hosts"),
    ("risk_kind_user", "Users"),
    ("risk_computed", "Computed at"),
];


pub const FRENCH: [(&str, &str); TEXT_COUNT] = [
    ("app_name", "Ostyr"),
    ("title_login", "Connexion"),
    ("title_alerts", "Alertes"),
    ("title_alert", "Alerte"),
    ("title_error", "Erreur"),
    ("login_username", "Nom d'utilisateur"),
    ("login_password", "Mot de passe"),
    ("login_totp", "Code du second facteur (si activé)"),
    ("login_submit", "Se connecter"),
    ("login_failed", "Connexion refusée. Vérifiez les identifiants et le second facteur."),
    ("nav_logout", "Se déconnecter"),
    ("nav_alerts", "Alertes"),
    ("nav_language_en", "English"),
    ("nav_language_fr", "Français"),
    ("alerts_empty", "Aucune alerte."),
    ("alerts_next", "Alertes plus anciennes"),
    ("col_severity", "Gravité"),
    ("col_rule", "Règle"),
    ("col_host", "Hôte"),
    ("col_user", "Utilisateur"),
    ("col_time", "Heure de l'événement"),
    ("sev_low", "Faible"),
    ("sev_medium", "Moyenne"),
    ("sev_high", "Élevée"),
    ("sev_critical", "Critique"),
    ("alert_rule_id", "Identifiant de la règle"),
    ("alert_created", "Levée le"),
    ("alert_events", "Événements"),
    ("alert_summary", "Résumé"),
    ("alert_summary_truncated", "Le résumé a été coupé par le serveur."),
    ("alert_back", "Retour aux alertes"),
    ("none", "aucun"),
    ("omitted", "omis"),
    ("cut", "coupé"),
    ("nav_cases", "Dossiers"),
    ("title_cases", "Dossiers"),
    ("title_case", "Dossier"),
    ("cases_empty", "Aucun dossier."),
    ("cases_next", "Dossiers plus anciens"),
    ("col_case_title", "Titre"),
    ("col_status", "Statut"),
    ("col_assignee", "Responsable"),
    ("col_updated", "Mis à jour"),
    ("col_created", "Créé le"),
    ("col_type", "Type"),
    ("status_new", "Nouveau"),
    ("status_in_progress", "En cours"),
    ("status_closed", "Clos"),
    ("res_true_positive", "Vrai positif"),
    ("res_false_positive", "Faux positif"),
    ("res_benign", "Bénin"),
    ("res_duplicate", "Doublon"),
    ("res_other", "Autre"),
    ("task_todo", "À faire"),
    ("task_done", "Fait"),
    ("unknown", "inconnu"),
    ("not_linkable", "non cliquable"),
    ("case_description", "Description"),
    ("case_resolution", "Résolution"),
    ("case_template", "Modèle"),
    ("case_tasks", "Tâches"),
    ("case_counts", "Compteurs"),
    ("count_tasks", "Tâches"),
    ("count_observables", "Observables"),
    ("count_comments", "Commentaires"),
    ("count_history", "Historique"),
    ("count_alerts", "Alertes"),
    ("case_due", "échéance"),
    ("case_back", "Retour aux dossiers"),
    ("error_generic", "La requête n'a pas pu aboutir. Réessayez plus tard."),
    ("error_forbidden", "Vous n'avez pas le droit de voir cette page."),
    ("error_not_found", "Cette page n'existe pas."),
    ("error_csrf", "Le formulaire n'est plus valide. Rechargez la page et recommencez."),
    ("error_throttled", "Trop de requêtes. Réessayez dans un instant."),
    ("error_bad_request", "La requête n'est pas valide."),
    ("error_unavailable", "Le service n'est pas disponible. Réessayez plus tard."),
    ("error_full", "Le service est occupe. Réessayez plus tard."),
    ("case_actions", "Actions"),
    ("action_start", "Démarrer"),
    ("action_close", "Clore"),
    ("action_reopen", "Rouvrir"),
    ("comment_label", "Ajouter un commentaire"),
    ("comment_submit", "Ajouter le commentaire"),
    ("comment_added", "Commentaire ajouté"),
    ("comment_unloaded", "Commentaire enregistré ; le dossier n'a pas pu être rechargé."),
    ("comment_signin", "Commentaire enregistré ; reconnectez-vous pour continuer."),
    ("case_reload", "Recharger le dossier"),
    (
        "error_transition_not_allowed",
        "Cette action n'est pas permise dans le statut actuel du dossier.",
    ),
    ("error_resolution_required", "Choisissez une résolution pour clore le dossier."),
    ("error_case_changed", "Le dossier a changé entre-temps. Rechargez la page et recommencez."),
    ("error_comment_full", "Le dossier contient déjà le nombre maximal de commentaires."),
    ("nav_assets", "Actifs"),
    ("title_assets", "Actifs"),
    ("title_asset", "Actif"),
    ("assets_empty", "Aucun actif."),
    ("assets_next", "Actifs suivants"),
    ("col_asset_id", "Identifiant"),
    ("col_kind", "Type"),
    ("col_lifecycle", "Cycle de vie"),
    ("col_name", "Nom"),
    ("col_value", "Valeur"),
    ("col_source", "Source"),
    ("count_keys", "Clés d'identité"),
    ("count_attributes", "Attributs"),
    ("count_conflicts", "Conflits ouverts"),
    ("asset_keys", "Clés d'identité"),
    ("asset_attributes", "Attributs"),
    ("asset_truncated", "Certains attributs ne sont pas affichés."),
    ("asset_unreadable", "Actif illisible."),
    ("asset_back", "Retour aux actifs"),
    ("nav_risk", "Risque"),
    ("title_risk", "Risque des entités"),
    ("title_risk_entity", "Risque de"),
    ("risk_empty", "Aucune entité notée."),
    ("risk_unreadable", "Entité illisible."),
    ("risk_busy", "Les scores sont en cours de calcul. Réessayez dans un instant."),
    ("risk_back", "Retour à la liste des risques"),
    (
        "risk_truncated",
        "Scores partiels. Borne atteinte : {limit}. Lus : {read}. Plafond : {cap}.",
    ),
    ("risk_limit_alerts", "alertes"),
    ("risk_limit_contributions", "contributions"),
    ("risk_limit_entities", "entités"),
    ("col_risk_entity", "Entité"),
    ("col_risk_value", "Score"),
    ("col_risk_used", "Contributions utilisées"),
    ("col_risk_dropped", "Contributions écartées"),
    ("risk_kind_all", "Toutes"),
    ("risk_kind_host", "Machines"),
    ("risk_kind_user", "Utilisateurs"),
    ("risk_computed", "Calculé le"),
];


pub fn table(language: Language) -> &'static TextTable {
    match language {
        Language::English => &ENGLISH,
        Language::French => &FRENCH,
    }
}


/// The text of `key`, or `MISSING_TEXT`; a test renders every page in both languages and refuses the marker.
pub fn text(language: Language, key: &str) -> &'static str {
    table(language)
        .iter()
        .find(|(name, _)| *name == key)
        .map_or(MISSING_TEXT, |(_, value)| value)
}


pub fn language_tag(language: Language) -> &'static str {
    match language {
        Language::English => "en",
        Language::French => "fr",
    }
}


pub fn severity_key(severity: crate::model::Severity) -> &'static str {
    match severity {
        crate::model::Severity::Low => "sev_low",
        crate::model::Severity::Medium => "sev_medium",
        crate::model::Severity::High => "sev_high",
        crate::model::Severity::Critical => "sev_critical",
    }
}


pub fn severity_class(severity: crate::model::Severity) -> &'static str {
    match severity {
        crate::model::Severity::Low => "sev-low",
        crate::model::Severity::Medium => "sev-medium",
        crate::model::Severity::High => "sev-high",
        crate::model::Severity::Critical => "sev-critical",
    }
}


pub fn status_key(value: &str) -> &'static str {
    match value {
        "new" => "status_new",
        "in_progress" => "status_in_progress",
        "closed" => "status_closed",
        _ => "unknown",
    }
}


pub fn task_status_key(value: &str) -> &'static str {
    match value {
        "todo" => "task_todo",
        "in_progress" => "status_in_progress",
        "done" => "task_done",
        _ => "unknown",
    }
}


pub fn resolution_key(value: &str) -> &'static str {
    match value {
        "true_positive" => "res_true_positive",
        "false_positive" => "res_false_positive",
        "benign" => "res_benign",
        "duplicate" => "res_duplicate",
        "other" => "res_other",
        _ => "unknown",
    }
}


pub const RESOLUTIONS: [&str; 5] = ["true_positive", "false_positive", "benign", "duplicate", "other"];


pub const CLOSE_ACTION: &str = "close";


pub const ACTIONS: [&str; 3] = ["start", CLOSE_ACTION, "reopen"];


pub fn action_key(value: &str) -> &'static str {
    match value {
        "start" => "action_start",
        CLOSE_ACTION => "action_close",
        "reopen" => "action_reopen",
        _ => "unknown",
    }
}


/// The actions the cases module accepts from a status; an unknown status offers none.
pub fn allowed_actions(status: &str) -> &'static [&'static str] {
    match status {
        "new" => &["start", CLOSE_ACTION],
        "in_progress" => &[CLOSE_ACTION],
        "closed" => &["reopen"],
        _ => &[],
    }
}


/// The action and resolution of the fixed tables for a submitted pair; `close` takes a resolution, the others none.
pub fn checked_action(action: &str, resolution: Option<&str>) -> Option<(&'static str, Option<&'static str>)> {
    let fixed_action = *ACTIONS.iter().find(|candidate| **candidate == action)?;
    let fixed_resolution = match resolution {
        Some(value) => Some(*RESOLUTIONS.iter().find(|candidate| **candidate == value)?),
        None => None,
    };
    Some((fixed_action, fixed_resolution)).filter(|(name, chosen)| (*name == CLOSE_ACTION) == chosen.is_some())
}


pub fn case_severity_key(value: &str) -> &'static str {
    match value {
        "low" => "sev_low",
        "medium" => "sev_medium",
        "high" => "sev_high",
        "critical" => "sev_critical",
        _ => "unknown",
    }
}


pub fn case_severity_class(value: &str) -> &'static str {
    match value {
        "low" => "sev-low",
        "medium" => "sev-medium",
        "high" => "sev-high",
        "critical" => "sev-critical",
        _ => "sev-unknown",
    }
}
