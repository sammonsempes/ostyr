use crate::model::Language;
use crate::types::TextTable;


pub const TEXT_COUNT: usize = 77;


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
    ("error_forbidden", "You do not have the permission to see alerts."),
    ("error_not_found", "This page does not exist."),
    ("error_csrf", "The form is no longer valid. Reload the page and try again."),
    ("error_throttled", "Too many requests. Try again in a moment."),
    ("error_bad_request", "The request is not valid."),
    ("error_unavailable", "The service is not available. Try again later."),
    ("error_full", "The service is busy. Try again later."),
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
    ("error_forbidden", "Vous n'avez pas le droit de voir les alertes."),
    ("error_not_found", "Cette page n'existe pas."),
    ("error_csrf", "Le formulaire n'est plus valide. Rechargez la page et recommencez."),
    ("error_throttled", "Trop de requêtes. Réessayez dans un instant."),
    ("error_bad_request", "La requête n'est pas valide."),
    ("error_unavailable", "Le service n'est pas disponible. Réessayez plus tard."),
    ("error_full", "Le service est occupe. Réessayez plus tard."),
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
