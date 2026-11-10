use crate::model::Language;
use crate::types::TextTable;


pub const TEXT_COUNT: usize = 42;


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
