SELECT `event.id` FROM `events` WHERE `host.os.type` = 'windows' AND `event.provider` = 'Microsoft-Windows-Security-Auditing' AND ((`event.code` ilike '4625' AND `user.name` ilike '%admin'))
