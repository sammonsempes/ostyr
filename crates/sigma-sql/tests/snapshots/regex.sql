SELECT `event.id` FROM `events` WHERE has(`event.category`, 'process') AND `host.os.type` = 'windows' AND (match(`process.command_line`, '\\d{3}-\\d{4}\\s+it\'s'))
