SELECT `event.id` FROM `events` WHERE `event.category` = 'process' AND (((isNotNull(`process.parent.executable`)) AND (isNull(`user.name`))) AND (isNull(`process.command_line`)))
