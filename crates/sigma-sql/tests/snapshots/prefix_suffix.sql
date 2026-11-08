SELECT `event.id` FROM `events` WHERE has(`event.category`, 'file') AND `host.os.type` = 'windows' AND ((`process.executable` ilike '%.exe' AND `file.path` ilike 'C:\\\\Users\\\\%'))
