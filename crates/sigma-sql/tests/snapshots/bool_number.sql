SELECT `event.id` FROM `events` WHERE has(`event.category`, 'network') AND ((`destination.port` ilike '%44%' AND `network.direction` = true))
