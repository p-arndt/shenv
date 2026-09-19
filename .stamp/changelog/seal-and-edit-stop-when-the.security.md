`seal` and `edit` stop when the current env.shenv can't be read (no permission, network error), instead of treating that as "nothing there yet" and overwriting it without the lockout check.
