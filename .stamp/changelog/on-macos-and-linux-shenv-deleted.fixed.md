On macOS and Linux, shenv deleted any file named `shenv.old` next to its binary on every start. That cleanup now only runs on Windows, where the updater creates that file.
