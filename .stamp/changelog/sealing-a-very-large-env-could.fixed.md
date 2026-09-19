Sealing a very large .env could succeed and produce a file that shenv itself refused to open. Anything over the 16 MiB limit is now rejected before the existing env.shenv is touched.
