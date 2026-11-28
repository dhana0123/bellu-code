# rpm fixture gap

Syft reads the rpm database (`var/lib/rpm/rpmdb.sqlite` or BerkeleyDB `Packages`),
a binary format that cannot be produced offline without the `rpm` tooling.
No rpm database is committed. Add one when the `rpm` tool is available in CI.
