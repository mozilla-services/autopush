Overview
---
These files are appended to the hindsight configurations that produce parquet
files in s3.

Structure
---
These files are organized by log stream. Log streams are named
`${app}.${type}.${source}`, where `app` is always `autopush`, `type` is
`autopush` or `autoendpoint`, and `source` is `docker.autopush` or
`docker.autoendpoint`, but may change based on logging configuration.

For each log stream there can be a `${log_stream}.cfg` file, or a directory
`${log_stream}/` which contains .cfg files. All cfg files must contain a
`parquet_schema`, and are interpreted as lua. If no cfg file is specified for a
stream, then a fallback schema is used. Files without a `.cfg` extension are
ignore.d

Providing a file for a stream indicates that there is only one schema for the
stream, and generally only requires specifying `parquet_schema`. This field
accesses the message after PII is scrubbed. A string to string map of mozlog
`Fields` is provided, and all values are also copied outside the map for use as
schema columns, with field names modified by converting to lowercase, replacing
`.`s with `_`, and adding a prefix of `fields_`.

Providing a directory for a stream indicates that the stream is going to be
split into multiple parquet schemas, so `message_matcher` and
`s3_path_dimensions` should be specified. These fields access the message
before PII is scrubbed, so metadata is referenced as `Hostname`, mozlog
metadata is referenced as `Fields[Hostname]`, and mozlog fields are accessed
like `Fields[Fields.agent]`.

The default value of `message_matcher` will match the log stream for the file,
so extending the matcher is preferrable using the lua `..` operator for string
concatenation. In order to keep logs that don't match specific schemas, a
fallback cfg should be provided that negates all the other message matchers in
the directory, and uses the default mozlog parquet schema.

Date and Hour are special fields that are extracted from the mozlog `Timestamp`
value, for use in `s3_path_dimesions`. `s3_path_dimensions` is a list of
partition names mapped to a hindsight `read_message()` source. It is standard
to add a partition between `log` and `date` called `type` that matches the name
of the cfg file. The default value partitions logs by log stream (heka message
`Type`), `Date`, and `Hour` with:

    s3_path_dimensions = {
        {name="log", source="Type"},
        {name="date", source="Fields[Date]"},
        {name="hour", source="Fields[Hour]"},
    }
