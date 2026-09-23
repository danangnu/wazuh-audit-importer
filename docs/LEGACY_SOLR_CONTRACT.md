# Legacy Solr contract used by Step 9

This note captures only the fields and transformations required for the read-only
comparison. It intentionally excludes credentials and unrelated configuration.

From the supplied legacy indexing application:

- The Solr document type declares `id` as the unique key.
- Indexed fields used here are `id`, `content`, `last_update`, `path`, `dbcandno`.
- Candidate lookup is by `dbcandno`.
- The active `genSolrId` implementation is based on `Path.GetFileName(filePath)`,
  strips characters outside `\w`/whitespace, converts spaces/underscores to `-`,
  and lowercases the result.
- Before indexing, legacy server paths replace the server share with `G:` and
  remove the `FastTrack` path component, producing paths such as
  `G:\Candidate\To 1189999\1180097\file.ext`.
- `last_update` is set to the current indexing time. It is therefore not a safe
  proxy for source-file modification time.
- The active document filter excludes hidden files and filename tokens `dni` and
  `ocrerror`. The current active call path does not enforce the old extension
  list in `ExtensionFilter`.

From the supplied Paths.ini:

- Solr endpoint: `http://192.168.18.22:8983/solr/AlliedSolrCore`
- The historical document root points to PERSVR02, but Step 9 deliberately does
  not use it. The pilot filesystem source of truth is FLOSVR01 via the explicit
  `--worker-root` UNC path.

Step 9 does not copy or package Paths.ini because it also contains unrelated
sensitive settings.
