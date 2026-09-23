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

## Step 10B extraction details from supplied source

The supplied `SolrIndexing.documentProcessing` dispatches `.pdf` to PDFBox
`PDFTextStripper`, Word/RTF formats to `classDocument.ExtractTextUsingAspose`,
and TXT/HTML/HTM to `My.Computer.FileSystem.ReadAllText`. `classDocument` uses
Aspose.Words 24.9.0 and removes the Aspose evaluation banners. `PDfProcessing`
uses PDFBox 1.8.2. `doIndexing` returns `EmptyDocument` when the extracted text,
after removing characters outside `[a-zA-Z0-9_.]`, has length zero.

Step 10B ports only the ReadAllText branch now. Word/PDF actions remain blocked
until those exact legacy extraction paths are validated in the .NET 9 tool.
