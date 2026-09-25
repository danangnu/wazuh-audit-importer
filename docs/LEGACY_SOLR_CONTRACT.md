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
and TXT/HTML/HTM to `My.Computer.FileSystem.ReadAllText`. The legacy Word path
constructs `Aspose.Words.Document(filePath)`, calls `ToString(SaveFormat.Text)`,
removes the exact `Created with an evaluation copy ... temporary-license/`
notice with `String.Replace`, then removes
`Evaluation Only\. Created with Aspose\.Words.*Aspose Pty Ltd\.` using
`RegexOptions.Singleline`. That supplied regex is greedy and can erase document
text between repeated Aspose banners. Step 10B uses the same start/end markers
with non-greedy matching (`.*?`) so each banner is removed independently while
intervening document text is preserved. A repeated-banner regression test covers
this behavior. Aspose.Words is version 24.9.0. The legacy function returns
`Nothing` when extraction throws; Step 10B records an explicit blocked payload
for that case. `PDfProcessing` uses PDFBox 1.8.2. `doIndexing` returns
`EmptyDocument` when extracted text, after removing characters outside
`[a-zA-Z0-9_.]`, has length zero.

Step 10B now ports the ReadAllText and Aspose.Words 24.9.0 branches. The PDF
action remains blocked until the exact PDFBox 1.8.2 path is ported and validated.


## Step 12 same-path source changes

A worker-detected `CHANGE` cannot be inferred from the legacy Solr `last_update` field because
that field records indexing time rather than source-file modification time. Step 12 therefore
uses the immutable worker `changes.changed` list from the Step 8 plan. If the changed file is
still present and legacy-eligible, Step 10A produces an `index_document` action with
`reason=source_changed` even when the Solr path/id comparison is otherwise `MATCH`. The same
changed-file list is used again during Step 11 preflight drift regeneration.
