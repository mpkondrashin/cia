# Check It All

Check all files in given folder using Trend Micro Deep Discovery Analyzer

**Note** this project requires access to private repository https://github.com/mpkondrashin/ddan

## Key Features

### &#x261E; Integration with Trend Micro Deep Discovery Analyzer

CIA provides ability to thoroughly check each file using cutting edge Trend Micro sandbox technology

### &#x261E; Fast Folder Checks

CIA has two features to speedup checks by avoiding unnessesary files checks

#### &bull; Flexible Prefiltering

True file type and file path flexible rule based system to avoid submitting unnessesory files to analysis

#### &bull; Caching

Previous checks are chached to enomerously speed up sucential checks if only small portion of files are changed between the runs.

### &#x261E; Configurable theshhold for file safety confidence

Each analysis result can be configarables separatly as acceptable or not

## Configuration File

```yaml
analyzer:
  url: 10.0.0.1:443 # IP:Port of the analyer
  apiKey: 00000000-0000-0000-0000-000000000000 # Check Help->About Analyser web GUI for correct value
  maxFileSize: 60000000 # Maxinum file size. It can not be bigger then configured in Analyzer iteslf
  jobs: 1 # How many parallel checks to run. Showl reflect nubmer os sandboxes in Analyzer
  pullInterval: 60s # How often to check analyzer for results. Lower values will result more request per minute to analyzer.
  ignoreTLSError: True # (default - false). Set True if you have incorrect certificate set on your Analyzer
  productName: cia # What product name to display in Analyzer Web GUI Submission->Submitters. Do not change! 
  sourceID: 500 # number of the product. Do not change!
  sourceName: pipeline # name of actual files source. Displaed in Submitters table also
  clientUUID: c7213f09-b399-4c71-9d1c-3a99905215e0 # random UUID to identify each particular setup. Set any unique value for each CIA used with your Analyzer
cache:
  type: postgres # The only option supported
  host: 135.181.111.163 # Address of PostreSQL server
  port: 5432 # Port of PostreSQL server
  username: postgres 
  password: <password>
  dbname: cia001 # keep it the same 
allow:
  highRisk: false
  mediumRisk: false
  lowRisk: false 
  error: false
  unscannable: true 
  timeout: true
  bigFile: true
filter: filter.yaml
folder: testing/t001
```

