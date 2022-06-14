# Check It All (CIA)

**Check all files in given folder using Trend Micro Deep Discovery Analyzer**

## Key Features

### &#x261E; Integration with Trend Micro Deep Discovery Analyzer

CIA provides ability to thoroughly check each file using cutting edge [Trend Micro sandbox technology](https://www.trendmicro.com/en_us/business/products/network/advanced-threat-protection/analyzer.html)

### &#x261E; CI/CD Pipline Integration

CIA designed to be used in piplines for automated checks safety of any files amount 

### &#x261E; Fast Folder Checks

CIA provides two features to speedup checks by avoiding unnessesary files checks:

#### &bull; Flexible Prefiltering

True file type and file path flexible rule based system to avoid unnecessary submittions of files for analysis

#### &bull; Caching

All checks results are chached to enomerously speed up subsequent checks provided only small portion of files are changed between the runs.

### &#x261E; Configurable theshhold for file safety confidence

Each analysis outcome can be configured separatly as acceptable or not


## Installation

### Get CIA binary
Download binary from [releases](https://github.com/mpkondrashin/cia/releases) or download sources and build it yourself:

```commandline
git clone https://github.com/mpkondrashin/cia.git
cd cia
go build
```
**Note** you need to have permission to have access to private repository https://github.com/mpkondrashin/ddan.

### Configuration

Copy examples of configuration files
```commandline
cp filters_example.yaml filters.yaml
cp cia_example.yaml cia.yaml
```
And edit cia.yaml amd filters.yaml files to suite your needs

### Run
```commandline
./cia
```

### Return code
If CIA finds any malicious file according to its configuration or faces some error during files scan, it returns non zero return code and zero otherwise.

### Logging

CIA writes its log to stderr and it can be redirected to any file required.

## Configuration Files

### cia.yaml

Main CIA configuration file

```yaml
analyzer:
  url: http://10.0.0.1:443                        # IP or DNS name and port of the analyer

  apiKey: 00000000-0000-0000-0000-000000000000    # Check Help->About Analyser 
                                                  # web GUI for correct value
  
  maxFileSize: 60000000                           # Maxinum file size. It can
                                                  # not be bigger then configured
                                                  # in Analyzer iteslf
  
  prescanJobs: 3                                  # How meny prescan jobs to run.
                                                  # For maximum perforamnce should
                                                  # be not less than CPU cores

  submitJobs: 3                                   # How many parallel checks to run.
                                                  # Should reflect nubmer os sandboxes
                                                  # in Analyzer

  pullInterval: 60s                               # How often to check analyzer for
                                                  # results. Lower values will result
                                                  # more request per minute to analyzer.
  
  ignoreTLSError: True                            # (default - false). Set True if
                                                  # you have incorrect certificate set
                                                  # on your Analyzer

  productName: cia                                # What product name to display in Analyzer
                                                  # Web GUI Virtual Analyzer->Submitters.
                                                  # Do not change! 
                                                  
  sourceID: 500                                   # number of the product. Do not change!

  sourceName: pipeline                            # name of actual files source. Displaed
                                                  # in Submitters table in Analyzer GUI

  clientUUID: c7213f09-b399-4c71-9d1c-3a99905215e0 # random UUID to identify each particular
                                                  # setup. Set any unique value for each
                                                  # CIA used with your Analyzer

cache:                                            # configuration of cache database 

  type: postgres                                  # The only option supported

  host: 10.0.0.100                                # IP or DNS name of PostreSQL server

  port: 5432                                      # (default - 5432) Port of PostreSQL server

  username: postgres                              # (default - postgres)

  password: <password>                            # database password

  dbname: cia001                                  # database name. Keep the same for
                                                  # all cia caches to get united cache

allow:
  highRisk: false
  mediumRisk: false
  lowRisk: false 
  error: false                                    # Allow files that resulted error
                                                  # during analysis

  unscannable: true                               # Allow files that are not supported by
                                                  # Analyzer. To improve performance
                                                  # filter rules can be used (see below)

  timeout: true                                   # Allow files that resulted timeout
                                                  # during analysis

  bigFile: true                                   # Allow files bigger then maxFileSize

filter: filter.yaml                               # path to the prefiltering rules file

folder: <folder>                                  # name of the folder to check

skip:                                             # list of scanned paths prefixes to skip
  - /proc
```

**Note** If whole **cache** secion is omited no cache will be used. In this case for subsequent CIA runs will check
 only analyzer cache. This will dramanically reduce perforamnce.

### filters.yaml

Configuration of prefiltering rules

```yaml
rules:
  - submit: true                                  # Submit matching file (true) or not (false)
    type: path                                    # type of rule. "path" for file path rules 
    value: 'eicar.com'                            # mask for file name
  - submit: true
    type: mime                                    # type of rule. "mime" for true file type rules 
    value: 'application/*zip'                     # mask for MIME type
  - submit: true
    type: mime
    value: 'application/x*exe*'
  - submit: true
    type: mime
    value: '*shellscript'	
```

Rules are applied in order of appearance in this file. First rules that matches file is applied
(decision is made to submit file for analysis or not). If non of the rules matches, default action
is **no to submit file**.

