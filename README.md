# onomondo-traffic-fetcher

Fetch your organization's traffic based on ip, iccid, or simid.

This is a tool for organizations that are using Onomondo Fleet Storage.

## Installation

You need to have `node.js` and `wireshark` installed on your system.

Install this way: `$ npm i -g onomondo-traffic-fetcher`

## How to use

`onomondo-traffic-fetcher` uses several parameters. All of these can either be passed through command-line arguments, or you can put them in a file called `conf.json`, which is read from the folder you run the program from.

Is is recommended to put access keys, and token into a `conf.json` and pass the other parameters to the program, but it can all be combined however you choose.

## Examples

These examples downloads traffic from either AWS S3 or Azure Blob Storage

### AWS S3

Download traffic between 5 and 7:30 on Dec 20th, from s3, filtering out traffic from a specific iccid.

This is run from the command line:

```
$ onomondo-traffic-fetcher \
  --from=2020-12-20T05:00:00Z \
  --to=2020-12-20T07:30:00Z \
  --iccid=8991101200003204514
```

With `conf.json` containing:

``` json
{
  "token": "abc123def456ghi",
  "s3-bucket": "mycompany-bucket",
  "s3-region": "eu-central-1",
  "aws-access-key-id": "AKAI1234ABCDEFGF",
  "aws-secret-access-key": "ghjKJH1234KJHkjhbnmY"
}
```

### Azure Blob Storage

Download traffic between 5 and 7:30 on Dec 20th, from s3, filtering out traffic from several sim id's, and one ip:

This is run from the command line:

```
$ onomondo-traffic-fetcher \
  --from=2020-12-20T05:00:00Z \
  --to=2020-12-20T07:30:00Z \
  --conf=conf-sim-group.json
```

With `conf-sim-group.json` containing:

``` json
{
  "token": "abc123def456ghi",
  "blob-storage-connection-string": "DefaultEndpointsProtocol=https;AccountName=foobarbaz;AccountKey=a1b2c3;EndpointSuffix=core.windows.net",
  "blob-storage-container-name": "my-container-name",
  "simid": [
    "000123456",
    "001234567",
    "012345678"
  ]
}
```

## Parameters

### --from=2020-12-20T05:00:00Z (**required**)

Fetch traffic from this time

### --to=2020-12-21T05:15:00Z (**required**)

Fetch traffic until this time

### --ip=100.64.12.34 (optional)

Filter traffic based on this IP.

*You can specify multiple ip''s like `--ip=... --ip=...`*

### --iccid=8991101200003204514 (optional)

Filter traffic based on this iccid. **Requires you to specify --token**

*You can specify multiple iccid''s like `--iccid=... --iccid=...`*

### --simid=000000001 (optional)

Filter traffic based on this simid. **Requires you to specify --token**

*You can specify multiple simid''s like `--simid=... --simid=...`*

### --token=abc123def456ghi789 (optional)

This is the token for Onomondo api. You only need to specify this if you use `--iccid` or `--simid`. This is because `onomondo-traffic-fetcher` needs to convert the iccid/simid into an ip address.

### --conf

Specify which conf file should be used. This is only available as a command line parameter.

## Storage Providers

### AWS S3

If you are using AWS S3 then these paramters are required.

#### --s3-bucket=mycompany-bucket
#### --s3-region=eu-central-1
#### --aws-access-key-id=AKAI1234ABCDEFGF
#### --aws-secret-access-key=ghjKJH1234KJHkjhbnmY

### Azure Blob Storage

If you are uzing Azure Blob Storage then these parameters are required.

#### --blob-storage-connection-string
#### --blob-storage-container-name
