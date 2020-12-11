# onomondo-traffic-fetcher

Fetch your organization's traffic based on ip, iccid, or simid.

This is a tool for organizations that are using Onomondo Fleet Storage.

## Installation

You need to have `node.js` and `wireshark` installed on your system.

Install this way: `$ npm i -g onomondo-traffic-fetcher`

## Examples

Download traffic between 5 and 7:30 on Dec 20th, from s3, filtering out traffic from a specific iccid:

```
$ onomondo-traffic-fetcher \
--from=2020-12-20T05:00:00Z \
--to=2020-12-20T07:30:00Z \
--iccid=8991101200003204514 \
--token=abc123def456ghi \
--s3-bucket=mycompany-bucket \
--s3-region=eu-central-1 \
--aws-access-key-id=AKAI1234ABCDEFGF \
--aws-secret-access-key=ghjKJH1234KJHkjhbnmY
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

Filter traffic based on this iccid.

**Requires you to specify --token**

*You can specify multiple iccid''s like `--iccid=... --iccid=...`*

### --simid=000000001 (optional)

Filter traffic based on this simid.

**Requires you to specify --token**

*You can specify multiple simid''s like `--simid=... --simid=...`*

### --token=abc123def456ghi789 (optional)

You only need to specify this if you use `--iccid` or `--simid`. This is because `onomondo-traffic-fetcher` need to convert the iccid/simid into an ip address.

## AWS S3

If you are using AWS S3 then these paramters are required.

### --s3-bucket=mycompany-bucket
### --s3-region=eu-central-1
### --aws-access-key-id=AKAI1234ABCDEFGF
### --aws-secret-access-key=ghjKJH1234KJHkjhbnmY

### Azure Blob Storage

If you are uzing Azure Blob Storage then these parameters are required.

### --blob-storage-connection-string
### --blob-storage-container-name
