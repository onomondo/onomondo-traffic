#!/usr/bin/env node

process.env.TZ = 'UTC' // Only work in UTC (I quit if I have to work more with date/time...)

const AWS = require('aws-sdk')
const fs = require('fs')
const { parse, format, addDays, startOfDay, isValid } = require('date-fns')
const filesize = require('filesize')
const log = require('single-line-log').stdout
const path = require('path')
const { spawn } = require('child_process')
const minimist = require('minimist')
const axios = require('axios')
const pkgJson = require('./package.json')
const getPackageJson = require('package-json')
const { BlobServiceClient } = require('@azure/storage-blob')

const ALLOWED_PARAMS = [
  'from', 'to', 'iccid', 'simid', 'ip',
  's3-bucket', 's3-region', 'aws-access-key-id', 'aws-secret-access-key',
  'blob-storage-sas-uri', 'blob-storage-connection-string', 'blob-storage-container-name',
  'conf', 'token', 'api-url', 'api-headers'
]

const argv = minimist(process.argv.slice(2), { string: ['simid', 'iccid'] })
const confFilename = argv.conf || 'conf.json'
const conf = fs.existsSync(confFilename) ? JSON.parse(fs.readFileSync(confFilename)) : {}
const allParams = Object.keys({ ...argv, ...conf })
const from = new Date(getParam('from'))
const to = new Date(getParam('to'))
const iccIds = typeof getParam('iccid') === 'string' ? [getParam('iccid')] : (getParam('iccid') || [])
const simIds = typeof getParam('simid') === 'string' ? [getParam('simid')] : (getParam('simid') || [])
const ips = typeof getParam('ip') === 'string' ? [getParam('ip')] : (getParam('ip') || [])
const token = getParam('token')
const apiUrl = getParam('api-url') || 'https://api.onomondo.com'
const apiHeaders = getParam('api-headers') || {}
const s3Bucket = getParam('s3-bucket')
const s3Region = getParam('s3-region')
const awsAccessKeyId = getParam('aws-access-key-id')
const awsSecretAccessKey = getParam('aws-secret-access-key')
const blobStorageSasUri = getParam('blob-storage-sas-uri')
const blobStorageConnectionString = getParam('blob-storage-connection-string')
const blobStorageContainerName = getParam('blob-storage-container-name')
const hasTokenIfNeeded = (iccIds.length || simIds.length) ? !!token : true
const areDatesValid = isValid(from) && isValid(to)
const isUsingBlobStorage = blobStorageSasUri || blobStorageConnectionString || blobStorageContainerName
const hasAllBlobStorageParams = (blobStorageSasUri || blobStorageConnectionString) && blobStorageContainerName
const isUsingS3 = s3Bucket || s3Region || awsAccessKeyId || awsSecretAccessKey
const hasAllS3Params = s3Bucket && s3Region && awsAccessKeyId && awsSecretAccessKey
const hasAllRequiredParams = from && to && (isUsingBlobStorage || isUsingS3)
const isRangeValid = from < to
const tmpFolder = fs.mkdtempSync('tmp-')

function getParam (param) {
  const isArray = Array.isArray(argv[param]) || Array.isArray(conf[param])
  if (!isArray) return conf[param] || argv[param]

  const res = []
    .concat(argv[param])
    .concat(conf[param])
    .filter(val => !!val) // remove undefined

  return [...new Set(res)] // remove duplicates
}

console.error(`Onomondo Traffic ${pkgJson.version} (node.js ${process.version})`)
console.error('')

allParams.forEach(key => {
  if (ALLOWED_PARAMS.includes(key)) return
  if (key[0] === '_') return // keys that start with _ are not checked
  exit([
    `You included a parameter that is not allowed: ${key}`,
    `Allowed parameters are: ${ALLOWED_PARAMS.join(', ')}`
  ].join('\n'))
})

if (!hasAllRequiredParams) exit('Some parameters are missing.')
if (!areDatesValid) exit('The dates are not valid. Needs to be in a format like --from=2020-12-20T18:00:00Z')
if (!isRangeValid) exit('"from" is after "to". Please correct this.')
if (!hasTokenIfNeeded) exit('If you specify either --simid or --iccid, then you also need to specify --token')
if (isUsingS3 && !hasAllS3Params) exit('If you use AWS S3, you need to specify all these parameters: --s3-bucket, --s3-region, --aws-access-key-id, --aws-secret-access-key')
if (isUsingBlobStorage && !hasAllBlobStorageParams) exit('If you use Azure Blob Storage, you need to specify one of these parameters: --blob-storage-sas-uri, --blob-storage-connection-string. And then this --blob-storage-container-name')
if (!isUsingBlobStorage && !isUsingS3) exit('You need to either specify an AWS S3 or Azure Blob Storage configuration')

AWS.config.update({
  region: s3Region,
  accessKeyId: awsAccessKeyId,
  secretAccessKey: awsSecretAccessKey
})
const s3 = new AWS.S3({ apiVersion: '2006-03-01' })

run()

function generateFilename () {
  const name = `Onomondo traffic from ${format(from, 'yyyy-MM-dd HH\'h\'mm\'m\'')} to ${format(to, 'yyyy-MM-dd HH\'h\'mm\'m\'')}`
  const allIds = [].concat(iccIds).concat(simIds).concat(ips)
  if (!allIds.length || allIds.length > 5) return `${name}.pcap`

  const hasOneId = allIds.length === 1
  if (hasOneId) return `${name} for ${allIds.pop()}.pcap`

  const lastId = allIds.pop()
  const allIdsButTheLast = allIds
  return `${name} for ${allIdsButTheLast.join(', ')} and ${lastId}.pcap`
}

async function run () {
  const finalFilename = generateFilename()

  // Check if mergecap exists on local machine
  const hasMergecap = await mergeCapExists()
  if (!hasMergecap) {
    exit([
      '"mergecap" is required to run Onomondo Traffic.',
      'Maybe Wireshark is not installed or "mergecap" is not in PATH?'
    ].join('\n'))
  }

  // Check local version vs public version
  const publicVersion = await getPublicVersion()
  const isUsingCorrectVersion = pkgJson.version === publicVersion
  if (!isUsingCorrectVersion) console.error(`You are currently using version ${pkgJson.version} and the latest version is ${publicVersion}\n`)

  // Convert ICCID/SimID into ip addresses
  if (simIds.length > 0) {
    await convertSimIdsIntoIps()
    console.log(`Done getting ip addresses from ${simIds.length} simid's`)
  }
  if (iccIds.length > 0) {
    await convertIccIdsIntoIps()
    console.log(`Done getting ip addresses from ${iccIds.length} iccid's`)
  }

  let pcapFilesLocally

  // Download pcap files from S3
  if (isUsingS3) {
    // Get list of pcap files
    const pcapFilesOnS3 = await getListOfAllPcapFilesOnS3()
    console.log(`Done getting list of pcap files from AWS S3 (${pcapFilesOnS3.length} objects)`)

    // Download all pcap files
    pcapFilesLocally = await downloadAllPcapFilesOnS3(pcapFilesOnS3)
    console.log(`Done downloading pcap files from AWS S3 (${pcapFilesLocally.length} files)`)
  }

  // Download pcap files from Blob Storage
  if (isUsingBlobStorage) {
    const pcapFilesOnBlobStorage = await getListOfAllPcapFilesOnBlobStorage()
    console.log(`Done getting list of pcap files from Azure Blob Storage (${pcapFilesOnBlobStorage.length} objects)`)

    // Download all pcap files
    pcapFilesLocally = await downloadAllPcapFilesOnBlobStorage(pcapFilesOnBlobStorage)
    console.log(`Done downloading pcap files from Azure Blob Storage (${pcapFilesLocally.length} files)`)
  }

  // Filter relevant packets
  const shouldFilter = ips.length > 0
  const filteredPcapFilesLocally = shouldFilter
    ? await filterPcapFiles(pcapFilesLocally, ips)
    : pcapFilesLocally

  // Merge files
  const mergeFilename = await mergePcapFiles(filteredPcapFilesLocally)
  console.log(`Done merging pcap files (${filteredPcapFilesLocally.length} files)`)

  // Rename file
  fs.renameSync(mergeFilename, finalFilename)

  // Clean up
  fs.rmdirSync(tmpFolder, { recursive: true })

  // Mention where file is
  console.log(`\nComplete. File is stored at "${finalFilename}"`)
}

async function downloadAllPcapFilesOnBlobStorage (pcapFilesOnBlobStorage) {
  const totalFiles = pcapFilesOnBlobStorage.length
  const totalSize = pcapFilesOnBlobStorage.reduce((totalSize, { properties: { contentLength } }) => totalSize + contentLength, 0)
  let downloadedSize = 0
  const pcapFilenames = []

  for (const [index, file] of Object.entries(pcapFilesOnBlobStorage)) {
    downloadedSize += file.properties.contentLength
    log(`Downloading pcap files from Azure Blob Storage. [${Number(index) + 1}/${totalFiles} (${filesize(downloadedSize)}/${filesize(totalSize)})] (${file.name})`)
    const filename = await downloadPcapFileOnBlobStorage(file.name)
    pcapFilenames.push(filename)
  }
  log('')

  return pcapFilenames
}

async function downloadPcapFileOnBlobStorage (blobStorageFilename) {
  const pcapFilename = path.join(tmpFolder, blobStorageFilename.replace(/\//g, '-'))
  const blobServiceClient = blobStorageConnectionString
    ? BlobServiceClient.fromConnectionString(blobStorageConnectionString)
    : new BlobServiceClient(blobStorageSasUri)
  const containerClient = blobServiceClient.getContainerClient(blobStorageContainerName)
  const blobClient = containerClient.getBlobClient(blobStorageFilename)
  await blobClient.downloadToFile(pcapFilename)
  return pcapFilename
}

async function downloadAllPcapFilesOnS3 (pcapFilesOnS3) {
  const totalFiles = pcapFilesOnS3.length
  const totalSize = pcapFilesOnS3.reduce((totalSize, { Size }) => totalSize + Size, 0)
  let downloadedSize = 0
  const pcapFilenames = []

  for (const [index, file] of Object.entries(pcapFilesOnS3)) {
    downloadedSize += file.Size
    log(`Downloading pcap files from AWS S3. [${Number(index) + 1}/${totalFiles} (${filesize(downloadedSize)}/${filesize(totalSize)})] (${file.Key})`)
    const filename = await downloadPcapFileOnS3(file.Key)
    pcapFilenames.push(filename)
  }
  log('')

  return pcapFilenames
}

async function downloadPcapFileOnS3 (s3Key) {
  return new Promise((resolve, reject) => {
    const pcapFilename = path.join(tmpFolder, s3Key.replace(/\//g, '-'))
    const stream = fs.createWriteStream(pcapFilename)
    s3.getObject({
      Bucket: s3Bucket,
      Key: s3Key
    }).createReadStream()
      .pipe(stream)
      .on('finish', () => resolve(pcapFilename))
      .on('error', reject)
  })
}

async function convertSimIdsIntoIps () {
  for (const [index, simId] of Object.entries(simIds)) {
    log(`Getting ip addresses from simid's [${Number(index) + 1}/${simIds.length}] (${simId})`)
    const ip = await getIpFromSimOrIccId({ id: simId, token })
    ips.push(ip)
  }
  log('')
}

async function convertIccIdsIntoIps () {
  for (const [index, iccId] of Object.entries(iccIds)) {
    log(`Getting ip addresses from iccid's [${Number(index) + 1}/${iccIds.length}] (${iccId})`)
    const ip = await getIpFromSimOrIccId({ id: iccId, token })
    ips.push(ip)
  }
  log('')
}

async function mergePcapFiles (pcapFilenames) {
  return new Promise((resolve, reject) => {
    log('Merging all pcap files, using mergecap')
    const mergeFilename = path.join('merged.pcap')
    const filename = pcapFilenames.map(filename => path.parse(filename).base)
    const mergecap = spawn('mergecap', [
      ...filename,
      '-w', mergeFilename
    ], {
      cwd: tmpFolder
    })
    mergecap.on('error', reject)
    mergecap.on('close', () => {
      log('')
      resolve(path.join(tmpFolder, mergeFilename))
    })
  })
}

async function filterPcapFiles (filenames, ips) {
  const newFilesnames = []
  for (const [index, filename] of filenames.entries()) {
    log(`Filtering relevant packets, using tshark [${Number(index) + 1}/${filenames.length}]`)
    const newFilename = await filterWithTshark(filename, ips)
    newFilesnames.push(newFilename)
  }

  return newFilesnames
}

async function filterWithTshark (filename, ips) {
  return new Promise((resolve, reject) => {
    const { dir, base } = path.parse(filename)
    const filteredFilename = path.join(dir, `f-${base}`)
    const args = [
      '-r', filename,
      '-w', filteredFilename,
      '-Y', `${ips.map(ip => `ip.addr == ${ip}`).join(' or ')}`
    ]
    const tshark = spawn('tshark', args)
    tshark.on('error', reject)
    tshark.on('close', () => {
      log('')
      resolve(filteredFilename)
    })
  })
}

async function mergeCapExists () {
  return new Promise(resolve => {
    const mergecap = spawn('mergecap', [], {
      cwd: tmpFolder
    })
    mergecap.on('error', () => resolve(false))
    mergecap.on('close', () => resolve(true))
  })
}

async function getListOfAllPcapFilesOnBlobStorage () {
  log('Getting list of pcap files from Azure Blob Storage')
  const pcapFilesOnBlobStorage = await getListOfAllPcapFilesOnBlobStorageRecursive({ from, to })
  log('')
  return pcapFilesOnBlobStorage
}

async function getListOfAllPcapFilesOnBlobStorageRecursive ({ from, to }) {
  if (from > to) return []

  const keyTimestamp = format(from, 'yyyy/MM/dd')
  const allFilesFromDay = []
  const blobServiceClient = blobStorageConnectionString
    ? BlobServiceClient.fromConnectionString(blobStorageConnectionString)
    : new BlobServiceClient(blobStorageSasUri)
  const client = blobServiceClient.getContainerClient(blobStorageContainerName)
  for await (const file of client.listBlobsFlat({ prefix: keyTimestamp })) {
    allFilesFromDay.push(file)
  }
  const filesInRange = allFilesFromDay.filter(({ name: filename }) => isInRange({ filename, from, to }))
  const nextFrom = startOfDay(addDays(from, 1))
  const nextFiles = await getListOfAllPcapFilesOnBlobStorageRecursive({ from: nextFrom, to })

  return filesInRange.concat(nextFiles)
}

async function getListOfAllPcapFilesOnS3 () {
  log('Getting list of pcap files from AWS S3')
  const pcapFilesOnS3 = await getListOfAllPcapFilesOnS3Recursive({ from, to })
  log('')
  return pcapFilesOnS3
}

async function getListOfAllPcapFilesOnS3Recursive ({ from, to }) {
  if (from > to) return []

  const keyTimestamp = format(from, 'yyyy/MM/dd')
  const { Contents: allFilesFromDay } = await s3.listObjects({
    Bucket: s3Bucket,
    Prefix: keyTimestamp
  }).promise()

  const filesInRange = allFilesFromDay.filter(({ Key: filename }) => isInRange({ filename, from, to }))
  const nextFrom = startOfDay(addDays(from, 1))
  const nextFiles = await getListOfAllPcapFilesOnS3Recursive({ from: nextFrom, to })

  return filesInRange.concat(nextFiles)
}

async function getIpFromSimOrIccId ({ id, token }) {
  const headers = apiHeaders || {}
  headers.authorization = token
  const { data: { ipv4: ip } } = await axios.get(`${apiUrl}/sims/${id}`, { headers })
  return ip
}

async function getPublicVersion () {
  const pkgJson = await getPackageJson('onomondo-traffic')
  return pkgJson.version
}

function isInRange ({ filename, from, to }) {
  const date = parse(filename.split('.pcap')[0].split('-')[0], 'yyyy/MM/dd/HH/mm', new Date())
  const isInRage = from < date && date < to
  return isInRage
}

function exit (err) {
  console.error(err)
  console.error()
  console.error('See https://github.com/onomondo/onomondo-traffic for more information')
  process.exit(1)
}
