#!/usr/bin/env node

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
const { BlobServiceClient } = require('@azure/storage-blob')

process.env.TZ = 'UTC' // Only work in UTC (I quit if I have to work more with date/time...)
const argv = minimist(process.argv.slice(2), { string: 'simid' })
const from = new Date(argv.from)
const to = new Date(argv.to)
const iccIds = typeof argv.iccid === 'string' ? [argv.iccid] : (argv.iccid || [])
const simIds = typeof argv.simid === 'string' ? [argv.simid] : (argv.simid || [])
const ips = typeof argv.ip === 'string' ? [argv.ip] : (argv.ip || [])
const token = argv.token
const apiUrl = argv.api || 'https://api.onomondo.com'
const organizationId = argv.organizationid
const s3Bucket = argv['s3-bucket']
const s3Region = argv['s3-region']
const awsAccessKeyId = argv['aws-access-key-id']
const awsSecretAccessKey = argv['aws-secret-access-key']
const blobStorageConnectionString = argv['blob-storage-connection-string']
const blobStorageContainerName = argv['blob-storage-container-name']
const hasTokenIfNeeded = (iccIds.length || simIds.length) ? !!token : true
const areDatesValid = isValid(from) && isValid(to)
const isUsingBlobStorage = blobStorageConnectionString || blobStorageContainerName
const hasAllBlobStorageParams = blobStorageConnectionString && blobStorageContainerName
const isUsingS3 = s3Bucket || s3Region || awsAccessKeyId || awsSecretAccessKey
const hasAllS3Params = s3Bucket && s3Region && awsAccessKeyId && awsSecretAccessKey
const hasAllRequiredParams = from && to && (isUsingBlobStorage || isUsingS3)

if (!areDatesValid) {
  console.error('The dates are not valid. Needs to be in a format like --from=2020-12-20T18:00:00Z')
  console.error('See https://github.com/onomondo/onomondo-traffic-fetcher for more information')
  process.exit(1)
}

if (!hasTokenIfNeeded) {
  console.error('If you specify either --simid or --iccid, then you also need to specify --token')
  console.error('See https://github.com/onomondo/onomondo-traffic-fetcher for more information')
  process.exit(1)
}

if (isUsingS3 && !hasAllS3Params) {
  console.error('If you use AWS S3, you need to specify all these parameters: --s3-bucket, --s3-region, --aws-access-key-id, --aws-secret-access-key')
  console.error('See https://github.com/onomondo/onomondo-traffic-fetcher for more information')
  process.exit(1)
}

if (isUsingBlobStorage && !hasAllBlobStorageParams) {
  console.error('If you use Azure Blob Storage, you need to specify all these parameters: --blob-storage-connection-string, --blob-storage-container-name')
  console.error('See https://github.com/onomondo/onomondo-traffic-fetcher for more information')
  process.exit(1)
}

if (!isUsingBlobStorage && !isUsingS3) {
  console.error('You need to either specify an AWS S3 or Azure Blob Storage configuration')
  console.error('See https://github.com/onomondo/onomondo-traffic-fetcher for more information')
  process.exit(1)
}

if (!hasAllRequiredParams) {
  console.error([
    `Onomondo Traffic Fetcher ${pkgJson.version}`,
    'Fetch your organization\'s traffic based on ip, iccid, or simid',
    '',
    'Some parameters are missing. See documentation on https://github.com/onomondo/onomondo-traffic-fetcher'
  ].join('\n'))
  process.exit(1)
}

AWS.config.update({
  region: s3Region,
  accessKeyId: awsAccessKeyId,
  secretAccessKey: awsSecretAccessKey
})
const s3 = new AWS.S3({ apiVersion: '2006-03-01' })

run()

async function run () {
  // Setup (remove ./tmp, create ./tmp)
  fs.rmdirSync('tmp', { recursive: true })
  fs.mkdirSync(path.join('tmp', 'traffic'), { recursive: true })

  // Convert ICCID/SimID into ip addresses
  if (simIds.length > 0) {
    await convertSimIdsIntoIps()
    console.log('Done getting ip addresses from simid\'s')
  }
  if (iccIds.length > 0) {
    await convertIccIdsIntoIps()
    console.log('Done getting ip addresses from iccid\'s')
  }

  let pcapFilesLocally

  // Download pcap files from S3
  if (isUsingS3) {
    // Get list of pcap files
    const pcapFilesOnS3 = await getListOfAllPcapFilesOnS3()
    console.log('Done getting list of pcap files from AWS S3')

    // Download all pcap files
    pcapFilesLocally = await downloadAllPcapFilesOnS3(pcapFilesOnS3)
    console.log('Done downloading pcap files from AWS S3')
  }

  // Download pcap files from Blob Storage
  if (isUsingBlobStorage) {
    const pcapFilesOnBlobStorage = await getListOfAllPcapFilesOnBlobStorage()
    console.log('Done getting list of pcap files from Azure Blob Storage')

    // Download all pcap files
    pcapFilesLocally = await downloadAllPcapFilesOnBlobStorage(pcapFilesOnBlobStorage)
    console.log('Done downloading pcap files from Azure Blob Storage')
  }

  // Merge files
  const mergeFilename = await mergePcapFiles(pcapFilesLocally)
  console.log('Done merging pcap files')

  // Filter relevant packets
  const shouldFilter = ips.length > 0
  if (!shouldFilter) {
    fs.renameSync(mergeFilename, 'traffic.pcap')
  } else {
    await filterWithTshark(mergeFilename, ips)
    console.log('Done filtering relevant packets')
  }

  // Clean up
  fs.rmdirSync('tmp', { recursive: true })

  // Mention where file is
  console.log('\nComplete. File is stored at traffic.pcap')
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
  const pcapFilename = path.join('tmp', 'traffic', blobStorageFilename.replace(/\//g, '-'))
  const blobServiceClient = BlobServiceClient.fromConnectionString(blobStorageConnectionString)
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
    const pcapFilename = path.join('tmp', 'traffic', s3Key.replace(/\//g, '-'))
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
    const mergeFilename = path.join('tmp', 'merged.pcap')
    const mergecap = spawn('mergecap', [
      ...pcapFilenames,
      '-w', mergeFilename
    ])
    mergecap.on('error', reject)
    mergecap.on('close', () => {
      log('')
      resolve(mergeFilename)
    })
  })
}

async function filterWithTshark (mergeFilename, ips) {
  return new Promise((resolve, reject) => {
    log('Filtering relevant packets, using tshark')
    const filteredFilename = 'traffic.pcap'
    const args = [
      '-r', mergeFilename,
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
  const blobServiceClient = BlobServiceClient.fromConnectionString(blobStorageConnectionString)
  const client = blobServiceClient.getContainerClient(blobStorageContainerName)
  for await (const file of client.listBlobsFlat({ prefix: keyTimestamp })) {
    allFilesFromDay.push(file)
  }

  const filesInRange = allFilesFromDay
    .filter(({ name }) => {
      const date = parse(name.split('.pcap')[0], 'yyyy/MM/dd/HH/mm', new Date())
      const isInRage = from < date && date < to
      return isInRage
    })
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
  const filesInRange = allFilesFromDay
    .filter(({ Key }) => {
      const date = parse(Key.split('.pcap')[0], 'yyyy/MM/dd/HH/mm', new Date())
      const isInRage = from < date && date < to
      return isInRage
    })
  const nextFrom = startOfDay(addDays(from, 1))
  const nextFiles = await getListOfAllPcapFilesOnS3Recursive({ from: nextFrom, to })

  return filesInRange.concat(nextFiles)
}

async function getIpFromSimOrIccId ({ id, token }) {
  const headers = { authorization: token }
  if (organizationId) headers.organization_id = organizationId
  const { data: { ipv4: ip } } = await axios.get(`${apiUrl}/sims/${id}`, { headers })
  return ip
}
