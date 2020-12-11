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
const hasAllRequiredParams = from && to && s3Bucket && s3Region && awsAccessKeyId && awsSecretAccessKey
const hasTokenIfNeeded = (iccIds.length || simIds.length) ? !!token : true
const areDatesValid = isValid(from) && isValid(to)
const isUsingS3 = s3Bucket || s3Region || awsAccessKeyId || awsSecretAccessKey
const hasAllS3Params = s3Bucket && s3Region && awsAccessKeyId && awsSecretAccessKey

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
  console.error('If you use S3, you need to specify all these parameters: --s3-bucket, --s3-region, --aws-access-key-id, --aws-secret-access-key')
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
    console.log('Done getting list of pcap files from S3')

    // Download all pcap files
    pcapFilesLocally = await downloadAllPcapFilesOnS3(pcapFilesOnS3)
    console.log('Done downloading pcap files from S3')
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

async function downloadAllPcapFilesOnS3 (pcapFilesOnS3) {
  const totalFiles = pcapFilesOnS3.length
  const totalSize = pcapFilesOnS3.reduce((totalSize, { Size }) => totalSize + Size, 0)
  let downloadedSize = 0
  const pcapFilenames = []

  for (const [index, file] of Object.entries(pcapFilesOnS3)) {
    downloadedSize += file.Size
    log(`Downloading pcap files from S3. [${Number(index) + 1}/${totalFiles} (${filesize(downloadedSize)}/${filesize(totalSize)})] (s3://${s3Bucket}/${file.Key})`)
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

async function getListOfAllPcapFilesOnS3 () {
  log('Getting list of pcap files')
  const pcapFilesOnS3 = await getListOfAllPcapFilesRecursive({ from, to })
  log('')
  return pcapFilesOnS3
}

async function getListOfAllPcapFilesRecursive ({ from, to }) {
  if (from > to) return []

  const keyTimestamp = format(from, 'yyyy/MM/dd')
  const { Contents: allItemsFromDay } = await s3.listObjects({
    Bucket: s3Bucket,
    Prefix: keyTimestamp
  }).promise()
  const itemsFiltered = allItemsFromDay
    .filter(({ Key }) => {
      const date = parse(Key.split('.pcap')[0], 'yyyy/MM/dd/HH/mm', new Date())
      const isInRage = from < date && date < to
      return isInRage
    })
  const nextFrom = startOfDay(addDays(from, 1))
  const nextItems = await getListOfAllPcapFilesRecursive({ from: nextFrom, to })

  return itemsFiltered.concat(nextItems)
}

async function getIpFromSimOrIccId ({ id, token }) {
  const headers = { authorization: token }
  if (organizationId) headers.organization_id = organizationId
  const { data: { ipv4: ip } } = await axios.get(`${apiUrl}/sims/${id}`, { headers })
  return ip
}
