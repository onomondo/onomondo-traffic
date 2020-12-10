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
const s3Bucket = argv['s3-bucket']
const s3Region = argv['s3-region']
const awsAccessKeyId = argv['aws-access-key-id']
const awsSecretAccessKey = argv['aws-secret-access-key']
const hasAllRequiredParams = from && to && s3Bucket && s3Region && awsAccessKeyId && awsSecretAccessKey
const hasTokenIfNeeded = (iccIds.length || simIds.length) ? !!token : true
const areDatesValid = isValid(from) && isValid(to)

if (!hasAllRequiredParams) {
  console.error([
    `Onomondo Traffic Fetcher ${pkgJson.version}`,
    'Fetch your organization\'s traffic based on ip, iccid, or simid',
    '',
    'Some parameters are missing. See documentation on https://github.com/onomondo/onomondo-traffic-fetcher'
  ].join('\n'))
  process.exit(1)
}

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
  for (const [index, simId] of Object.entries(simIds)) {
    log(`Getting ip addresses from simid's [${index + 1}/${simIds.length}]`)
    const ip = await getIpFromSimId({ simId, token })
    ips.push(ip)
  }
  if (simIds.length > 0) {
    log('')
    console.log('Done getting ip addresses from simid\'s')
  }

  for (const [index, iccId] of Object.entries(iccIds)) {
    log(`Getting ip addresses from iccid's [${index + 1}/${iccIds.length}]`)
    const ip = await getIpFromSimId({ iccId, token })
    ips.push(ip)
  }
  if (iccIds.length > 0) {
    log('')
    console.log('Done getting ip addresses from iccid\'s')
  }

  // Get list of pcap files
  log('Getting list of pcap files')
  const objects = await getObjectsToFetch({ from, to })
  log('')
  console.log('Done getting list of pcap files')

  // Download all pcap files
  const totalObjects = objects.length
  const totalSize = objects.reduce((totalSize, { Size }) => totalSize + Size, 0)
  let downloadedSize = 0
  const pcapFilenames = []

  for (const [index, obj] of Object.entries(objects)) {
    downloadedSize += obj.Size
    log(`Downloading pcap files. ${Number(index) + 1}/${totalObjects} (${filesize(downloadedSize)}/${filesize(totalSize)})`)
    const filename = await downloadObject(obj.Key)
    pcapFilenames.push(filename)
  }
  log('')
  console.log('Done downloading pcap files')

  // Merge files
  log('Merging all pcap files, using mergecap')
  const mergeFilename = await mergePcapFiles(pcapFilenames)
  log('')
  console.log('Done merging pcap files')

  // Filter relevant packets
  const shouldFilter = ips.length > 0
  if (shouldFilter) {
    log('Filtering relevant packets, using tshark')
    await filterFile(mergeFilename, ips)
    log('')
    console.log('Done filtering relevant packets')
  } else {
    fs.renameSync(mergeFilename, 'traffic.pcap')
  }

  // Clean up
  fs.rmdirSync('tmp', { recursive: true })

  // Mention where file is
  console.log('\nComplete. File is stored at traffic.pcap')
}

async function downloadObject (s3Key) {
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

async function mergePcapFiles (pcapFilenames) {
  return new Promise((resolve, reject) => {
    const mergeFilename = path.join('tmp', 'merged.pcap')
    const mergecap = spawn('mergecap', [
      ...pcapFilenames,
      '-w', mergeFilename
    ])
    mergecap.on('error', reject)
    mergecap.on('close', () => resolve(mergeFilename))
  })
}

async function filterFile (mergeFilename, ips) {
  return new Promise((resolve, reject) => {
    const filteredFilename = 'traffic.pcap'
    const args = [
      '-r', mergeFilename,
      '-w', filteredFilename,
      '-Y', `${ips.map(ip => `ip.addr == ${ip}`).join(' or ')}`
    ]
    const tshark = spawn('tshark', args)
    tshark.on('error', reject)
    tshark.on('close', () => resolve(filteredFilename))
  })
}

async function getObjectsToFetch ({ from, to }) {
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
  const nextItems = await getObjectsToFetch({ from: nextFrom, to })

  return itemsFiltered.concat(nextItems)
}

async function getIpFromSimId ({ simId, token }) {
  const { data: { ipv4: ip } } = await axios.get(`${apiUrl}/sims/${simId}`, {
    headers: {
      authorization: token
    }
  })
  return ip
}

async function getIpFromIccId ({ iccId, token }) {
  const { data: { ipv4: ip } } = await axios.get(`${apiUrl}/sims/${iccId}`, {
    headers: {
      authorization: token
    }
  })
  return ip
}
