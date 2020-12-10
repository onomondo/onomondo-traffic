#!/usr/bin/env node

const AWS = require('aws-sdk')
const fs = require('fs')
const { parse, format, addDays, startOfDay } = require('date-fns')
const filesize = require('filesize')
const log = require('single-line-log').stdout
const path = require('path')
const { spawn } = require('child_process')
const minimist = require('minimist')
const pkgJson = require('./package.json')

process.env.TZ = 'UTC' // Only work in UTC (I quit if I have to work more with date/time...)
const argv = minimist(process.argv.slice(2), { string: 'simid' })
const apiUrl = argv.api || 'https://api.onomondo.com'
const from = argv.from
const to = argv.to
const s3Bucket = argv['s3-bucket']
const s3Region = argv['s3-region']
const awsAccessKeyId = argv['aws-access-key-id']
const awsSecretAccessKey = argv['aws-secret-access-key']
const hasAllRequiredParams = from && to && s3Bucket && s3Region && awsAccessKeyId && awsSecretAccessKey

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

start({
  from: new Date(from),
  to: new Date(to),
  ips: ['100.64.17.39']
})

async function start ({ from, to, ips }) {
  // Setup (remove ./tmp, create ./tmp)
  fs.rmdirSync('tmp', { recursive: true })
  fs.mkdirSync(path.join('tmp', 'traffic'), { recursive: true })

  // Convert ICCID/SimID into ip addresses

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
  log('Filtering relevant packets, using editcap')
  const trafficFilename = await filterFile(mergeFilename, ips)
  log('')
  console.log('Done filtering relevant packets')

  // Clean up
  fs.rmdirSync('tmp', { recursive: true })

  // Mention where file is
  console.log(`\nComplete. File is stored at ${trafficFilename}`)
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
