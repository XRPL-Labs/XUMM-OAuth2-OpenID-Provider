// Limit on sign-in starts (/auth). Every start creates a sign request at the API in the name of the client, so the
// number of starts is limited: per caller address and client, and per client over all callers. The counts are kept
// in the memory of this process (the service runs as one process).
const net = require('net')

// The starts of the last AUTH_START_WINDOW_MS count (a sliding window)
const AUTH_START_WINDOW_MS = 60 * 1000
// Starts in the window from one caller address for one client. Several users of a client can share one address.
const AUTH_START_MAX_PER_ADDRESS = 60
// Starts in the window for one client, from all addresses together
const AUTH_START_MAX_PER_CLIENT = 600
// Most keys kept per list at one moment (memory bound). Over it, the key that was not used for the longest time goes.
const AUTH_START_MAX_KEYS = 50000
// The request header with the address of the caller. It is set by the proxy in front of this service: the address
// of the connection itself is the proxy, the same for every caller.
const CALLER_ADDRESS_HEADER = 'cf-connecting-ip'

// The 8 groups of an IPv6 address, as numbers
const ipv6Groups = ip => {
  // An IPv4 tail (`::ffff:192.0.2.1`) is two groups
  const text = ip.replace(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/, (match, a, b, c, d) => {
    return (Number(a) * 256 + Number(b)).toString(16) + ':' + (Number(c) * 256 + Number(d)).toString(16)
  })
  const [head, tail] = text.split('::')
  const first = head ? head.split(':') : []
  const last = tail ? tail.split(':') : []
  const groups = text.includes('::') ? [...first, ...Array(Math.max(0, 8 - first.length - last.length)).fill('0'), ...last] : first
  return groups.map(group => parseInt(group, 16))
}

// The caller of a request, as the key of the limit: an IPv4 address, or the /64 network of an IPv6 address (one
// caller has every address of its network). Without a usable address in the header: undefined. Then only the limit
// per client counts for the request, so callers without the header never share one count.
const callerAddress = function callerAddress (req) {
  const value = req?.headers?.[CALLER_ADDRESS_HEADER]
  if (typeof value !== 'string') return undefined

  const ip = value.trim().toLowerCase().split('%')[0]
  const version = net.isIP(ip)
  if (version === 4) return ip
  if (version !== 6) return undefined

  const groups = ipv6Groups(ip)
  // An IPv4 address written as IPv6 (`::ffff:192.0.2.1`) is that IPv4 address
  if (groups.slice(0, 5).every(group => group === 0) && groups[5] === 0xffff) {
    return [groups[6] >> 8, groups[6] & 255, groups[7] >> 8, groups[7] & 255].join('.')
  }
  return groups.slice(0, 4).map(group => group.toString(16)).join(':') + '::/64'
}

const createAuthStartLimit = function createAuthStartLimit (options) {
  const windowMs = options?.windowMs ?? AUTH_START_WINDOW_MS
  const maxPerAddress = options?.maxPerAddress ?? AUTH_START_MAX_PER_ADDRESS
  const maxPerClient = options?.maxPerClient ?? AUTH_START_MAX_PER_CLIENT
  const maxKeys = options?.maxKeys ?? AUTH_START_MAX_KEYS

  // Key -> the times (ms, oldest first) of its starts in the window. Only a start that was allowed is stored, so a
  // list is never longer than its limit, and a key without a start in the window is not kept.
  const perClient = new Map()
  const perCaller = new Map()
  let sweptAt = 0

  // A time after `now` (the clock of the host was set back) does not count
  const inWindow = (time, now) => time <= now && now - time < windowMs

  const recent = (list, key, now) => (list.get(key) || []).filter(time => inWindow(time, now))

  // The key moves to the end of the list (the order of a Map is the order of insertion): the first key is always
  // the one that was not used for the longest time
  const store = (list, key, times) => {
    list.delete(key)
    if (list.size >= maxKeys) list.delete(list.keys().next().value)
    list.set(key, times)
  }

  // Once per window: every key without a start in the window is removed
  const sweep = now => {
    if (now >= sweptAt && now - sweptAt < windowMs) return
    sweptAt = now
    for (const list of [perClient, perCaller]) {
      for (const [key, times] of list) {
        if (!inWindow(times[times.length - 1], now)) list.delete(key)
      }
    }
  }

  return {
    // Counts one start for this caller address (undefined: not known) and client, when both limits have room.
    // No room: nothing is counted, so requests over the limit do not make the wait longer.
    take (address, client, now = Date.now()) {
      sweep(now)

      const callerKey = address === undefined ? undefined : client + ' ' + address
      const callerTimes = callerKey === undefined ? undefined : recent(perCaller, callerKey, now)
      const clientTimes = recent(perClient, client, now)

      // Room is there again when the oldest start of the full list leaves the window
      if (callerTimes && callerTimes.length >= maxPerAddress) {
        return { allowed: false, limit: 'address', retryAfterMs: callerTimes[0] + windowMs - now }
      }
      if (clientTimes.length >= maxPerClient) {
        return { allowed: false, limit: 'client', retryAfterMs: clientTimes[0] + windowMs - now }
      }

      clientTimes.push(now)
      store(perClient, client, clientTimes)
      if (callerTimes) {
        callerTimes.push(now)
        store(perCaller, callerKey, callerTimes)
      }

      return { allowed: true }
    },
    // The number of keys in memory
    size () {
      return perClient.size + perCaller.size
    }
  }
}

module.exports = {
  AUTH_START_WINDOW_MS,
  AUTH_START_MAX_PER_ADDRESS,
  AUTH_START_MAX_PER_CLIENT,
  AUTH_START_MAX_KEYS,
  CALLER_ADDRESS_HEADER,
  callerAddress,
  createAuthStartLimit,
  // The limit of this process
  authStartLimit: createAuthStartLimit()
}
