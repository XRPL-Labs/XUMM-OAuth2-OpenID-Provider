const mysql = require('mysql2/promise')
const config = require('./config')
const crypto = require('crypto')

console.log('Connect DB')

const db = mysql.createPool(config.db.uri)

class DatastoreQuery {
  m_dataset = ''
  m_filter = []

  constructor (dataset) {
    // DEBUG
    // console.log('new dataset', dataset)
    this.m_dataset = dataset
  }

  filter (key, operator, value) {
    this.m_filter.push({key, operator, value})
    return this
  }

  async update (data) {
    // console.log(this.m_dataset, this.m_filter, data)
    const conn = await db.getConnection()

    const updateValues = Object.keys(data).map(f => {
      return '`' + f + '` = ?'
    }).join(', ')

    const whereQuery = this.m_filter.map(f => {
      return '`' + f.key + '` ' + f.operator + ' ?'
    }).join(' AND ')

    const query = `
      UPDATE ${this.m_dataset}s
      SET ${updateValues}  
      WHERE ${whereQuery}
    `

    const params = [
      ...Object.keys(data).map(k => data[k]),
      ...this.m_filter.map(f => f.value)
    ]

    // console.log(query, params)

    const results = await conn.execute(query, params)

    conn.release()

    return results
  }

  async get () {
    if (this.m_dataset === 'user') {
      const conn = await db.getConnection()

      const results = await conn.execute(`
        SELECT id,
               username,
               password,
               xrpl_account
          FROM users
         WHERE username = ?
         LIMIT 1
      `, this.m_filter.filter(f => f.key === 'username').map(f => f.value))

      conn.release()

      if (Array.isArray(results) && results.length > 0) {
        if (Array.isArray(results[0]) && results[0].length > 0) {
          const result = (await Promise.all(results[0].map(async r => {
            const outcome = await new Promise((resolve, reject) => {
              if ((Number(r?.xrpl_account || 0) || 0) > 0) {
                // XRPL account, no need for password check if XUMM flow.
                const account = this.m_filter.filter(f => f.key === 'username').map(f => f.value)[0]
                const pwhash = crypto.createHash('sha256').update(account + config.secret).digest('hex')
                if (this.m_filter.filter(f => f.key === 'password').map(f => f.value)[0] === pwhash) {
                  // console.log('xrpl account outcome r', r, this.m_filter.filter(f => f.key === 'password').map(f => f.value)[0])
                  return resolve({...r, safe: true})
                }
              }
              crypto.pbkdf2(this.m_filter.filter(f => f.key === 'password').map(f => f.value)[0], String(r.id), 100000, 64, 'sha512', (err, derivedKey) => {
                if (err) {
                  console.log(err)
                  return reject(err)
                }
                const hashhalf = derivedKey.toString('hex').slice(0, 64)
                // console.log({hashhalf})

                resolve({...r, safe: hashhalf === r.password})
              })
            })

            return outcome
          }))).filter(r => r.safe)

          // DEBUG
          // console.log('users.match', result)
          return result
        }
      }
    } else {
      const conn = await db.getConnection()
      // DEBUG
      // console.log('Use MySQL database @ ', this.m_dataset, this.m_filter)

      const whereQuery = this.m_filter.map(f => {
        return '`' + f.key + '` ' + f.operator + ' ?'
      }).join(' AND ')

      const query = `
        SELECT *
          FROM ${this.m_dataset}s
         WHERE ${whereQuery}
      `

      const results = await conn.execute(query, this.m_filter.map(f => f.value))
      conn.release()

      if (Array.isArray(results) && results.length > 0) {
        if (Array.isArray(results[0]) && results[0].length > 0) {
          return results[0]
        }
      }
    }

    return []
  }
}

class Datastore {
  m_databaseConnection = undefined

  constructor () {
    console.log('Datastore constructed')
  }

  createQuery (dataset) {
    return new DatastoreQuery(dataset)
  }

  async updateQuery (datstoreQuery, newData) {
    try {
      const queryResults = await datstoreQuery.update(newData)
      // DEBUG
      // console.log('updateQuery', newData, queryResults)
      return true
    } catch (e) {
      console.log('error', e.message)
      return false
    }
  }

  async runQuery (datstoreQuery) {
    try {
      const queryResults = await datstoreQuery.get()
      // console.log('runQuery', queryResults)
      return [ queryResults ]
    } catch (e) {
      console.log('error', e.message)
      return [[]]
    }
  }

  key ([k, v]) {
    return {
      [k]: v
    }
  }

  async upsert (data) {
    console.log('upsert', data)

    const upsertData = {}

    Object.keys(data).forEach(k => {
      Object.keys(data[k]).forEach(fld => {
        // console.log(fld, data[k][fld])
        upsertData[fld] = data[k][fld]
      })
    })

    const conn = await db.getConnection()
    let table = ''

    if (upsertData?.authorization_code) {
      table = 'grants'
    } else
    if (upsertData?.xrpl_account) {
      table = 'users'
    } else
    if (upsertData?.payload) {
      table = 'xumm_challenges'
    } else {
      throw new Error('Error, unknown dataset to upsert to')
    }

    console.log('Use MySQL database @ ', table)
    await conn.execute('INSERT IGNORE INTO `' + table + '`' + `
             (${Object.keys(upsertData).join(', ')})
      VALUES (${Object.keys(upsertData).map(v => '?').join(', ')})
      ON DUPLICATE KEY UPDATE
        ${Object.keys(upsertData).map(v => '`' + v + '` = ?').join(', ')}
    `, [
      ...Object.keys(upsertData).map(k => upsertData[k] || null),
      ...Object.keys(upsertData).map(k => upsertData[k] || null),
    ])

    conn.release()
  }

  transaction () {
    console.log('Start transaction')
    return new DatastoreTransaction()
  }
}

class DatastoreTransaction {
  _mf_resolveConnection = null
  _mf_resolveTransaction = null

  m_connection = null
  m_transaction = null

  constructor () {
    this.m_connection = new Promise(resolve => {
      this._mf_resolveConnection = resolve
    })
    this.m_transaction = new Promise(resolve => {
      this._mf_resolveTransaction = resolve
    })
  
    db.getConnection().then(c => {
      this._mf_resolveConnection(c)
      console.log('Got connection')
      c.beginTransaction().then(t => {
        this._mf_resolveTransaction(t)
        console.log('Got transaction')
       })
    })

    return this
  }

  async run () {
    console.log('Transaction RUN')

    return this
  }

  async get (key) {
    const c = await this.m_connection

    if (key?.authorization_code) {
      console.log('Transaction GET', key?.authorization_code)
      const data = await c.execute(`
        SELECT * FROM grants
        WHERE authorization_code = ?
        AND fetched = 0
        ORDER BY exp DESC LIMIT 1
      `, [key?.authorization_code])

      if (Array.isArray(data) && data.length > 0) {
        return data[0]
      }
    }

    throw new Error('Invalid dataset: transaction Get (key)')
  }

  async delete (key) {
    const c = await this.m_connection

    if (key?.authorization_code) {
      console.log('Transaction DELETE', key?.authorization_code)
      const data = await c.execute(`
        UPDATE grants SET fetched = 1 WHERE authorization_code = ?
      `, [key?.authorization_code])
    }

    return this
  }

  async rollback () {
    const c = await this.m_connection
  
    console.log('Transaction ROLLBACK')

    c.rollback()
    c.release()

    return this
  }

  async commit () {
    const c = await this.m_connection
    const t = await this.m_transaction

    console.log('Transaction COMMIT')

    c.commit()
    c.release()

    return this
  }
}

module.exports = {
  datastore: new Datastore(),
  db
}

