import { PrismaClient } from '@prisma/client'
import * as fs from 'fs'
import * as path from 'path'

// HARDCODED correct URL — used as fallback if .env is missing or contains
// a bad value (custom.db or absolute Unix path that breaks on Windows).
const CORRECT_URL = 'file:../db/webrecon.db'

function loadDatabaseUrlFromEnv(): string {
  try {
    const envPath = path.join(process.cwd(), '.env')
    const envContent = fs.readFileSync(envPath, 'utf-8')
    for (const line of envContent.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) continue
      const eqIdx = trimmed.indexOf('=')
      if (eqIdx === -1) continue
      const key = trimmed.slice(0, eqIdx).trim()
      const value = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '')
      if (key === 'DATABASE_URL' && value) {
        // REJECT bad values: custom.db, absolute Unix paths (file:/...)
        if (value.includes('custom.db') || value.startsWith('file:/')) {
          process.env.DATABASE_URL = CORRECT_URL
          return CORRECT_URL
        }
        process.env.DATABASE_URL = value
        return value
      }
    }
  } catch {
    // .env doesn't exist
  }
  // Check process.env — reject bad values
  const envVal = process.env.DATABASE_URL
  if (envVal && !envVal.includes('custom.db') && !envVal.startsWith('file:/')) {
    return envVal
  }
  process.env.DATABASE_URL = CORRECT_URL
  return CORRECT_URL
}

const databaseUrl = loadDatabaseUrlFromEnv()

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

const prismaLog: ('query' | 'info' | 'warn' | 'error')[] =
  process.env.WEBRECON_DEBUG_PRISMA === '1'
    ? ['query', 'warn', 'error']
    : ['warn', 'error']

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: prismaLog,
    datasources: {
      db: {
        url: databaseUrl,
      },
    },
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db
