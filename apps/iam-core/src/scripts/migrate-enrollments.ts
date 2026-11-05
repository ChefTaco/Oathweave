#!/usr/bin/env node
import { lstatSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import Database from 'better-sqlite3'
import { enrollmentMigrationSchema, migrateEnrollments } from '../services/enrollment-migration.js'
function protectedFile(path: string): string {
 const stat=lstatSync(path)
 if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || process.getuid && stat.uid !== process.getuid()) throw new Error('Migration inputs must be private regular files owned by the operator')
 return path
}
try {
 const args=process.argv.slice(2), configIndex=args.indexOf('--config'), configPath=args[configIndex+1]
 if(configIndex<0 || !configPath || args.some((value,index)=>index!==configIndex && index!==configIndex+1 && !['--apply','--dry-run'].includes(value)) || args.includes('--apply') && args.includes('--dry-run')) throw new Error('Usage: migrate-enrollments --config protected.json [--dry-run|--apply]')
 const config=enrollmentMigrationSchema.parse(JSON.parse(readFileSync(protectedFile(resolve(configPath)),'utf8')))
 if(resolve(config.sourceDatabase)===resolve(config.targetDatabase)) throw new Error('Source and destination databases must be distinct')
 protectedFile(config.sourceDatabase);protectedFile(config.targetDatabase)
 const sourceStat=lstatSync(config.sourceDatabase),targetStat=lstatSync(config.targetDatabase)
 if(sourceStat.dev===targetStat.dev && sourceStat.ino===targetStat.ino) throw new Error('Source and destination must not alias the same database inode')
 const source=new Database(config.sourceDatabase,{readonly:true,fileMustExist:true}),target=new Database(config.targetDatabase,{readonly:!args.includes('--apply'),fileMustExist:true})
 try { console.log(JSON.stringify(migrateEnrollments(source,target,config,{source:readFileSync(protectedFile(config.sourceSecretFile),'utf8').trim(),target:readFileSync(protectedFile(config.targetReceiptSecretFile),'utf8').trim()},args.includes('--apply')),null,2)) } finally {source.close();target.close()}
} catch(error) {
 // Schema errors can contain private paths/account IDs. Print no raw exception.
 console.error(error instanceof Error && error.message.startsWith('Usage:') ? error.message : 'Enrollment migration refused. Verify private file ownership, separate quiesced snapshots, complete explicit subject mappings, target migrations, and exact reviewed dry-run digests. No credentials or source state were changed.')
 process.exitCode=1
}
