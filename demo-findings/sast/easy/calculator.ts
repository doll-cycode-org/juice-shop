// DEMO FINDING (SAST / easy): single-line, source and sink in the same statement.
import { type Request, type Response } from 'express'
import crypto from 'crypto'

// CWE-95: eval() on user-controlled input
export function calculate (req: Request, res: Response) {
  const result = eval(req.query.expr as string)
  res.json({ result })
}

// CWE-328: weak hash used for passwords
export function hashPassword (password: string) {
  return crypto.createHash('md5').update(password).digest('hex')
}

// CWE-338: non-cryptographic PRNG for a security token
export function generateResetToken () {
  return Math.random().toString(36).substring(2)
}

// CWE-79: reflected XSS, raw query param written to the response
export function greet (req: Request, res: Response) {
  res.send('<h1>Hello ' + req.query.name + '</h1>')
}
